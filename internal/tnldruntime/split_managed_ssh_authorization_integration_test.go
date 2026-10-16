package tnldruntime

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os/user"
	"strconv"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/managedssh"
	"github.com/tnldotdev/tnl/internal/proxyproto"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/tnldconfig"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type splitSSHAuthorizationObservation struct {
	scope    controlclient.VisitorCertificateScope
	state    tls.ConnectionState
	username string
	decision controlclient.SSHVisitorDecision
	err      error
}

// retain the real control client and all publisher lifecycle operations. only
// observe the fresh SSH authorization boundary selected by the publisher.
type splitSSHObservedControl struct {
	*integrationScopedRunControl
	observed chan splitSSHAuthorizationObservation
}

func (c *splitSSHObservedControl) AuthorizeSSHVisitor(ctx context.Context, scope controlclient.VisitorCertificateScope, state tls.ConnectionState, username string) (controlclient.SSHVisitorDecision, error) {
	decision, err := c.Client.AuthorizeSSHVisitor(ctx, scope, state, username)
	c.observed <- splitSSHAuthorizationObservation{scope, state, username, decision, err}
	return decision, err
}

func takeSplitSSHAuthorization(t *testing.T, c *splitSSHObservedControl) splitSSHAuthorizationObservation {
	t.Helper()
	select {
	case observation := <-c.observed:
		return observation
	case <-time.After(5 * time.Second):
		t.Fatal("publisher did not consult real control SSH authorization")
		return splitSSHAuthorizationObservation{}
	}
}

func TestIntegrationSplitManagedSSHAuthorization(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if u.Uid == "0" {
		t.Skip("host transport checks use a nonroot developer account; the explicit Linux container target covers root serving")
	}
	for _, transport := range []string{"quic", "tls-tcp"} {
		t.Run(transport, func(t *testing.T) { splitManagedSSHAuthorization(t, transport, u.Username) })
	}
}

func splitManagedSSHAuthorization(t *testing.T, transport, username string) {
	seed := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	f := newSplitPublishFixtureWithOptions(t, "shell", splitPublishOptions{proxyIngress: true, configureProcess: func(c *tnldconfig.Config) {
		if c.Role == tnldconfig.RoleControl {
			c.VisitorIssuerSeed = seed
		}
		if c.Role == tnldconfig.RoleIngress {
			c.RequireProxyHeader = true
		}
	}})
	_, portText, err := net.SplitHostPort(unusedTCPAddress(t))
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.inspect.ExecContext(t.Context(), `UPDATE control.ingress_pools SET ipv4_address='127.0.0.1'::inet,state='enabled' WHERE id='ingress-a'`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.inspect.ExecContext(t.Context(), `INSERT INTO control.ingress_pool_ports(ingress_pool_id,port,enabled) VALUES ('ingress-a',$1,true)`, port); err != nil {
		t.Fatal(err)
	}
	private, _, err := managedssh.GenerateHostKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := managedssh.ParseHostKey(private)
	if err != nil {
		t.Fatal(err)
	}
	quic, tcp := f.connectors()
	if transport == "quic" {
		tcp, _ = disabledIntegrationConnector("select QUIC for the managed SSH authorization boundary")
	} else {
		quic, _ = disabledIntegrationConnector("select TLS/TCP for the managed SSH authorization boundary")
	}
	publication := f.identity.publisherConfig("", quic, tcp)
	publication.ServiceProtocol, publication.AccessMode = controlv1.Ssh, controlv1.Restricted
	publication.SSH = &publisher.SSHConfig{HostKey: signer, Users: []string{username}}
	observed := &splitSSHObservedControl{integrationScopedRunControl: publication.Control.(*integrationScopedRunControl), observed: make(chan splitSSHAuthorizationObservation, 16)}
	publication.Control = observed
	handle := startOwnedIntegrationPublisher(t, f.owner, publication, func() string { return integrationPublisherDiagnostics(f.inspect, f.pebble.logPath) })
	ready := waitForPublisherReady(t, handle)
	_, allocatedPort, err := net.SplitHostPort(ready.PublicURL)
	if err != nil || allocatedPort != portText {
		t.Fatalf("managed SSH public port = %q, %v", ready.PublicURL, err)
	}
	waitForReadyPublisherConnections(t, f.inspect, ready.PublicURLID, ready.PublishRunNumber, 2)
	waitForIngressRoutingCurrent(t, f.inspect, 1)
	dial := func(source string) net.Conn {
		t.Helper()
		c, err := net.DialTimeout("tcp", f.ingressConfig.IngressListen, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		header, err := proxyproto.Encode(proxyproto.Header{Source: netip.AddrPortFrom(netip.MustParseAddr(source), 40001), Destination: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port))})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Write(header); err != nil {
			t.Fatal(err)
		}
		return c
	}
	checkNoBanner := func(c net.Conn) {
		t.Helper()
		response, err := io.ReadAll(c)
		if bytes.Contains(response, []byte("SSH-")) {
			t.Fatalf("unapproved transport exposed an SSH banner: %q", response)
		}
		if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			t.Fatal("denied transport remained open instead of closing")
		}
	}
	raw := dial("127.0.0.1")
	if _, err := io.WriteString(raw, "SSH-2.0-unwrapped-client\r\n"); err != nil {
		t.Fatal(err)
	}
	checkNoBanner(raw)
	visitorTLS := func(source string, certificate *tls.Certificate) *tls.Conn {
		t.Helper()
		config := &tls.Config{ServerName: f.identity.hostname, RootCAs: f.pebble.roots, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}
		if certificate != nil {
			config.Certificates = []tls.Certificate{*certificate}
		}
		return tls.Client(dial(source), config)
	}
	missing := visitorTLS("127.0.0.1", nil)
	if err := missing.HandshakeContext(t.Context()); err == nil {
		t.Fatal("matching source IP bypassed required visitor mTLS")
	}
	select {
	case <-observed.observed:
		t.Fatal("raw SSH or missing certificate reached control authorization")
	default:
	}
	identity, err := f.identity.authority.IdentityContext(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.identity.routes.IssueVisitorCertificate(t.Context(), ready.PublicURLID, csr); !splitSSHForbidden(err) {
		t.Fatalf("ownership alone issued an SSH identity certificate: %v", err)
	}
	grantRequest := controlv1.CreateIdentityVisitorGrantRequest{IdentityId: identity.Identity.Id, SshUser: &username}
	grant, err := f.identity.routes.CreateIdentityVisitorGrant(t.Context(), ready.PublicURLID, "split-ssh-initial", grantRequest)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := f.identity.routes.IssueVisitorCertificate(t.Context(), ready.PublicURLID, csr)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair([]byte(issued.CertificatePem), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.identity.routes.RevokeVisitorGrant(t.Context(), ready.PublicURLID, grant.Id); err != nil {
		t.Fatal(err)
	}
	denied := visitorTLS("127.0.0.1", &certificate)
	if err := denied.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	checkNoBanner(denied)
	proof := takeSplitSSHAuthorization(t, observed)
	if !splitSSHForbidden(proof.err) || proof.username != "" || !proof.state.HandshakeComplete || len(proof.state.PeerCertificates) != 1 ||
		proof.scope.PublicURLID != ready.PublicURLID || proof.scope.PublishRunNumber != ready.PublishRunNumber || proof.scope.SourceIP.String() != "127.0.0.1" ||
		sha256.Sum256(proof.state.PeerCertificates[0].Raw) != sha256.Sum256(certificate.Certificate[0]) {
		t.Fatal("relay transport lost exact certificate, source, run, or denied grant")
	}
	grant, err = f.identity.routes.CreateIdentityVisitorGrant(t.Context(), ready.PublicURLID, "split-ssh-current", grantRequest)
	if err != nil {
		t.Fatal(err)
	}
	// the host test does not run a root SSH runtime. obtain the real publisher's
	// pre-account control decision, then exercise account-specific decisions with
	// that exact TLS proof and run. root-to-user serving is covered separately in
	// TestIntegrationManagedSSHPublisherRoot, never by a same-uid bypass here.
	permitted := visitorTLS("127.0.0.1", &certificate)
	if err := permitted.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	checkNoBanner(permitted)
	proof = takeSplitSSHAuthorization(t, observed)
	if proof.err != nil || proof.decision.IdentityID != identity.Identity.Id || proof.decision.PublicURLID != ready.PublicURLID || proof.decision.SSHUser != "" {
		t.Fatalf("explicit grant did not pass publisher pre-account authorization: %v", proof.err)
	}
	decision, err := f.identity.routes.AuthorizeSSHVisitor(t.Context(), proof.scope, proof.state, username)
	if err != nil || decision.SSHUser != username || decision.IdentityID != identity.Identity.Id || !decision.ValidUntil.After(time.Now()) {
		t.Fatalf("exact account authorization failed: %+v, %v", decision, err)
	}
	if _, err := f.identity.routes.AuthorizeSSHVisitor(t.Context(), proof.scope, proof.state, "other-user"); !splitSSHForbidden(err) {
		t.Fatal("URL-level grant authorized another SSH account", err)
	}
	wrongRun := proof.scope
	wrongRun.PublishRunNumber++
	if _, err := f.identity.routes.AuthorizeSSHVisitor(t.Context(), wrongRun, proof.state, username); err == nil {
		t.Fatal("certificate decision accepted a different current run number")
	}
	wrongSource := proof.scope
	wrongSource.SourceIP = netip.MustParseAddr("198.51.100.7")
	if _, err := f.identity.routes.AuthorizeSSHVisitor(t.Context(), wrongSource, proof.state, username); !splitSSHForbidden(err) {
		t.Fatal("certificate decision bypassed source IP policy", err)
	}
	if err := f.identity.routes.RevokeVisitorGrant(t.Context(), ready.PublicURLID, grant.Id); err != nil {
		t.Fatal(err)
	}
	if _, err := f.identity.routes.AuthorizeSSHVisitor(t.Context(), proof.scope, proof.state, username); !splitSSHForbidden(err) {
		t.Fatal("fresh account authorization retained a revoked grant", err)
	}
	t.Logf("verified %s carries visitor TLS unchanged and requires exact identity, explicit account grant, source, and current run", transport)
}

func splitSSHForbidden(err error) bool {
	var problem *controlclient.ProblemError
	return errors.As(err, &problem) && problem.Status == http.StatusForbidden
}
