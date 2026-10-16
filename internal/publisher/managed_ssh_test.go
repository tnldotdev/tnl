package publisher

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"io"
	"net"
	"net/netip"
	"os/user"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/livevisitor"
	"github.com/tnldotdev/tnl/internal/proxyproto"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
	"golang.org/x/crypto/ssh"
)

var managedSSHRootUser = flag.String("tnl-test-managed-ssh-root-user", "", "nonroot account in the disposable managed SSH container")

func managedSSHTestUser(t *testing.T) string {
	t.Helper()
	if *managedSSHRootUser != "" {
		return *managedSSHRootUser
	}
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if u.Uid == "0" {
		t.Skip("requires a nonroot developer account or the explicit disposable root fixture")
	}
	return u.Username
}

func managedSSHTestSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func managedSSHTestConfig(t *testing.T) PublicURLServerConfig {
	t.Helper()
	return PublicURLServerConfig{Hostname: "shell.example", PublicURLID: "ssh-url", PublishRunID: "ssh-run", PublishRunNumber: 7,
		ServiceProtocol: controlv1.Ssh, PublicPort: 2222, AccessMode: controlv1.Restricted,
		SSH: &SSHConfig{HostKey: managedSSHTestSigner(t), Users: []string{managedSSHTestUser(t)}},
		AuthorizeSSHVisitor: func(context.Context, Visitor, tls.ConnectionState, string) (controlclient.SSHVisitorDecision, error) {
			return controlclient.SSHVisitorDecision{}, livevisitor.ErrDenied
		}}
}

// the fixture represents the publisher side of a relay stream. only the relay
// supplies the original metadata and AccessPending; client TLS stays unchanged.
func listenManagedSSHPublisher(t *testing.T, config PublicURLServerConfig) (*PublicURLServer, string) {
	t.Helper()
	route, err := NewPublicURLServer(config)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = route.Close()
		t.Fatal(err)
	}
	header, err := proxyproto.Encode(proxyproto.Header{Source: netip.MustParseAddrPort("192.0.2.10:40001"), Destination: netip.MustParseAddrPort("203.0.113.10:2222")})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var workers sync.WaitGroup
	go func() {
		defer close(done)
		defer workers.Wait()
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Go(func() {
				stream := &publicURLReaderConn{Conn: c, reader: io.MultiReader(bytes.NewReader(header), c)}
				route.handleVisitorHeader(stream, true, tunnelv1.VisitorStreamHeader{PublicURLID: config.PublicURLID, PublishRunID: config.PublishRunID, PublishRunNumber: config.PublishRunNumber, AccessPending: true})
			})
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); _ = route.Close(); awaitPublisherTest(t, done) })
	return route, listener.Addr().String()
}

func managedSSHTestTLS(t *testing.T, server, client tls.Certificate) *tls.Config {
	t.Helper()
	c := &tls.Config{ServerName: "shell.example", RootCAs: rootsForCertificate(t, server), MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}
	if len(client.Certificate) != 0 {
		c.Certificates = []tls.Certificate{client}
	}
	return c
}

func TestManagedSSHRejectsRawTargetsAndAnonymousConfiguration(t *testing.T) {
	for _, change := range []struct {
		name  string
		apply func(*PublicURLServerConfig)
	}{
		{"target", func(c *PublicURLServerConfig) { c.Target = "127.0.0.1:22" }},
		{"target TLS", func(c *PublicURLServerConfig) { c.TargetTLS = true }},
		{"anonymous", func(c *PublicURLServerConfig) { c.AccessMode = controlv1.Anonymous }},
		{"missing authorizer", func(c *PublicURLServerConfig) { c.AuthorizeSSHVisitor = nil }},
		{"missing host configuration", func(c *PublicURLServerConfig) { c.SSH = nil }},
		{"root account", func(c *PublicURLServerConfig) { c.SSH.Users = []string{"root"} }},
	} {
		t.Run(change.name, func(t *testing.T) {
			config := managedSSHTestConfig(t)
			change.apply(&config)
			if route, err := NewPublicURLServer(config); err == nil {
				_ = route.Close()
				t.Fatal("accepted unmanaged SSH configuration")
			}
		})
	}
}

func TestManagedSSHNoBannerBeforeTLSCertificateAndGrant(t *testing.T) {
	config := managedSSHTestConfig(t)
	var checks, promotions atomic.Int32
	config.AuthorizeSSHVisitor = func(_ context.Context, visitor Visitor, state tls.ConnectionState, username string) (controlclient.SSHVisitorDecision, error) {
		checks.Add(1)
		if !state.HandshakeComplete || len(state.PeerCertificates) != 1 || !visitor.Header.AccessPending || visitor.Source.String() != "192.0.2.10:40001" || username != "" {
			t.Error("pre-account authorization lost the exact TLS proof or trusted metadata")
		}
		return controlclient.SSHVisitorDecision{}, livevisitor.ErrDenied
	}
	config.PromoteVisitor = func(context.Context, Visitor) error { promotions.Add(1); return nil }
	route, address := listenManagedSSHPublisher(t, config)
	dial := func() net.Conn {
		t.Helper()
		c, err := net.DialTimeout("tcp", address, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		return c
	}
	// no certificate is installed, so even a TLS ClientHello cannot produce SSH.
	missing := tls.Client(dial(), &tls.Config{ServerName: config.Hostname, InsecureSkipVerify: true}) // local uninstalled fixture certificate.
	if err := missing.HandshakeContext(t.Context()); err == nil {
		t.Fatal("accepted TLS before public URL certificate installation")
	}
	certificate := publicURLTestCertificate(t, config.Hostname)
	if err := route.InstallCertificate(certificate); err != nil {
		t.Fatal(err)
	}
	raw := dial()
	if _, err := io.WriteString(raw, "SSH-2.0-unwrapped-client\r\n"); err != nil {
		t.Fatal(err)
	}
	response, _ := io.ReadAll(raw)
	if bytes.Contains(response, []byte("SSH-")) {
		t.Fatalf("raw SSH received a banner: %q", response)
	}
	missing = tls.Client(dial(), managedSSHTestTLS(t, certificate, tls.Certificate{}))
	if err := missing.HandshakeContext(t.Context()); err == nil {
		t.Fatal("accepted SSH transport without a visitor certificate")
	}
	if checks.Load() != 0 {
		t.Fatal("missing TLS proof reached control authorization")
	}
	ungranted := tls.Client(dial(), managedSSHTestTLS(t, certificate, certificate))
	if err := ungranted.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(ungranted)
	if len(response) != 0 || err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("ungranted TLS visitor received application bytes: %q, %v", response, err)
	}
	if checks.Load() != 1 || promotions.Load() != 0 {
		t.Fatalf("denied proof: checks=%d promotions=%d", checks.Load(), promotions.Load())
	}
}

type sshVisitorAuthorizerFunc func(context.Context, controlclient.VisitorCertificateScope, tls.ConnectionState, string) (controlclient.SSHVisitorDecision, error)

func (f sshVisitorAuthorizerFunc) AuthorizeSSHVisitor(ctx context.Context, scope controlclient.VisitorCertificateScope, state tls.ConnectionState, username string) (controlclient.SSHVisitorDecision, error) {
	return f(ctx, scope, state, username)
}

func TestSSHVisitorAuthorizationBindsCertificateRunSourceAndAccount(t *testing.T) {
	certificate := publicURLTestCertificate(t, "shell.example")
	state := tls.ConnectionState{HandshakeComplete: true, PeerCertificates: []*x509.Certificate{certificate.Leaf}}
	visitor := Visitor{Run: PublishRunIdentity{PublicURLID: "url", PublishRunID: "run", Number: 4}, Source: netip.MustParseAddrPort("192.0.2.10:1234")}
	scope := controlclient.VisitorCertificateScope{PublicURLID: "url", PublishRunID: "run", PublishRunNumber: 4, PublishRunToken: "private-run-token"}
	calls := 0
	authorize := sshVisitorAuthorization(sshVisitorAuthorizerFunc(func(_ context.Context, bound controlclient.VisitorCertificateScope, got tls.ConnectionState, username string) (controlclient.SSHVisitorDecision, error) {
		calls++
		if bound.SourceIP.String() != "192.0.2.10" || bound.PublishRunID != scope.PublishRunID || bound.PublishRunToken != scope.PublishRunToken || sha256.Sum256(got.PeerCertificates[0].Raw) != sha256.Sum256(certificate.Leaf.Raw) {
			t.Error("SSH authorization lost its exact proof")
		}
		return controlclient.SSHVisitorDecision{IdentityID: "identity", PublicURLID: "url", SSHUser: username, ValidUntil: time.Now().Add(time.Minute)}, nil
	}), scope)
	for _, username := range []string{"", "alice", "bob"} {
		decision, err := authorize(t.Context(), visitor, state, username)
		if err != nil || decision.SSHUser != username {
			t.Fatalf("exact account decision: %+v, %v", decision, err)
		}
	}
	if calls != 3 {
		t.Fatal("SSH account-specific checks reused a URL-only decision")
	}
	visitor.Run.PublishRunID = "replaced-run"
	if _, err := authorize(t.Context(), visitor, state, "alice"); !errors.Is(err, livevisitor.ErrDenied) || calls != 3 {
		t.Fatal("SSH authorization accepted another run")
	}
	visitor.Run.PublishRunID = scope.PublishRunID
	state.PeerCertificates = nil
	if _, err := authorize(t.Context(), visitor, state, "alice"); !errors.Is(err, livevisitor.ErrDenied) || calls != 3 {
		t.Fatal("SSH authorization accepted an anonymous TLS proof")
	}
}
