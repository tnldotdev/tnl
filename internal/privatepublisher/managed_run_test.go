package privatepublisher

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/proxyproto"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func managedTestCertificate(t *testing.T, host string) (tls.Certificate, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	root, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{host}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(root)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der, root}, PrivateKey: leafKey}, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: host}
}

func privateFixture(t *testing.T, target string) (*Prepared, *Bound, tunnelv1.PrivatePublisherConnectionRef, *tls.Config) {
	t.Helper()
	id := func(prefix string) string {
		v, err := opaqueid.New(prefix)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	service, team, domain := id(opaqueid.PrivateServicePrefix), id(opaqueid.TeamPrefix), id(opaqueid.DomainPrefix)
	identity := authorityv1.PublisherEnrollmentResult{ClientId: id(opaqueid.PublisherIdentityPrefix), GrantId: id(opaqueid.PublisherGrantPrefix), KeyId: id(opaqueid.PublisherIdentityKeyPrefix), TeamId: team, Kind: authorityv1.PrivateService, PrivateServiceId: &service}
	const hostname = "service.worktree.member.example.test"
	plan := controlv1.CertificatePlan{CacheKey: "managed-service-test", Scope: hostname, Identifiers: []string{hostname}, ChallengeMethod: controlv1.Dns01}
	prep := controlv1.PrivateServiceRunPreparation{TeamId: team, PrivateServiceId: service, PrivateRunId: id(opaqueid.PrivateRunPrefix), RunNumber: 7, PublisherIdentityId: identity.ClientId, PublisherGrantId: identity.GrantId, PublisherKeyId: identity.KeyId, IdempotencyKey: id(opaqueid.IdempotencyPrefix), ExpiresAt: time.Now().Add(time.Minute), Hostname: hostname, ServicePort: 25443, DomainId: domain, CertificatePlan: &plan}
	approved := controlv1.PrivateService{Id: service, TeamId: team, DomainId: &domain, Protocol: controlv1.Tcp, Enabled: true, TrustRevision: 1, ManagedTls: &controlv1.ManagedServiceTLS{Hostname: hostname, Port: prep.ServicePort}}
	p, err := newManagedPrepared(prep, approved, RunConfig{Identity: identity, Target: target})
	if err != nil {
		t.Fatal(err)
	}
	certificate, verification := managedTestCertificate(t, hostname)
	if err := p.installManagedCertificate(certificate); err != nil {
		t.Fatal(err)
	}
	p.managedVisitor = func(tunnelv1.PrivateForwardingHeader) publisher.ManagedVisitorAuthentication {
		return publisher.ConnectorVisitor{Check: func(context.Context) (publisher.ManagedVisitorDecision, error) {
			return publisher.ManagedVisitorDecision{Allowed: true, ValidUntil: time.Now().Add(time.Minute)}, nil
		}}
	}
	setup := controlv1.PrivateServiceRunSetup{PrivateServiceId: service, PrivateRunId: prep.PrivateRunId, RunNumber: prep.RunNumber, RunToken: "private-run-token"}
	for slot := range 2 {
		setup.PublisherConnections = append(setup.PublisherConnections, controlv1.ConnectionAssignment{PublisherConnectionId: id(opaqueid.PublisherConnectionPrefix), ConnectionSlot: slot, ConnectionAssignmentRevision: 3, RelayServiceId: fmt.Sprintf("relay-%d", slot), RelayAddress: fmt.Sprintf("relay-%d.example:443", slot), TlsServerName: fmt.Sprintf("relay-%d.example", slot), PublisherConnectionCredential: "private-assignment-credential", PublisherConnectionCredentialExpiresAt: time.Now().Add(time.Minute)})
	}
	bound, err := p.Activate(setup)
	if err != nil {
		t.Fatal(err)
	}
	return p, bound, bound.assignments[setup.PublisherConnections[0].PublisherConnectionId], verification
}

func privateHeader(t *testing.T, ref tunnelv1.PrivatePublisherConnectionRef) tunnelv1.PrivateForwardingHeader {
	t.Helper()
	id := func(prefix string) string {
		v, err := opaqueid.New(prefix)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	return tunnelv1.PrivateForwardingHeader{PrivateStreamHeader: tunnelv1.PrivateStreamHeader{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.PrivateForwardingStream, PrivateServiceID: ref.PrivateServiceID, PrivateRunID: ref.PrivateRunID, RunNumber: ref.RunNumber, Connector: &tunnelv1.ConnectorAdmission{SessionID: id(opaqueid.PrivateConnectorSessionPrefix), IdentityID: id(opaqueid.IdentityPrefix), DeviceID: id(opaqueid.VisitorDevicePrefix), GrantRevision: 1}, SourceIP: "192.0.2.10", VisitorConnectionID: id(opaqueid.VisitorConnectionPrefix), PublisherConnectionID: ref.PublisherConnectionID, ConnectionAssignmentRevision: ref.ConnectionAssignmentRevision, ExpiresAt: time.Now().Add(time.Minute)}, ConnectionSlot: ref.ConnectionSlot, RelayServiceID: ref.RelayServiceID, RelayID: "relay-instance", RelayRunID: id(opaqueid.RelayRunPrefix), RelayLeaseRevision: 2, LeaseExpiresAt: time.Now().Add(time.Minute)}
}

func TestManagedStreamRejectsStaleAdmissionsBeforeTargetDial(t *testing.T) {
	for _, name := range []string{"service", "run", "number", "assignment", "slot", "relay", "expired", "source", "denied", "wrong-certificate-name"} {
		t.Run(name, func(t *testing.T) {
			target, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			p, bound, ref, verification := privateFixture(t, target.Addr().String())
			header := privateHeader(t, ref)
			switch name {
			case "service":
				header.PrivateServiceID = opaqueid.PrivateServicePrefix + "bbbbbbbbbbbbbbbbbbbbbb"
			case "run":
				header.PrivateRunID = opaqueid.PrivateRunPrefix + "bbbbbbbbbbbbbbbbbbbbbb"
			case "number":
				header.RunNumber++
			case "assignment":
				header.ConnectionAssignmentRevision++
			case "slot":
				header.ConnectionSlot = 1
			case "relay":
				header.RelayServiceID = "other-relay"
			case "expired":
				header.ExpiresAt = time.Now().Add(-time.Second)
			case "source":
				header.SourceIP = "192.0.2.11"
			case "denied":
				p.managedVisitor = func(tunnelv1.PrivateForwardingHeader) publisher.ManagedVisitorAuthentication {
					return publisher.ConnectorVisitor{Check: func(context.Context) (publisher.ManagedVisitorDecision, error) {
						return publisher.ManagedVisitorDecision{}, nil
					}}
				}
			case "wrong-certificate-name":
				verification.ServerName = "another.example.test"
			}
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			_ = client.SetDeadline(time.Now().Add(time.Second))
			done := make(chan error, 1)
			go func() { defer server.Close(); done <- bound.serveBody(t.Context(), ref, server, header) }()
			proxy, _ := proxyproto.Encode(proxyproto.Header{Source: netip.MustParseAddrPort("192.0.2.10:40000"), Destination: netip.MustParseAddrPort("203.0.113.1:443")})
			_, _ = client.Write(proxy)
			secure := tls.Client(client, verification)
			handshakeErr := secure.Handshake()
			if name == "denied" && handshakeErr != nil {
				t.Fatal(handshakeErr)
			}
			_ = client.Close()
			if err := <-done; err == nil {
				t.Fatal("stale or unverified stream reached target")
			}
			_ = target.SetDeadline(time.Now().Add(10 * time.Millisecond))
			if connection, err := target.Accept(); err == nil {
				_ = connection.Close()
				t.Fatal("invalid admission dialed the target")
			}
		})
	}
}

func TestManagedCertificateAndRunIdentityCannotBeSubstituted(t *testing.T) {
	p, bound, _, _ := privateFixture(t, "127.0.0.1:1")
	wrong, _ := managedTestCertificate(t, "sibling.example.test")
	if err := p.installManagedCertificate(wrong); err == nil {
		t.Fatal("certificate scope widened")
	}
	state := controlv1.PrivateServiceRunState{PrivateServiceId: p.Preparation.PrivateServiceId, PrivateRunId: p.Preparation.PrivateRunId, RunNumber: p.Preparation.RunNumber, State: "ready", PublisherExpiresAt: time.Now().Add(time.Minute), PublisherConnections: []controlv1.ConnectionAssignment{bound.connections[0], bound.connections[1]}}
	if err := bound.ApplyHeartbeat(state); err != nil {
		t.Fatal(err)
	}
	state.RunNumber++
	if !errors.Is(bound.ApplyHeartbeat(state), ErrPrivateStream) {
		t.Fatal("restarted run reused old assignments")
	}
	bound.Invalidate()
	if _, _, err := bound.Hello(0); !errors.Is(err, ErrPrivateStream) {
		t.Fatal("closed run reopened")
	}
}
