package service

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
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

func TestManagedPublicConnectorAcceptsLoopbackHTTPAuthority(t *testing.T) {
	for _, public := range []bool{false, true} {
		for _, protocol := range []config.ProtocolName{config.ProtocolHTTP, config.ProtocolKubernetes} {
			t.Run(fmt.Sprintf("public=%v/%s", public, protocol), func(t *testing.T) {
				target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Header.Get("Authorization") != "Bearer cluster-only" {
						t.Error("application authentication changed")
					}
					_, _ = io.WriteString(w, "loopback connector")
				}))
				defer target.Close()
				p, bound, ref, verification := privateFixture(t, target.Listener.Addr().String())
				p.managedPublic, p.managedProtocol = public, protocol
				roots := x509.NewCertPool()
				roots.AddCert(target.Certificate())
				p.managedTargetTLS = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: target.Certificate().DNSNames[0]}
				var err error
				p.serviceHTTPRequests, err = publisher.NewServiceHTTPRequestLimits(nil)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				client, server := net.Pipe()
				defer client.Close()
				_ = client.SetDeadline(time.Now().Add(5 * time.Second))
				done := make(chan error, 1)
				header := privateHeader(t, ref)
				go func() { defer server.Close(); done <- bound.serveBody(ctx, ref, server, header) }()
				proxy, _ := proxyproto.Encode(proxyproto.Header{Source: netip.MustParseAddrPort("192.0.2.10:40000"), Destination: netip.MustParseAddrPort("203.0.113.1:443")})
				if _, err := client.Write(proxy); err != nil {
					t.Fatal(err)
				}
				native, err := writeNativeFixtureOpening(t, client, header)
				if err != nil {
					t.Fatal(err)
				}
				secure := tls.Client(native, verification)
				if err := secure.HandshakeContext(ctx); err != nil {
					t.Fatal(err)
				}
				request, _ := http.NewRequest("GET", "https://127.0.0.1:15432/api/v1/pods", nil)
				request.Header.Set("Authorization", "Bearer cluster-only")
				request.Close = true
				if err := request.Write(secure); err != nil {
					t.Fatal(err)
				}
				response, err := http.ReadResponse(bufio.NewReader(secure), request)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil || response.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != "loopback connector" {
					t.Fatalf("loopback authority rejected: %d %q %v", response.StatusCode, body, err)
				}
				_ = client.Close()
				select {
				case <-done:
				case <-ctx.Done():
					t.Fatal("connector publisher did not join")
				}
				if p.managedPublic != public || p.managedHostname != verification.ServerName {
					t.Fatal("connector changed approved public endpoint metadata")
				}
			})
		}
	}
}

func privateFixture(t *testing.T, target string) (*Prepared, *Bound, tunnelv1.ServicePublisherConnectionRef, *tls.Config) {
	t.Helper()
	id := func(prefix string) string {
		v, err := opaqueid.New(prefix)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	service, team, domain := id(opaqueid.ServicePrefix), id(opaqueid.TeamPrefix), id(opaqueid.DomainPrefix)
	identity := authorityv1.PublisherEnrollmentResult{ClientId: id(opaqueid.PublisherIdentityPrefix), GrantId: id(opaqueid.PublisherGrantPrefix), KeyId: id(opaqueid.PublisherIdentityKeyPrefix), TeamId: team, Kind: authorityv1.Service, ServiceId: &service}
	const hostname = "service.worktree.member.example.test"
	plan := controlv1.CertificatePlan{CacheKey: "service-test", Scope: hostname, Identifiers: []string{hostname}, ChallengeMethod: controlv1.Dns01}
	prep := controlv1.ServiceRunPreparation{TeamId: team, ServiceId: service, ServiceRunId: id(opaqueid.ServiceRunPrefix), RunNumber: 7, PublisherIdentityId: identity.ClientId, PublisherGrantId: identity.GrantId, PublisherKeyId: identity.KeyId, IdempotencyKey: id(opaqueid.IdempotencyPrefix), ExpiresAt: time.Now().Add(time.Minute), Hostname: hostname, ServicePort: 25443, DomainId: domain, CertificatePlan: &plan}
	approved := controlv1.Service{Id: service, TeamId: team, DomainId: &domain, Protocol: controlv1.Tcp, Enabled: true, TrustRevision: 1, Endpoint: &controlv1.ServiceEndpoint{Hostname: hostname, Port: prep.ServicePort}}
	p, err := newManagedPrepared(prep, approved, RunConfig{Identity: identity, Target: target})
	if err != nil {
		t.Fatal(err)
	}
	certificate, verification := managedTestCertificate(t, hostname)
	if err := p.installManagedCertificate(certificate); err != nil {
		t.Fatal(err)
	}
	p.managedVisitor = func(tunnelv1.ServiceForwardingHeader, func(tunnelv1.ServiceVisitorReference) error) publisher.ServiceVisitorAuthentication {
		return publisher.ConnectorVisitor{Check: func(context.Context) (publisher.ServiceVisitorDecision, error) {
			return publisher.ServiceVisitorDecision{Allowed: true, ValidUntil: time.Now().Add(time.Minute)}, nil
		}}
	}
	setup := controlv1.ServiceRunSetup{ServiceId: service, ServiceRunId: prep.ServiceRunId, RunNumber: prep.RunNumber, RunToken: "service-run-token"}
	for slot := range 2 {
		setup.PublisherConnections = append(setup.PublisherConnections, controlv1.ConnectionAssignment{PublisherConnectionId: id(opaqueid.PublisherConnectionPrefix), ConnectionSlot: slot, ConnectionAssignmentRevision: 3, RelayServiceId: fmt.Sprintf("relay-%d", slot), RelayAddress: fmt.Sprintf("relay-%d.example:443", slot), TlsServerName: fmt.Sprintf("relay-%d.example", slot), PublisherConnectionCredential: "private-assignment-credential", PublisherConnectionCredentialExpiresAt: time.Now().Add(time.Minute)})
	}
	bound, err := p.Activate(setup)
	if err != nil {
		t.Fatal(err)
	}
	prepareNativeFixturePolicy(t, p)
	return p, bound, bound.assignments[setup.PublisherConnections[0].PublisherConnectionId], verification
}

func privateHeader(t *testing.T, ref tunnelv1.ServicePublisherConnectionRef) tunnelv1.ServiceForwardingHeader {
	t.Helper()
	id := func(prefix string) string {
		v, err := opaqueid.New(prefix)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	visitor := id(opaqueid.VisitorConnectionPrefix)
	return tunnelv1.ServiceForwardingHeader{ServiceStreamHeader: tunnelv1.ServiceStreamHeader{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.ServiceForwardingStream, ServiceID: ref.ServiceID, ServiceRunID: ref.ServiceRunID, RunNumber: ref.RunNumber, Connector: &tunnelv1.ConnectorAdmission{SessionID: id(opaqueid.ConnectorSessionPrefix), Subject: nativeFixtureSubject(), GrantRevision: 1}, SourceIP: "192.0.2.10", VisitorConnectionID: visitor, PublisherConnectionID: ref.PublisherConnectionID, ConnectionAssignmentRevision: ref.ConnectionAssignmentRevision, ExpiresAt: time.Now().Add(time.Minute), Reservation: nativeFixtureReservation(ref, visitor)}, ConnectionSlot: ref.ConnectionSlot, RelayServiceID: ref.RelayServiceID, RelayID: "relay-instance", RelayRunID: id(opaqueid.RelayRunPrefix), RelayLeaseRevision: 2, LeaseExpiresAt: time.Now().Add(time.Minute)}
}

func TestServiceStreamRejectsStaleAdmissionsBeforeTargetDial(t *testing.T) {
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
				header.ServiceID = opaqueid.ServicePrefix + "bbbbbbbbbbbbbbbbbbbbbb"
			case "run":
				header.ServiceRunID = opaqueid.ServiceRunPrefix + "bbbbbbbbbbbbbbbbbbbbbb"
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
				p.policy.Close()
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
			native, _ := writeNativeFixtureOpening(t, client, header)
			secure := tls.Client(native, verification)
			handshakeErr := secure.Handshake()
			if name == "denied" && handshakeErr == nil {
				t.Fatal("denied permission reached visitor TLS")
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
	state := controlv1.ServiceRunState{ServiceId: p.Preparation.ServiceId, ServiceRunId: p.Preparation.ServiceRunId, RunNumber: p.Preparation.RunNumber, State: "ready", PublisherExpiresAt: time.Now().Add(time.Minute), PublisherConnections: []controlv1.ConnectionAssignment{bound.connections[0], bound.connections[1]}}
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
