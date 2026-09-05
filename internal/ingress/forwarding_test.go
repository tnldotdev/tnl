package ingress

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/relay"
	"github.com/tnldotdev/tnl/internal/routebackend"
	"github.com/tnldotdev/tnl/internal/servicepki"
	"github.com/tnldotdev/tnl/internal/tunnel"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestForwarderPoolsExactRelaySessionAndPreservesBytes(t *testing.T) {
	material := newForwardingTestMaterial(t)
	requests := make(chan forwardingTestRequest, 3)
	server := startForwardingTestServer(t, material, func(ctx context.Context, transport muxsession.Session) error {
		return captureForwardingRequests(ctx, transport, requests)
	})
	forwarder := newTestForwarder(t, material)

	entry := forwardingTestEntry(time.Now(), server.address())
	backends, err := forwarder.Backends(entry)
	if err != nil {
		t.Fatalf("Backends: %v", err)
	}
	if len(backends) != 1 {
		t.Fatalf("backends = %d; want 1", len(backends))
	}

	for _, visitorConnectionID := range []string{"visitor_connection_1", "visitor_connection_2"} {
		connection, err := backends[0].Open(t.Context(), visitorConnectionID)
		if err != nil {
			t.Fatalf("Open(%q): %v", visitorConnectionID, err)
		}
		if _, err := connection.Write([]byte("ping")); err != nil {
			t.Fatalf("write %q: %v", visitorConnectionID, err)
		}
		response := make([]byte, 4)
		if _, err := io.ReadFull(connection, response); err != nil || string(response) != "pong" {
			t.Fatalf("response for %q = %q, %v", visitorConnectionID, response, err)
		}
		_ = connection.Close()

		request := <-requests
		want := forwardingTestHeader(entry, visitorConnectionID)
		if request.header != want || request.payload != "ping" {
			t.Fatalf("forwarded request = %#v; want header %#v and payload ping", request, want)
		}
	}
	if got := server.accepted.Load(); got != 1 {
		t.Fatalf("accepted sessions = %d; want one pooled session", got)
	}

	entry.PublisherConnections[0].RelayRunId = "relay_run_2"
	entry.PublisherConnections[0].RelayLeaseRevision++
	connection, err := mustOnlyBackend(t, forwarder, entry).Open(t.Context(), "visitor_connection_3")
	if err != nil {
		t.Fatalf("Open replacement lease: %v", err)
	}
	if _, err := connection.Write([]byte("next")); err != nil {
		t.Fatalf("write replacement lease: %v", err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(connection, response); err != nil || string(response) != "pong" {
		t.Fatalf("replacement response = %q, %v", response, err)
	}
	_ = connection.Close()
	request := <-requests
	if want := forwardingTestHeader(entry, "visitor_connection_3"); request.header != want || request.payload != "next" {
		t.Fatalf("replacement request = %#v; want header %#v and payload next", request, want)
	}
	if got := server.accepted.Load(); got != 2 {
		t.Fatalf("accepted sessions = %d; want a new session for the replacement lease", got)
	}
}

func TestForwarderRejectsMismatchedRelayCertificate(t *testing.T) {
	material := newForwardingTestMaterial(t)
	wrongCertificate := issueForwardingTestCertificate(t, material.authority, servicepki.Identity{
		Role: servicepki.RoleRelay, RelayServiceID: "relay_service_1", ProcessID: "relay_2",
	})
	server := startForwardingTestServerWithCertificate(t, material, wrongCertificate, func(ctx context.Context, transport muxsession.Session) error {
		return captureForwardingRequests(ctx, transport, make(chan forwardingTestRequest, 1))
	})
	forwarder := newTestForwarder(t, material)

	backend := mustOnlyBackend(t, forwarder, forwardingTestEntry(time.Now(), server.address()))
	_, err := backend.Open(t.Context(), "visitor_connection_1")
	if err == nil || !strings.Contains(err.Error(), "certificate identity does not match") {
		t.Fatalf("Open error = %v; want exact relay identity rejection", err)
	}
	if got := server.accepted.Load(); got != 0 {
		t.Fatalf("accepted sessions = %d; want no authenticated session", got)
	}
}

func TestForwarderPreservesStaleAssignmentRejection(t *testing.T) {
	material := newForwardingTestMaterial(t)
	registry := relay.NewRegistry()
	acceptor, err := relay.NewForwardingAcceptor(relay.ForwardingAcceptorConfig{
		Registry: registry, StreamCapacity: 8,
	})
	if err != nil {
		t.Fatalf("NewForwardingAcceptor: %v", err)
	}
	server := startForwardingTestServer(t, material, acceptor.Accept)
	forwarder := newTestForwarder(t, material)
	backend := mustOnlyBackend(t, forwarder, forwardingTestEntry(time.Now(), server.address()))

	for _, visitorConnectionID := range []string{"visitor_connection_1", "visitor_connection_2"} {
		_, err := backend.Open(t.Context(), visitorConnectionID)
		var protocolError *tunnel.ProtocolError
		if !errors.As(err, &protocolError) || protocolError.Code != tunnelv1.StaleConnectionAssignment {
			t.Fatalf("Open(%q) error = %v; want stale connection assignment", visitorConnectionID, err)
		}
	}
	if got := server.accepted.Load(); got != 1 {
		t.Fatalf("accepted sessions = %d; semantic rejections must not replace the session", got)
	}
}

func TestForwarderConvertsRoutingPolicyWithoutSharingMutableState(t *testing.T) {
	material := newForwardingTestMaterial(t)
	forwarder := newTestForwarder(t, material)
	entry := forwardingTestEntry(time.Now(), "relay.internal:9445")
	entry.IpPolicy = ingressv1.Allowlist
	entry.AllowedIpPrefixes = []string{"192.0.2.0/24"}

	route, err := forwarder.Route(entry)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if route.ID != entry.RouteId || route.RouteVersion != uint64(entry.RouteVersion) ||
		len(route.Backends) != 1 || len(route.AllowedIPPrefixes) != 1 || route.AllowedIPPrefixes[0].String() != "192.0.2.0/24" {
		t.Fatalf("route = %#v", route)
	}
	entry.AllowedIpPrefixes[0] = "198.51.100.0/24"
	if route.AllowedIPPrefixes[0].String() != "192.0.2.0/24" {
		t.Fatal("route retained mutable routing-table state")
	}

	entry.IpPolicy = ingressv1.AllowAll
	if _, err := forwarder.Route(entry); err == nil {
		t.Fatal("allow-all route with allowlist prefixes was accepted")
	}
}

type forwardingTestMaterial struct {
	authority  servicepki.Authority
	roots      *x509.CertPool
	ingress    tls.Certificate
	relay      tls.Certificate
	serverName string
}

func newForwardingTestMaterial(t *testing.T) forwardingTestMaterial {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	authority, err := servicepki.GenerateAuthority(now)
	if err != nil {
		t.Fatalf("GenerateAuthority: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(authority.CertificatePEM)) {
		t.Fatal("append service authority")
	}
	return forwardingTestMaterial{
		authority: authority,
		roots:     roots,
		ingress: issueForwardingTestCertificate(t, authority, servicepki.Identity{
			Role: servicepki.RoleIngress, ProcessID: "ingress_1",
		}),
		relay: issueForwardingTestCertificate(t, authority, servicepki.Identity{
			Role: servicepki.RoleRelay, RelayServiceID: "relay_service_1", ProcessID: "relay_1",
		}),
		serverName: "relay.example",
	}
}

func issueForwardingTestCertificate(
	t *testing.T,
	authority servicepki.Authority,
	identity servicepki.Identity,
) tls.Certificate {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate service key: %v", err)
	}
	requestDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, privateKey)
	if err != nil {
		t.Fatalf("create service CSR: %v", err)
	}
	issued, err := servicepki.SignServiceCSR(
		authority,
		identity,
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: requestDER})),
		time.Now().UTC(),
		time.Hour,
	)
	if err != nil {
		t.Fatalf("SignServiceCSR: %v", err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("encode service key: %v", err)
	}
	certificate, err := tls.X509KeyPair(
		[]byte(issued.CertificatePEM),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER}),
	)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	return certificate
}

func newTestForwarder(t *testing.T, material forwardingTestMaterial) *Forwarder {
	t.Helper()
	forwarder, err := NewForwarder(ForwarderConfig{TLSConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: material.roots,
		Certificates: []tls.Certificate{material.ingress},
	}})
	if err != nil {
		t.Fatalf("NewForwarder: %v", err)
	}
	t.Cleanup(func() {
		if err := forwarder.Close(); err != nil && !errors.Is(err, muxsession.ErrClosed) {
			t.Errorf("Forwarder.Close: %v", err)
		}
	})
	return forwarder
}

func mustOnlyBackend(
	t *testing.T,
	forwarder *Forwarder,
	entry ingressv1.IngressRoutingTableEntry,
) routebackend.Backend {
	t.Helper()
	backends, err := forwarder.Backends(entry)
	if err != nil {
		t.Fatalf("Backends: %v", err)
	}
	if len(backends) != 1 {
		t.Fatalf("backends = %d; want 1", len(backends))
	}
	return backends[0]
}

func forwardingTestEntry(now time.Time, address string) ingressv1.IngressRoutingTableEntry {
	now = now.UTC()
	return ingressv1.IngressRoutingTableEntry{
		RouteId: "route_1", RouteSessionId: "route_session_1", RouteVersion: 2,
		RouteExpiresAt: now.Add(time.Hour),
		PublisherConnections: []ingressv1.IngressRoutingPublisherConnection{{
			ConnectionSlot: 0, PublisherConnectionId: "publisher_connection_1",
			ConnectionAssignmentRevision: 3, RelayServiceId: "relay_service_1",
			RelayId: "relay_1", RelayRunId: "relay_run_1", RelayLeaseRevision: 4,
			InternalRelayAddress: address, TlsServerName: "relay.example", LeaseExpiresAt: now.Add(time.Minute),
		}},
	}
}

func forwardingTestHeader(
	entry ingressv1.IngressRoutingTableEntry,
	visitorConnectionID string,
) tunnelv1.InternalForwardingHeader {
	connection := entry.PublisherConnections[0]
	return tunnelv1.InternalForwardingHeader{
		ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.InternalForwardingStream,
		VisitorConnectionID: visitorConnectionID, RouteID: entry.RouteId,
		RouteSessionID: entry.RouteSessionId, RouteVersion: uint64(entry.RouteVersion),
		PublisherConnectionID: connection.PublisherConnectionId, ConnectionSlot: uint8(connection.ConnectionSlot),
		ConnectionAssignmentRevision: uint64(connection.ConnectionAssignmentRevision),
		RelayServiceID:               connection.RelayServiceId, RelayID: connection.RelayId,
		RelayRunID: connection.RelayRunId, RelayLeaseRevision: uint64(connection.RelayLeaseRevision),
		RouteExpiresAt: entry.RouteExpiresAt, LeaseExpiresAt: connection.LeaseExpiresAt,
	}
}

type forwardingTestRequest struct {
	header  tunnelv1.InternalForwardingHeader
	payload string
}

func captureForwardingRequests(
	ctx context.Context,
	transport muxsession.Session,
	requests chan<- forwardingTestRequest,
) error {
	session, hello, err := tunnel.Accept(ctx, transport, func(_ context.Context, message tunnelv1.Message) error {
		if message.Role != tunnelv1.Ingress {
			return &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if hello.Role != tunnelv1.Ingress {
		return errors.New("test relay accepted a non-ingress tunnel")
	}
	defer session.Close()
	for {
		incoming, err := session.AcceptInternalForwardingStream(ctx)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) || errors.Is(err, muxsession.ErrClosed) {
				return nil
			}
			return err
		}
		if err := incoming.Accept(); err != nil {
			return err
		}
		payload := make([]byte, 4)
		if _, err := io.ReadFull(incoming.Stream, payload); err != nil {
			return err
		}
		if _, err := incoming.Stream.Write([]byte("pong")); err != nil {
			return err
		}
		requests <- forwardingTestRequest{header: incoming.Header, payload: string(payload)}
		_ = incoming.Stream.Close()
	}
}

type forwardingTestServer struct {
	listener net.Listener
	cancel   context.CancelFunc
	accepted atomic.Int32
	errors   chan error
	active   sync.WaitGroup
}

func startForwardingTestServer(
	t *testing.T,
	material forwardingTestMaterial,
	handle func(context.Context, muxsession.Session) error,
) *forwardingTestServer {
	t.Helper()
	return startForwardingTestServerWithCertificate(t, material, material.relay, handle)
}

func startForwardingTestServerWithCertificate(
	t *testing.T,
	material forwardingTestMaterial,
	certificate tls.Certificate,
	handle func(context.Context, muxsession.Session) error,
) *forwardingTestServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	server := &forwardingTestServer{
		listener: listener, cancel: cancel, errors: make(chan error, 16),
	}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: material.roots,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("test relay received no ingress certificate")
			}
			identity, err := servicepki.CertificateIdentity(state.PeerCertificates[0])
			if err != nil || identity.Role != servicepki.RoleIngress || identity.ProcessID != "ingress_1" {
				return errors.New("test relay received the wrong ingress identity")
			}
			return nil
		},
	}
	server.active.Add(1)
	go func() {
		defer server.active.Done()
		for {
			connection, err := listener.Accept()
			if err != nil {
				if ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
					server.errors <- err
				}
				return
			}
			server.active.Add(1)
			go func() {
				defer server.active.Done()
				transport, err := muxsession.AcceptTLSYamux(ctx, connection, tlsConfig, muxsession.TLSYamuxConfig{})
				if err != nil {
					if ctx.Err() == nil {
						server.errors <- err
					}
					return
				}
				server.accepted.Add(1)
				if err := handle(ctx, transport); err != nil && ctx.Err() == nil {
					server.errors <- err
				}
			}()
		}
	}()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		server.active.Wait()
		close(server.errors)
		for err := range server.errors {
			t.Errorf("forwarding test server: %v", err)
		}
	})
	return server
}

func (s *forwardingTestServer) address() string {
	return s.listener.Addr().String()
}
