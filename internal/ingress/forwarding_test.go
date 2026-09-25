package ingress

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/relay"
	"github.com/tnldotdev/tnl/internal/routebackend"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/internal/tunnel"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

const forwardingClusterSecret = "forwarding-cluster-secret-012345678901"

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
		connection, err := backends[0].Open(ingressContext(t), visitorConnectionID)
		if err != nil {
			t.Fatalf("Open(%q): %v", visitorConnectionID, err)
		}
		ownIngressConn(t, connection)
		if _, err := connection.Write([]byte("ping")); err != nil {
			t.Fatalf("write %q: %v", visitorConnectionID, err)
		}
		response := make([]byte, 4)
		if _, err := io.ReadFull(connection, response); err != nil || string(response) != "pong" {
			t.Fatalf("response for %q = %q, %v", visitorConnectionID, response, err)
		}
		_ = connection.Close()

		request := ingressAwait(t, requests)
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
	connection, err := mustOnlyBackend(t, forwarder, entry).Open(ingressContext(t), "visitor_connection_3")
	if err != nil {
		t.Fatalf("Open replacement lease: %v", err)
	}
	ownIngressConn(t, connection)
	if _, err := connection.Write([]byte("next")); err != nil {
		t.Fatalf("write replacement lease: %v", err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(connection, response); err != nil || string(response) != "pong" {
		t.Fatalf("replacement response = %q, %v", response, err)
	}
	_ = connection.Close()
	request := ingressAwait(t, requests)
	if want := forwardingTestHeader(entry, "visitor_connection_3"); request.header != want || request.payload != "next" {
		t.Fatalf("replacement request = %#v; want header %#v and payload next", request, want)
	}
	if got := server.accepted.Load(); got != 2 {
		t.Fatalf("accepted sessions = %d; want a new session for the replacement lease", got)
	}
}

func TestForwarderReportsUnexpectedRelaySessionClose(t *testing.T) {
	material := newForwardingTestMaterial(t)
	relaySessions := make(chan muxsession.Session, 1)
	server := startForwardingTestServer(t, material, func(ctx context.Context, transport muxsession.Session) error {
		relaySessions <- transport
		return captureForwardingRequests(ctx, transport, make(chan forwardingTestRequest, 1))
	})
	forwarder := newTestForwarder(t, material)
	closed := make(chan error, 1)
	forwarder.onSessionClosed = func(serviceID, relayID, origin string, cause error) {
		if serviceID != "relay_service_1" || relayID != "relay_1" || origin != "observed_close" {
			closed <- errors.New("unexpected relay session closure")
			return
		}
		closed <- cause
	}
	backend := mustOnlyBackend(t, forwarder, forwardingTestEntry(time.Now(), server.address())).(forwardingBackend)
	if _, _, err := forwarder.session(ingressContext(t), backend.target); err != nil {
		t.Fatal(err)
	}
	if err := ingressAwait(t, relaySessions).Close(); err != nil {
		t.Fatal(err)
	}
	if err := ingressAwait(t, closed); !errors.Is(err, io.EOF) {
		t.Fatalf("unexpected session close cause = %v", err)
	}
}

func TestForwarderRejectsMismatchedRelayCertificate(t *testing.T) {
	material := newForwardingTestMaterial(t)
	wrongCertificate := issueForwardingTestCertificate(t, material.authority, material.authorityKey, "wrong.example")
	server := startForwardingTestServerWithCertificate(t, material, wrongCertificate, func(ctx context.Context, transport muxsession.Session) error {
		return captureForwardingRequests(ctx, transport, make(chan forwardingTestRequest, 1))
	})
	forwarder := newTestForwarder(t, material)

	backend := mustOnlyBackend(t, forwarder, forwardingTestEntry(time.Now(), server.address()))
	_, err := backend.Open(ingressContext(t), "visitor_connection_1")
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("Open error = %v; want relay hostname rejection", err)
	}
	select {
	case err := <-server.errors:
		if !strings.Contains(err.Error(), "tls: bad certificate") {
			t.Fatalf("server handshake error = %v; want client certificate rejection", err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not observe the client certificate rejection")
	}
	if got := server.accepted.Load(); got != 0 {
		t.Fatalf("accepted sessions = %d; want no authenticated session", got)
	}
}

func TestForwarderPreservesStaleAssignmentRejection(t *testing.T) {
	material := newForwardingTestMaterial(t)
	registry := relay.NewRegistry()
	acceptor, err := relay.NewForwardingAcceptor(relay.ForwardingAcceptorConfig{
		Registry: registry, ClusterSecrets: forwardingTestSecrets(t), StreamCapacity: 8,
	})
	if err != nil {
		t.Fatalf("NewForwardingAcceptor: %v", err)
	}
	server := startForwardingTestServer(t, material, acceptor.Accept)
	forwarder := newTestForwarder(t, material)
	backend := mustOnlyBackend(t, forwarder, forwardingTestEntry(time.Now(), server.address()))

	for _, visitorConnectionID := range []string{"visitor_connection_1", "visitor_connection_2"} {
		_, err := backend.Open(ingressContext(t), visitorConnectionID)
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
	authority    *x509.Certificate
	authorityKey *ecdsa.PrivateKey
	roots        *x509.CertPool
	relay        tls.Certificate
	serverName   string
}

func newForwardingTestMaterial(t *testing.T) forwardingTestMaterial {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	authorityKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate authority key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "forwarding test authority"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	authorityDER, err := x509.CreateCertificate(rand.Reader, template, template, &authorityKey.PublicKey, authorityKey)
	if err != nil {
		t.Fatalf("issue authority certificate: %v", err)
	}
	authority, err := x509.ParseCertificate(authorityDER)
	if err != nil {
		t.Fatalf("parse authority certificate: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(authority)
	return forwardingTestMaterial{
		authority: authority, authorityKey: authorityKey, roots: roots,
		relay:      issueForwardingTestCertificate(t, authority, authorityKey, "relay.example"),
		serverName: "relay.example",
	}
}

func issueForwardingTestCertificate(
	t *testing.T,
	authority *x509.Certificate,
	authorityKey *ecdsa.PrivateKey,
	hostname string,
) tls.Certificate {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate relay key: %v", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: hostname}, DNSNames: []string{hostname},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, authority, &privateKey.PublicKey, authorityKey)
	if err != nil {
		t.Fatalf("issue relay certificate: %v", err)
	}
	privateKeyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal relay key: %v", err)
	}
	certificate, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKeyDER}),
	)
	if err != nil {
		t.Fatalf("parse relay key pair: %v", err)
	}
	return certificate
}

func newTestForwarder(t *testing.T, material forwardingTestMaterial) *Forwarder {
	t.Helper()
	forwarder, err := NewForwarder(ForwarderConfig{
		TLSConfig:     &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: material.roots},
		ClusterSecret: forwardingClusterSecret,
	})
	if err != nil {
		t.Fatalf("NewForwarder: %v", err)
	}
	t.Cleanup(func() {
		// t.Context is canceled before cleanup, so the peer may already have
		// closed its transport. EOF is a normal close outcome at this point.
		if err := forwarder.Close(); err != nil && !errors.Is(err, muxsession.ErrClosed) && !errors.Is(err, io.EOF) {
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
		if message.Role != tunnelv1.Ingress || message.Credential != forwardingClusterSecret {
			return &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
		}
		return nil
	})
	if err != nil {
		return err
	}
	defer session.Close()
	if hello.Role != tunnelv1.Ingress {
		return errors.New("test relay accepted a non-ingress tunnel")
	}
	for {
		incoming, err := session.AcceptInternalForwardingStream(ctx)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) || errors.Is(err, muxsession.ErrClosed) {
				return nil
			}
			return err
		}
		if err := func() error {
			defer incoming.Stream.Close()
			if err := incoming.Accept(); err != nil {
				return err
			}
			if err := incoming.Stream.SetDeadline(time.Now().Add(fixtureTimeout)); err != nil {
				return err
			}
			payload := make([]byte, 4)
			if _, err := io.ReadFull(incoming.Stream, payload); err != nil {
				return err
			}
			if _, err := incoming.Stream.Write([]byte("pong")); err != nil {
				return err
			}
			select {
			case requests <- forwardingTestRequest{header: incoming.Header, payload: string(payload)}:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}(); err != nil {
			return err
		}
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
	t.Cleanup(func() { _ = listener.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	server := &forwardingTestServer{
		listener: listener, cancel: cancel, errors: make(chan error, 16),
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
	done := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		ingressAwait(t, done)
		for err := range server.errors {
			t.Errorf("forwarding test server: %v", err)
		}
	})
	server.active.Add(1)
	go func() {
		defer func() { server.active.Done(); server.active.Wait(); close(server.errors); close(done) }()
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
				defer connection.Close()
				stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
				defer stop()
				_ = connection.SetDeadline(time.Now().Add(fixtureTimeout))
				transport, err := muxsession.AcceptTLSYamux(ctx, connection, tlsConfig, muxsession.TLSYamuxConfig{})
				if err != nil {
					if ctx.Err() == nil {
						server.errors <- err
					}
					return
				}
				defer transport.Close()
				server.accepted.Add(1)
				if err := handle(ctx, transport); err != nil && ctx.Err() == nil {
					server.errors <- err
				}
			}()
		}
	}()
	return server
}

func (s *forwardingTestServer) address() string {
	return s.listener.Addr().String()
}

func forwardingTestSecrets(t *testing.T) serviceapi.BearerSecrets {
	t.Helper()
	secrets, err := serviceapi.NewBearerSecrets(forwardingClusterSecret, "")
	if err != nil {
		t.Fatal(err)
	}
	return secrets
}
