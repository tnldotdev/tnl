package ingress

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/proxyproto"
	"github.com/tnldotdev/tnl/internal/sourceauth"
	"github.com/tnldotdev/tnl/internal/sourcelimiter"
	"github.com/tnldotdev/tnl/internal/worker"
)

var testSourceKey = [32]byte{1, 2, 3}

func TestIngressRoutesTLSWithProxyMetadata(t *testing.T) {
	certificate := testCertificate(t, "route.example")
	backend := &tlsBackend{certificate: certificate, result: make(chan backendResult, 1)}
	usage := &testUsageConnection{closed: make(chan struct{})}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(listener, Config{
		Lookup: func(hostname string) (Route, bool) {
			return Route{ID: "route_test", Version: 1, Backend: backend, SourceKey: testSourceKey}, hostname == "route.example"
		},
		OpenUsage: func(routeID string, version uint64, source netip.Addr, at time.Time) UsageConnection {
			usage.routeID = routeID
			usage.version = version
			usage.source = source
			usage.openedAt = at
			return usage
		},
		MaxConnections:      8,
		MaxRouteConnections: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- server.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Drain(ctx)
		<-served
	})

	client, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
		ServerName:         "route.example",
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // The test certificate is self-signed.
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != "pong" {
		t.Fatalf("response = %q", response)
	}
	_ = client.Close()

	result := <-backend.result
	if result.err != nil {
		t.Fatal(result.err)
	}
	if result.request != "ping" || !result.header.Source.Addr().IsLoopback() || !result.header.Destination.Addr().IsLoopback() {
		t.Fatalf("backend result = %#v", result)
	}
	select {
	case <-usage.closed:
	case <-time.After(time.Second):
		t.Fatal("usage connection did not close")
	}
	usage.mu.Lock()
	defer usage.mu.Unlock()
	if usage.routeID != "route_test" || usage.version != 1 || !usage.source.IsLoopback() || usage.openedAt.IsZero() || usage.closedAt.IsZero() {
		t.Fatalf("usage identity = %#v", usage)
	}
	if usage.publisherOpeningAt.IsZero() || usage.publisherOpenedAt.IsZero() || usage.streams != 1 {
		t.Fatalf("usage lifecycle = %#v", usage)
	}
	if usage.ingressBytes <= 0 || usage.egressBytes <= 0 {
		t.Fatalf("usage bytes = %d ingress, %d egress", usage.ingressBytes, usage.egressBytes)
	}
}

func TestIngressUsesProvisioningRouteOnlyForACMETLSALPN(t *testing.T) {
	backend := &tlsBackend{
		certificate: testCertificate(t, "route.example"), result: make(chan backendResult, 1),
		nextProtos: []string{"acme-tls/1"},
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var usageOpened atomic.Bool
	server, err := New(listener, Config{
		Lookup: func(string) (Route, bool) {
			return Route{AllowedIPPrefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}, true
		},
		LookupChallenge: func(hostname string) (Route, bool) {
			return Route{ID: "route_test", Version: 1, Backend: backend, SourceKey: testSourceKey}, hostname == "route.example"
		},
		OpenUsage: func(string, uint64, netip.Addr, time.Time) UsageConnection {
			usageOpened.Store(true)
			return &testUsageConnection{closed: make(chan struct{})}
		},
		MaxConnections: 8, MaxRouteConnections: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- server.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Drain(ctx)
		<-served
	})

	client, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
		ServerName: "route.example", NextProtos: []string{"acme-tls/1"}, MinVersion: tls.VersionTLS12,
		InsecureSkipVerify: true, // The test certificate is self-signed.
	})
	if err != nil {
		t.Fatal(err)
	}
	if client.ConnectionState().NegotiatedProtocol != "acme-tls/1" {
		t.Fatalf("negotiated ALPN = %q", client.ConnectionState().NegotiatedProtocol)
	}
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	if result := <-backend.result; result.err != nil {
		t.Fatal(result.err)
	}
	if usageOpened.Load() {
		t.Fatal("ACME challenge opened usage accounting")
	}
}

func TestIngressEnforcesProxySourceLimitsAndRouteAllowlistInOrder(t *testing.T) {
	certificate := testCertificate(t, "route.example")
	backend := &tlsBackend{certificate: certificate, result: make(chan backendResult, 1)}
	metrics := &testMetrics{}
	usage := new(testUsageRecorder)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var lookups atomic.Int32
	server, err := New(listener, Config{
		Lookup: func(hostname string) (Route, bool) {
			lookups.Add(1)
			return Route{
				ID: "route_test", Version: 1, Backend: backend,
				SourceKey:         testSourceKey,
				AllowedIPPrefixes: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
			}, hostname == "route.example"
		},
		RequireProxyHeader: true, Metrics: metrics,
		OpenUsage:      usage.Open,
		MaxConnections: 8, MaxRouteConnections: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	server.limiter, err = sourcelimiter.New(sourcelimiter.Config{
		Rate: 0.000001, Burst: 1, MaxEntries: 8, IdleExpiration: time.Hour, Shards: 4,
		OnEntriesChanged: metrics.SetSourceLimiterEntries,
	})
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- server.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Drain(ctx)
		<-served
	})

	malformed, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := writeProxyHeader(malformed, "198.51.100.1:40001"); err != nil {
		t.Fatal(err)
	}
	_, _ = malformed.Write([]byte("not TLS"))
	_ = malformed.Close()
	for deadline := time.Now().Add(time.Second); server.limiter.Entries() != 1 && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
	}
	if server.limiter.Entries() != 1 || lookups.Load() != 0 {
		t.Fatalf("malformed connection: limiter entries=%d, route lookups=%d", server.limiter.Entries(), lookups.Load())
	}

	allowed, err := dialProxyTLS(listener.Addr().String(), "198.51.100.2:40002")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := allowed.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(allowed, response); err != nil || string(response) != "pong" {
		t.Fatalf("allowed response = %q, %v", response, err)
	}
	_ = allowed.Close()
	result := <-backend.result
	if result.err != nil || result.header.Source != netip.MustParseAddrPort("198.51.100.2:40002") {
		t.Fatalf("allowed backend result = %#v", result)
	}

	if connection, err := dialProxyTLS(listener.Addr().String(), "198.51.100.2:40003"); err == nil {
		_ = connection.Close()
		t.Fatal("rate-limited source completed TLS")
	}
	if connection, err := dialProxyTLS(listener.Addr().String(), "203.0.113.3:40004"); err == nil {
		_ = connection.Close()
		t.Fatal("disallowed source completed TLS")
	}
	if metrics.sourceLimiterRejections.Load() != 1 || metrics.ipAllowlistDenials.Load() != 1 ||
		backend.opens.Load() != 1 || lookups.Load() != 2 {
		t.Fatalf("rejections=%d denials=%d backend opens=%d lookups=%d",
			metrics.sourceLimiterRejections.Load(), metrics.ipAllowlistDenials.Load(), backend.opens.Load(), lookups.Load())
	}
	server.mu.Lock()
	remainingByRoute := len(server.byRoute)
	server.mu.Unlock()
	if remainingByRoute != 0 {
		t.Fatalf("route capacity retained denied connections: %#v", server.byRoute)
	}
	attempts := usage.snapshot()
	if len(attempts) != 2 {
		t.Fatalf("usage attempts = %d, want allowed and policy-denied attempts", len(attempts))
	}
	var policies, streams int
	for _, attempt := range attempts {
		attempt.mu.Lock()
		policies += attempt.policyDenials
		streams += attempt.streams
		attempt.mu.Unlock()
	}
	if policies != 1 || streams != 1 {
		t.Fatalf("usage outcomes = %d policy denials, %d streams", policies, streams)
	}
}

func TestIngressRecordsRouteCapacityAndPublisherOpenFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	backend := &blockingOpenBackend{entered: make(chan struct{}), release: make(chan struct{})}
	usage := new(testUsageRecorder)
	server, err := New(listener, Config{
		Lookup: func(hostname string) (Route, bool) {
			return Route{ID: "route_test", Version: 1, Backend: backend, SourceKey: testSourceKey}, hostname == "route.example"
		},
		OpenUsage: usage.Open, OpenTimeout: time.Second,
		MaxConnections: 4, MaxRouteConnections: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- server.Serve() }()
	t.Cleanup(func() {
		backend.releaseOpen()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Drain(ctx)
		<-served
	})

	firstResult := make(chan error, 1)
	go func() {
		connection, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
			ServerName: "route.example", MinVersion: tls.VersionTLS12,
			InsecureSkipVerify: true, // The publisher intentionally fails to open.
		})
		if err == nil {
			_ = connection.Close()
		}
		firstResult <- err
	}()
	select {
	case <-backend.entered:
	case <-time.After(time.Second):
		t.Fatal("first publisher open did not start")
	}
	second, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
		ServerName: "route.example", MinVersion: tls.VersionTLS12,
		InsecureSkipVerify: true, // The route-capacity denial closes before TLS completes.
	})
	if err == nil {
		_ = second.Close()
		t.Fatal("route-capacity-denied connection completed TLS")
	}
	backend.releaseOpen()
	if err := <-firstResult; err == nil {
		t.Fatal("publisher-open-failed connection completed TLS")
	}

	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		attempts := usage.snapshot()
		var capacity, failures int
		for _, attempt := range attempts {
			attempt.mu.Lock()
			capacity += attempt.capacityDenials
			failures += attempt.publisherFailures
			attempt.mu.Unlock()
		}
		if len(attempts) == 2 && capacity == 1 && failures == 1 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("usage outcomes after capacity and open failure = %#v", usage.snapshot())
}

func TestIngressRecordsPublisherFailureWhenBackendTrackingFails(t *testing.T) {
	backend := &blockingSuccessfulOpenBackend{entered: make(chan struct{}), release: make(chan struct{})}
	testIngressPublisherSetupFailure(t, backend, func(server *Server) {
		select {
		case <-backend.entered:
		case <-time.After(time.Second):
			t.Fatal("publisher open did not start")
		}
		server.mu.Lock()
		server.closing = true
		server.mu.Unlock()
		close(backend.release)
	})
}

func TestIngressRecordsPublisherFailureWhenProxyHeaderWriteFails(t *testing.T) {
	testIngressPublisherSetupFailure(t, proxyWriteFailBackend{}, nil)
}

func TestIngressHandsControlTLSOffByExactSNI(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	connections := make(chan net.Conn)
	controlCertificate := testCertificate(t, "control.example")
	server, err := New(listener, Config{
		Lookup:         func(string) (Route, bool) { return Route{}, false },
		ServerHostname: "control.example",
		HandleControl: func(connection net.Conn) bool {
			connections <- connection
			return true
		},
		MaxConnections: 8, MaxRouteConnections: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- server.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Drain(ctx)
		<-served
	})

	controlResult := make(chan error, 1)
	go func() {
		connection := <-connections
		defer connection.Close()
		secured := tls.Server(connection, &tls.Config{
			Certificates: []tls.Certificate{controlCertificate}, MinVersion: tls.VersionTLS12,
		})
		if err := secured.Handshake(); err != nil {
			controlResult <- err
			return
		}
		request := make([]byte, 4)
		if _, err := io.ReadFull(secured, request); err != nil {
			controlResult <- err
			return
		}
		if string(request) != "ping" || !connection.RemoteAddr().(*net.TCPAddr).IP.IsLoopback() {
			controlResult <- errors.New("unexpected control connection")
			return
		}
		_, err := secured.Write([]byte("pong"))
		controlResult <- err
	}()

	client, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
		ServerName: "control.example", MinVersion: tls.VersionTLS12,
		InsecureSkipVerify: true, // The test certificate is self-signed.
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	if string(response) != "pong" {
		t.Fatalf("response = %q", response)
	}
	if err := <-controlResult; err != nil {
		t.Fatal(err)
	}
}

func TestDrainDeadlineForcesBackendClosed(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	backend := &holdingBackend{opened: make(chan struct{}), closed: make(chan struct{})}
	server, err := New(listener, Config{
		Lookup: func(string) (Route, bool) {
			return Route{ID: "route_test", Version: 1, Backend: backend, SourceKey: testSourceKey}, true
		},
		MaxConnections: 2, MaxRouteConnections: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- server.Serve() }()
	connection, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client := tls.Client(connection, &tls.Config{
		ServerName: "route.example", MinVersion: tls.VersionTLS12,
		InsecureSkipVerify: true, // The backend intentionally never completes TLS.
	})
	handshake := make(chan error, 1)
	go func() { handshake <- client.Handshake() }()
	select {
	case <-backend.opened:
	case <-time.After(time.Second):
		t.Fatal("backend did not open")
	}
	drainCtx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err = server.Drain(drainCtx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Drain error = %v, want deadline exceeded", err)
	}
	select {
	case <-backend.closed:
	case <-time.After(time.Second):
		t.Fatal("backend was not force-closed")
	}
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	<-handshake
}

func TestAdmissionRegistersBeforeDrainWait(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server, err := New(listener, Config{
		Lookup:         func(string) (Route, bool) { return Route{}, false },
		MaxConnections: 1, MaxRouteConnections: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	connection, peer := net.Pipe()
	defer peer.Close()
	accounted, ok := server.admit(connection)
	if !ok {
		t.Fatal("connection was not admitted")
	}
	waited := make(chan struct{})
	go func() {
		server.active.Wait()
		close(waited)
	}()
	select {
	case <-waited:
		t.Fatal("wait completed before the admitted handler")
	case <-time.After(20 * time.Millisecond):
	}
	_ = accounted.Close()
	server.active.Done()
	select {
	case <-waited:
	case <-time.After(time.Second):
		t.Fatal("wait did not complete after the handler")
	}
}

func TestTransferredControlConnectionRetainsAdmissionSlot(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server, err := New(listener, Config{
		Lookup: func(string) (Route, bool) { return Route{}, false }, MaxConnections: 1, MaxRouteConnections: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	first, firstPeer := net.Pipe()
	defer firstPeer.Close()
	accounted, ok := server.admit(first)
	if !ok {
		t.Fatal("first connection was not admitted")
	}
	server.transfer(accounted)
	server.active.Done()
	second, secondPeer := net.Pipe()
	defer secondPeer.Close()
	if admitted, ok := server.admit(second); ok {
		_ = admitted.Close()
		t.Fatal("transferred connection released its admission slot")
	}
	_ = second.Close()
	if err := accounted.Close(); err != nil {
		t.Fatal(err)
	}
	third, thirdPeer := net.Pipe()
	defer thirdPeer.Close()
	admitted, ok := server.admit(third)
	if !ok {
		t.Fatal("slot was not released when transferred connection closed")
	}
	_ = admitted.Close()
	server.active.Done()
}

type tlsBackend struct {
	certificate tls.Certificate
	result      chan backendResult
	nextProtos  []string
	opens       atomic.Int32
}

type holdingBackend struct {
	opened chan struct{}
	closed chan struct{}
}

type blockingOpenBackend struct {
	entered     chan struct{}
	release     chan struct{}
	once        sync.Once
	releaseOnce sync.Once
}

type blockingSuccessfulOpenBackend struct {
	entered chan struct{}
	release chan struct{}
}

type proxyWriteFailBackend struct{}

type writeFailConn struct {
	net.Conn
}

type testUsageConnection struct {
	mu                 sync.Mutex
	routeID            string
	version            uint64
	source             netip.Addr
	openedAt           time.Time
	closedAt           time.Time
	publisherOpeningAt time.Time
	publisherOpenedAt  time.Time
	policyDenials      int
	capacityDenials    int
	publisherFailures  int
	streams            int
	ingressBytes       int64
	egressBytes        int64
	closed             chan struct{}
}

type testUsageRecorder struct {
	mu          sync.Mutex
	connections []*testUsageConnection
}

func (r *testUsageRecorder) Open(routeID string, version uint64, source netip.Addr, at time.Time) UsageConnection {
	connection := &testUsageConnection{
		routeID: routeID, version: version, source: source, openedAt: at, closed: make(chan struct{}),
	}
	r.mu.Lock()
	r.connections = append(r.connections, connection)
	r.mu.Unlock()
	return connection
}

func (r *testUsageRecorder) snapshot() []*testUsageConnection {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*testUsageConnection(nil), r.connections...)
}

func (u *testUsageConnection) PolicyDenied(time.Time) {
	u.mu.Lock()
	u.policyDenials++
	u.mu.Unlock()
}

func (u *testUsageConnection) CapacityDenied(time.Time) {
	u.mu.Lock()
	u.capacityDenials++
	u.mu.Unlock()
}

func (u *testUsageConnection) PublisherOpening(at time.Time) {
	u.mu.Lock()
	u.publisherOpeningAt = at
	u.mu.Unlock()
}

func (u *testUsageConnection) PublisherOpened(at time.Time) {
	u.mu.Lock()
	u.publisherOpenedAt = at
	u.mu.Unlock()
}

func (u *testUsageConnection) PublisherOpenFailed(time.Time) {
	u.mu.Lock()
	u.publisherFailures++
	u.mu.Unlock()
}

func (u *testUsageConnection) StreamOpened(time.Time) {
	u.mu.Lock()
	u.streams++
	u.mu.Unlock()
}

func (u *testUsageConnection) AddIngress(bytes int64, _ time.Time) {
	u.mu.Lock()
	u.ingressBytes += bytes
	u.mu.Unlock()
}

func (u *testUsageConnection) AddEgress(bytes int64, _ time.Time) {
	u.mu.Lock()
	u.egressBytes += bytes
	u.mu.Unlock()
}

func (u *testUsageConnection) Close(at time.Time) {
	u.mu.Lock()
	u.closedAt = at
	u.mu.Unlock()
	close(u.closed)
}

func (b *holdingBackend) Open(context.Context) (net.Conn, error) {
	ingress, peer := net.Pipe()
	go func() {
		defer close(b.closed)
		defer peer.Close()
		_, err := sourceauth.Server(peer, testSourceKey)
		if err != nil {
			return
		}
		// Authenticating the claim proves the server has tracked the backend.
		close(b.opened)
		_, _ = io.Copy(io.Discard, peer)
	}()
	return ingress, nil
}

func (b *blockingOpenBackend) Open(ctx context.Context) (net.Conn, error) {
	b.once.Do(func() { close(b.entered) })
	select {
	case <-b.release:
		return nil, errors.New("publisher unavailable")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (b *blockingOpenBackend) releaseOpen() {
	b.releaseOnce.Do(func() { close(b.release) })
}

func (b *blockingSuccessfulOpenBackend) Open(ctx context.Context) (net.Conn, error) {
	close(b.entered)
	select {
	case <-b.release:
		connection, peer := net.Pipe()
		_ = peer.Close()
		return connection, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (proxyWriteFailBackend) Open(context.Context) (net.Conn, error) {
	connection, peer := net.Pipe()
	_ = peer.Close()
	return &writeFailConn{Conn: connection}, nil
}

func (*writeFailConn) Write([]byte) (int, error) {
	return 0, errors.New("proxy header write failed")
}

type backendResult struct {
	header  proxyproto.Header
	request string
	err     error
}

func (b *tlsBackend) Open(context.Context) (net.Conn, error) {
	b.opens.Add(1)
	ingress, publisher := net.Pipe()
	go func() {
		defer publisher.Close()
		claim, err := sourceauth.Server(publisher, testSourceKey)
		if err != nil {
			b.result <- backendResult{err: err}
			return
		}
		server := tls.Server(publisher, &tls.Config{
			Certificates: []tls.Certificate{b.certificate},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   b.nextProtos,
		})
		if err := server.Handshake(); err != nil {
			b.result <- backendResult{err: err}
			return
		}
		request := make([]byte, 4)
		if _, err = io.ReadFull(server, request); err == nil {
			_, err = server.Write([]byte("pong"))
		}
		b.result <- backendResult{header: claim.Header, request: string(request), err: err}
	}()
	return ingress, nil
}

type testMetrics struct {
	sourceLimiterRejections atomic.Int32
	sourceLimiterEntries    atomic.Int32
	ipAllowlistDenials      atomic.Int32
}

func (*testMetrics) IncCapacityRejection(string)  {}
func (m *testMetrics) IncSourceLimiterRejection() { m.sourceLimiterRejections.Add(1) }
func (m *testMetrics) SetSourceLimiterEntries(entries int) {
	m.sourceLimiterEntries.Store(int32(entries))
}
func (m *testMetrics) IncIPAllowlistDenial()         { m.ipAllowlistDenials.Add(1) }
func (*testMetrics) AddForwardedBytes(string, int64) {}
func (*testMetrics) SetStreams(int)                  {}

func dialProxyTLS(address, source string) (*tls.Conn, error) {
	connection, err := net.Dial("tcp", address)
	if err != nil {
		return nil, err
	}
	if err := writeProxyHeader(connection, source); err != nil {
		_ = connection.Close()
		return nil, err
	}
	secured := tls.Client(connection, &tls.Config{
		ServerName: "route.example", MinVersion: tls.VersionTLS12,
		InsecureSkipVerify: true, // The test certificate is self-signed.
	})
	if err := secured.Handshake(); err != nil {
		_ = secured.Close()
		return nil, err
	}
	return secured, nil
}

func testIngressPublisherSetupFailure(
	t *testing.T,
	backend worker.RouteBackend,
	afterOpen func(*Server),
) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	usage := new(testUsageRecorder)
	server, err := New(listener, Config{
		Lookup: func(hostname string) (Route, bool) {
			return Route{ID: "route_test", Version: 1, Backend: backend, SourceKey: testSourceKey}, hostname == "route.example"
		},
		OpenUsage: usage.Open, OpenTimeout: time.Second,
		MaxConnections: 2, MaxRouteConnections: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- server.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Drain(ctx)
		<-served
	})

	result := make(chan error, 1)
	go func() {
		connection, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
			ServerName: "route.example", MinVersion: tls.VersionTLS12,
			InsecureSkipVerify: true, // Stream setup intentionally fails before TLS reaches the publisher.
		})
		if err == nil {
			_ = connection.Close()
		}
		result <- err
	}()
	if afterOpen != nil {
		afterOpen(server)
	}
	if err := <-result; err == nil {
		t.Fatal("publisher-setup-failed connection completed TLS")
	}

	var attempt *testUsageConnection
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		attempts := usage.snapshot()
		if len(attempts) == 1 {
			attempt = attempts[0]
			select {
			case <-attempt.closed:
				goto closed
			default:
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("usage connection did not close")

closed:
	attempt.mu.Lock()
	defer attempt.mu.Unlock()
	outcomes := attempt.policyDenials + attempt.capacityDenials + attempt.publisherFailures + attempt.streams
	if attempt.publisherOpeningAt.IsZero() || attempt.publisherOpenedAt.IsZero() ||
		attempt.publisherFailures != 1 || attempt.streams != 0 || outcomes != 1 {
		t.Fatalf("usage lifecycle = %#v", attempt)
	}
}

func writeProxyHeader(connection net.Conn, source string) error {
	header, err := proxyproto.Encode(proxyproto.Header{
		Source: netip.MustParseAddrPort(source), Destination: netip.MustParseAddrPort("203.0.113.10:443"),
	})
	if err != nil {
		return err
	}
	_, err = io.Copy(connection, bytes.NewReader(header))
	return err
}

func testCertificate(t *testing.T, hostname string) tls.Certificate {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: hostname},
		DNSNames:     []string{hostname},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}
}
