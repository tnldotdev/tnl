package ingress

import (
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
	"github.com/tnldotdev/tnl/internal/routebackend"
)

const fixtureTimeout = 5 * time.Second

func ingressContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), fixtureTimeout)
	t.Cleanup(cancel)
	return ctx
}

func ingressAwait[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case result := <-ch:
		return result
	case <-time.After(fixtureTimeout):
		t.Fatal("ingress worker timed out")
		var zero T
		return zero
	}
}

func ingressWorker(t *testing.T, unblock func(), run func() error) <-chan error {
	t.Helper()
	result, done := make(chan error, 1), make(chan struct{})
	t.Cleanup(func() { unblock(); ingressAwait(t, done) })
	go func() { defer close(done); result <- run() }()
	return result
}

func startIngress(t *testing.T, config Config, configure ...func(*Server)) (*Server, string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if config.MaxConnections == 0 {
		config.MaxConnections = 8
	}
	if config.MaxRouteConnections == 0 {
		config.MaxRouteConnections = 2
	}
	if config.Lookup == nil {
		config.Lookup = func(string) (Route, bool) { return Route{}, false }
	}
	server, err := New(listener, config)
	if err != nil {
		t.Fatal(err)
	}
	for _, configure := range configure {
		configure(server)
	}
	ingressWorker(t, func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Drain(ctx)
	}, func() error {
		err := server.Serve()
		if err != nil {
			t.Errorf("ingress Serve: %v", err)
		}
		return err
	})
	return server, listener.Addr().String()
}

func ownIngressConn(t *testing.T, c net.Conn) {
	t.Helper()
	t.Cleanup(func() { _ = c.Close() })
	if err := c.SetDeadline(time.Now().Add(fixtureTimeout)); err != nil {
		t.Fatal(err)
	}
}

func ingressClient(t *testing.T, address, hostname, source string, protos ...string) *tls.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", address, fixtureTimeout)
	if err != nil {
		t.Fatal(err)
	}
	ownIngressConn(t, c)
	if source != "" {
		header, err := proxyproto.Encode(proxyproto.Header{Source: netip.MustParseAddrPort(source), Destination: netip.MustParseAddrPort("203.0.113.10:443")})
		if err != nil {
			t.Fatal(err)
		}
		if err := writeAll(c, header); err != nil {
			t.Fatal(err)
		}
	}
	return tls.Client(c, &tls.Config{ServerName: hostname, MinVersion: tls.VersionTLS12, NextProtos: protos, InsecureSkipVerify: true}) // Local self-signed fixture.
}

func exchangePing(t *testing.T, c *tls.Conn) {
	t.Helper()
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	var response [4]byte
	if _, err := io.ReadFull(c, response[:]); err != nil || string(response[:]) != "pong" {
		t.Fatalf("response = %q, %v", response, err)
	}
	_ = c.Close()
}

func routeConfig(backends ...routebackend.Backend) Config {
	return Config{Lookup: func(host string) (Route, bool) {
		return Route{ID: "route_test", RouteVersion: 1, RecoveryEpisodeID: 7, Backends: backends}, host == "route.example"
	}}
}

type backendResult struct {
	header                       proxyproto.Header
	visitorConnectionID, request string
	err                          error
}
type tlsBackend struct {
	connection net.Conn
	result     chan backendResult
	opens      atomic.Int32
	visitorID  chan string
}

func newTLSBackend(t *testing.T, protos ...string) *tlsBackend {
	t.Helper()
	a, b := net.Pipe()
	ownIngressConn(t, a)
	ownIngressConn(t, b)
	backend := &tlsBackend{connection: a, result: make(chan backendResult, 1), visitorID: make(chan string, 1)}
	certificate := testCertificate(t, "route.example")
	ingressWorker(t, func() { _ = a.Close(); _ = b.Close() }, func() error {
		defer b.Close()
		header, replay, err := proxyproto.Decode(b)
		if err != nil {
			backend.result <- backendResult{err: err}
			return nil
		}
		secured := tls.Server(&testReaderConn{Conn: b, reader: replay}, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12, NextProtos: protos})
		request := make([]byte, 4)
		_, err = io.ReadFull(secured, request)
		if err == nil {
			_, err = secured.Write([]byte("pong"))
		}
		backend.result <- backendResult{header: header, visitorConnectionID: <-backend.visitorID, request: string(request), err: err}
		return nil
	})
	return backend
}
func (b *tlsBackend) Open(_ context.Context, id string) (net.Conn, error) {
	if b.opens.Add(1) != 1 {
		return nil, errors.New("TLS fixture unexpectedly opened twice")
	}
	b.visitorID <- id
	return b.connection, nil
}

type testReaderConn struct {
	net.Conn
	reader io.Reader
}

func (c *testReaderConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func testCertificate(t *testing.T, hostname string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: hostname}, DNSNames: []string{hostname}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

type testUsageConnection struct {
	mu                                                         sync.Mutex
	routeID                                                    string
	routeVersion                                               uint64
	source                                                     netip.Addr
	openedAt, closedAt, publisherOpeningAt, publisherOpenedAt  time.Time
	policyDenials, capacityDenials, publisherFailures, streams int
	ingressBytes, egressBytes                                  int64
	closed                                                     chan struct{}
}
type testUsageRecorder struct{ opened chan *testUsageConnection }

func newUsageRecorder() *testUsageRecorder {
	return &testUsageRecorder{opened: make(chan *testUsageConnection, 8)}
}
func (r *testUsageRecorder) Open(id string, version uint64, source netip.Addr, at time.Time) UsageConnection {
	u := &testUsageConnection{routeID: id, routeVersion: version, source: source, openedAt: at, closed: make(chan struct{})}
	r.opened <- u
	return u
}
func (u *testUsageConnection) PolicyDenied(time.Time) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.policyDenials++
}
func (u *testUsageConnection) CapacityDenied(time.Time) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.capacityDenials++
}
func (u *testUsageConnection) VisitorStreamOpening(at time.Time) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.publisherOpeningAt = at
}
func (u *testUsageConnection) VisitorStreamOpened(at time.Time) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.publisherOpenedAt = at
}
func (u *testUsageConnection) VisitorStreamOpenFailed(time.Time) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.publisherFailures++
}
func (u *testUsageConnection) StreamOpened(time.Time) { u.mu.Lock(); defer u.mu.Unlock(); u.streams++ }
func (u *testUsageConnection) AddIngress(n int64, _ time.Time) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.ingressBytes += n
}
func (u *testUsageConnection) AddEgress(n int64, _ time.Time) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.egressBytes += n
}
func (u *testUsageConnection) Close(at time.Time) {
	u.mu.Lock()
	u.closedAt = at
	u.mu.Unlock()
	close(u.closed)
}

type testMetrics struct {
	sourceLimiterRejections, sourceLimiterEntries, ipAllowlistDenials atomic.Int32
	forwardedMu                                                       sync.Mutex
	forwardedBytes                                                    map[string]int64
	entriesChanged                                                    chan int
}

func (*testMetrics) IncCapacityRejection(string)  {}
func (m *testMetrics) IncSourceLimiterRejection() { m.sourceLimiterRejections.Add(1) }
func (m *testMetrics) SetSourceLimiterEntries(n int) {
	m.sourceLimiterEntries.Store(int32(n))
	if m.entriesChanged != nil {
		m.entriesChanged <- n
	}
}
func (m *testMetrics) IncIPAllowlistDenial() { m.ipAllowlistDenials.Add(1) }
func (m *testMetrics) AddForwardedBytes(direction string, n int64) {
	m.forwardedMu.Lock()
	defer m.forwardedMu.Unlock()
	if m.forwardedBytes == nil {
		m.forwardedBytes = make(map[string]int64)
	}
	m.forwardedBytes[direction] += n
}
func (*testMetrics) SetIngressStreams(int)              {}
func (*testMetrics) ObserveRelayAttempt(string, string) {}
