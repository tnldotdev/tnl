package ingress

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
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
	if config.Control == nil {
		fixture, _, _, _ := publicServiceTestConfig(t)
		config.Control, config.Forwarder, config.CurrentLease = fixture.Control, fixture.Forwarder, fixture.CurrentLease
	}
	server, err := New(listener, config)
	if err != nil {
		t.Fatal(err)
	}
	for _, configure := range configure {
		configure(server)
	}
	applyServiceRoutingFixture(t, server)
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

func applyServiceRoutingFixture(t *testing.T, server *Server) {
	t.Helper()
	lease := server.config.CurrentLease()
	if lease.Draining || !lease.LeaseExpiresAt.After(time.Now()) {
		return
	}
	started := time.Now()
	snapshot, err := server.config.Control.ReadIngressServices(t.Context(), lease.IngressId, ingressv1.IngressLeaseIdentity{
		IngressId: lease.IngressId, IngressRunId: lease.IngressRunId, IngressLeaseRevision: lease.IngressLeaseRevision,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.services.apply(started, lease, snapshot); err != nil {
		t.Fatal(err)
	}
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
	return tls.Client(c, &tls.Config{ServerName: hostname, MinVersion: tls.VersionTLS12, NextProtos: protos, InsecureSkipVerify: true}) // local self-signed fixture.
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

type backendResult struct {
	header                       proxyproto.Header
	visitorConnectionID, request string
	err                          error
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

type testMetrics struct {
	visitorOpenSuccesses atomic.Int32
	visitorOpenFailures  atomic.Int32
	ipAllowlistDenials   atomic.Int32
	visitorOutcomes      chan string
	forwardedMu          sync.Mutex
	forwardedBytes       map[string]int64
}

func (*testMetrics) IncCapacityRejection(string)            {}
func (*testMetrics) IncInspectionFailure(string)            {}
func (*testMetrics) ObserveTrafficAdmission(string, string) {}

func (m *testMetrics) ObserveVisitor(outcome observability.VisitorOutcome) {
	if outcome == "policy_denied" {
		m.ipAllowlistDenials.Add(1)
	}
	if m.visitorOutcomes != nil {
		m.visitorOutcomes <- string(outcome)
	}
}
func (m *testMetrics) ObserveVisitorOpen(success bool, _ time.Duration) {
	if success {
		m.visitorOpenSuccesses.Add(1)
	} else {
		m.visitorOpenFailures.Add(1)
	}
}
func (*testMetrics) SetIngressConnections(string, int) {}
func (m *testMetrics) AddForwardedBytes(direction string, n int64) {
	m.forwardedMu.Lock()
	defer m.forwardedMu.Unlock()
	if m.forwardedBytes == nil {
		m.forwardedBytes = make(map[string]int64)
	}
	m.forwardedBytes[direction] += n
}
func (*testMetrics) SetIngressStreams(int)                                         {}
func (*testMetrics) ObserveRelayAttempt(string, observability.RelayAttemptOutcome) {}
