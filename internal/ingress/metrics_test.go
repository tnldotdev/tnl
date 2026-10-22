package ingress

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
)

type pendingTLSBackend struct{ connection net.Conn }

func (b pendingTLSBackend) Open(context.Context, string) (net.Conn, error) { return b.connection, nil }

func (b pendingTLSBackend) OpenPending(ctx context.Context, id string) (net.Conn, error) {
	return b.Open(ctx, id)
}

func TestRestrictedVisitorForwardingHasSuccessfulOutcome(t *testing.T) {
	// TCP half-close semantics matter here: net.Pipe reports ErrClosedPipe when
	// the fixture ends, which correctly records a failed copy rather than success.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	certificate := testCertificate(t, "route.example")
	result := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			result <- err
			return
		}
		defer conn.Close()
		_, replay, err := proxyproto.Decode(conn)
		if err != nil {
			result <- err
			return
		}
		secured := tls.Server(&testReaderConn{Conn: conn, reader: replay}, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
		data := make([]byte, 4)
		_, err = io.ReadFull(secured, data)
		if err == nil {
			_, err = secured.Write([]byte("pong"))
		}
		_ = secured.Close()
		result <- err
	}()
	connection, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	backend := pendingTLSBackend{connection}
	metrics := &testMetrics{visitorOutcomes: make(chan string, 1)}
	config := publicURLConfig(backend)
	lookup := config.Lookup
	config.Lookup = func(host string) (PublicURL, LookupReason) {
		url, reason := lookup(host)
		url.AccessMode = "restricted"
		return url, reason
	}
	config.Metrics = metrics
	_, address := startIngress(t, config)
	visitor := ingressClient(t, address, "route.example", "")
	exchangePing(t, visitor)
	if err := ingressAwait(t, result); err != nil {
		t.Fatal(err)
	}
	_ = visitor.Close()
	if outcome := ingressAwait(t, metrics.visitorOutcomes); outcome != "forwarded" {
		t.Fatalf("restricted visitor reached publisher but was reported as %s", outcome)
	}
}

func TestVisitorLookupFailureIsCountedOnce(t *testing.T) {
	metrics := &testMetrics{visitorOutcomes: make(chan string, 2)}
	_, address := startIngress(t, Config{
		Metrics: metrics,
		Lookup:  func(string) (PublicURL, LookupReason) { return PublicURL{}, LookupNotFound },
	})
	visitor := ingressClient(t, address, "missing.example", "")
	if err := visitor.Handshake(); err == nil {
		t.Fatal("missing hostname was forwarded")
	}
	if got := ingressAwait(t, metrics.visitorOutcomes); got != "lookup_missing" {
		t.Fatalf("visitor outcome=%q, want lookup_missing", got)
	}
	select {
	case extra := <-metrics.visitorOutcomes:
		t.Fatalf("visitor counted twice: %q", extra)
	default:
	}
}

func TestConcurrentBackendGaugeReturnsToZero(t *testing.T) {
	metrics := observability.New("ingress")
	server := &Server{config: Config{Metrics: metrics}, backends: make(map[net.Conn]struct{})}
	var group sync.WaitGroup
	for range 64 {
		group.Add(1)
		go func() {
			defer group.Done()
			left, right := net.Pipe()
			defer right.Close()
			if !server.trackBackend(left) {
				t.Error("failed to track backend")
				return
			}
			if err := server.releaseBackend(left); err != nil {
				t.Error(err)
			}
		}()
	}
	group.Wait()
	families, err := metrics.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() == "tnl_ingress_backend_streams" {
			if got := family.Metric[0].GetGauge().GetValue(); got != 0 {
				t.Fatalf("backend streams=%g after concurrent closes", got)
			}
			return
		}
	}
	t.Fatal("missing ingress backend stream gauge")
}
