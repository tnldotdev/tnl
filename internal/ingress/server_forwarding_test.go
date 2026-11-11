package ingress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
)

func TestIngressRoutesTLSWithProxyMetadata(t *testing.T) {
	backend := newTLSBackend(t)
	metrics := &testMetrics{visitorOutcomes: make(chan string, 1)}
	type recovery struct {
		id               string
		version, episode uint64
		at               time.Time
	}
	recovered := make(chan recovery, 1)
	config := publicURLConfig(backend)
	config.Metrics = metrics
	config.ObserveRecovery = func(id string, version, episode uint64, at time.Time) {
		recovered <- recovery{id, version, episode, at}
	}
	_, address := startIngress(t, config)
	client := ingressClient(t, address, "ROUTE.EXAMPLE", "")
	exchangePing(t, client)
	result := ingressAwait(t, backend.result)
	if result.err != nil || result.request != "ping" || !result.header.Source.Addr().IsLoopback() || !result.header.Destination.Addr().IsLoopback() {
		t.Fatalf("backend = %+v", result)
	}
	ingressAwait(t, metrics.visitorOutcomes)
	if metrics.visitorOpenSuccesses.Load() != 1 || metrics.visitorOpenFailures.Load() != 0 {
		t.Fatal("visitor stream did not open successfully")
	}
	metrics.forwardedMu.Lock()
	defer metrics.forwardedMu.Unlock()
	if len(metrics.forwardedBytes) != 2 || metrics.forwardedBytes["visitor_to_publisher"] <= 0 || metrics.forwardedBytes["publisher_to_visitor"] <= 0 {
		t.Fatalf("forwarded bytes=%v", metrics.forwardedBytes)
	}
	r := ingressAwait(t, recovered)
	if r.id != "public_url_test" || r.version != 1 || r.episode != 7 || r.at.IsZero() {
		t.Fatalf("recovery=%+v", r)
	}
}

func TestIngressEnforcesProxySourceAndPublicURLAllowlist(t *testing.T) {
	backend := newTLSBackend(t)
	metrics := &testMetrics{visitorOutcomes: make(chan string, 2)}
	var lookups atomic.Int32
	config := Config{RequireProxyHeader: true, TrustedProxyPeers: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, Metrics: metrics, Lookup: func(host string) ([]PublicURL, LookupReason) {
		lookups.Add(1)
		if host != "route.example" {
			return nil, LookupNotFound
		}
		return []PublicURL{{ID: "public_url_test", PublishRunID: "publish_run_test", PublishRunNumber: 1, Backends: []Backend{backend}, HashedIPPolicy: hashedPolicyForTest(t, "198.51.100.0/24"), AttestSource: testBackendSourceProof}}, LookupCurrent
	}}
	server, address := startIngress(t, config)
	malformed := ingressClient(t, address, "route.example", "198.51.100.1:40001")
	// write malformed bytes on the underlying connection, before TLS.
	_, _ = malformed.NetConn().Write([]byte("not TLS"))
	_ = malformed.Close()
	allowed := ingressClient(t, address, "route.example", "198.51.100.2:40002")
	exchangePing(t, allowed)
	result := ingressAwait(t, backend.result)
	if result.err != nil || result.header.Source != netip.MustParseAddrPort("198.51.100.2:40002") {
		t.Fatalf("allowed = %+v", result)
	}
	for _, source := range []string{"203.0.113.3:40004"} {
		client := ingressClient(t, address, "route.example", source)
		if err := client.Handshake(); err == nil {
			t.Fatalf("denied source %s completed TLS", source)
		}
	}
	outcomes := map[string]int{}
	for range 2 {
		outcomes[ingressAwait(t, metrics.visitorOutcomes)]++
	}
	if outcomes["policy_denied"] != 1 || metrics.visitorOpenSuccesses.Load() != 1 || metrics.visitorOpenFailures.Load() != 0 || metrics.ipAllowlistDenials.Load() != 1 || lookups.Load() != 2 || backend.opens.Load() != 1 {
		t.Fatalf("outcomes=%v allowlist=%d lookups=%d opens=%d", outcomes, metrics.ipAllowlistDenials.Load(), lookups.Load(), backend.opens.Load())
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if len(server.byPublicURL) != 0 {
		t.Fatalf("route capacity retained: %v", server.byPublicURL)
	}
}

type gatedOpenBackend struct {
	entered    chan struct{}
	release    <-chan struct{}
	connection net.Conn
	err        error
}

type gatedDeniedBackend struct {
	*gatedOpenBackend
}

func TestDeniedConnectionsHaveSeparateCapacity(t *testing.T) {
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	t.Cleanup(unblock)
	backend := gatedDeniedBackend{&gatedOpenBackend{entered: make(chan struct{}), release: release, err: errors.New("relay unavailable")}}
	metrics := &testMetrics{visitorOutcomes: make(chan string, 2)}
	config := Config{
		RequireProxyHeader: true, TrustedProxyPeers: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, Pending: PendingConfig{Connections: 2, PublicURLConnections: 1, SourceConnections: 1}, Metrics: metrics,
		Lookup: func(host string) ([]PublicURL, LookupReason) {
			if host != "route.example" {
				return nil, LookupNotFound
			}
			return []PublicURL{{ID: "public_url_test", PublishRunID: "publish_run_test", PublishRunNumber: 1, AccessMode: "restricted", Backends: []Backend{backend},
				HashedIPPolicy: hashedPolicyForTest(t, "198.51.100.0/24"), AttestSource: testBackendSourceProof}}, LookupCurrent
		},
	}
	_, address := startIngress(t, config)
	first := ingressClient(t, address, "route.example", "198.51.100.1:40001")
	result := ingressWorker(t, func() { unblock(); _ = first.Close() }, first.Handshake)
	ingressAwait(t, backend.entered)
	second := ingressClient(t, address, "route.example", "198.51.100.2:40002")
	if err := second.Handshake(); err == nil {
		t.Fatal("denied connection bypassed capacity")
	}
	unblock()
	if err := ingressAwait(t, result); err == nil {
		t.Fatal("denied connection completed TLS without a publisher")
	}
	outcomes := map[string]int{}
	for range 2 {
		outcomes[ingressAwait(t, metrics.visitorOutcomes)]++
	}
	if outcomes["capacity_denied"] != 1 || outcomes["open_failed"] != 1 {
		t.Fatalf("denied outcomes = %v", outcomes)
	}
}

func (b *gatedOpenBackend) Start(ctx context.Context, _ string, _ bool, proxy, initial []byte) (net.Conn, error) {
	close(b.entered)
	select {
	case <-b.release:
		if b.err != nil {
			return nil, b.err
		}
		return startTestBackend(ctx, b.connection, proxy, initial)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestIngressRecordsRouteCapacityAndVisitorStreamOpenFailure(t *testing.T) {
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	t.Cleanup(unblock)
	backend := &gatedOpenBackend{entered: make(chan struct{}), release: release, err: errors.New("publisher unavailable")}
	metrics := &testMetrics{visitorOutcomes: make(chan string, 2)}
	config := publicURLConfig(backend)
	config.Metrics = metrics
	config.MaxConnections = 2
	config.Traffic.Default = trafficlimits.Default()
	// lifetime admission follows pool selection and remains attributable to a run.
	// a full concurrent pool has no selected run; pool_selection_test covers it.
	config.Traffic.Default.TotalConnections = 1
	_, address := startIngress(t, config)
	first := ingressClient(t, address, "route.example", "")
	result := ingressWorker(t, func() { unblock(); _ = first.Close() }, first.Handshake)
	ingressAwait(t, backend.entered)
	second := ingressClient(t, address, "route.example", "")
	if err := second.Handshake(); err == nil {
		t.Fatal("capacity-denied visitor completed TLS")
	}
	unblock()
	if err := ingressAwait(t, result); err == nil {
		t.Fatal("failed publisher completed TLS")
	}
	outcomes := map[string]int{}
	for range 2 {
		outcomes[ingressAwait(t, metrics.visitorOutcomes)]++
	}
	if outcomes["capacity_denied"] != 1 || outcomes["open_failed"] != 1 {
		t.Fatalf("outcomes = %v", outcomes)
	}
}

func TestIngressRecordsPublisherSetupFailures(t *testing.T) {
	for _, tracking := range []bool{false, true} {
		t.Run(fmt.Sprintf("tracking_failure=%t", tracking), func(t *testing.T) {
			a, b := net.Pipe()
			ownIngressConn(t, a)
			ownIngressConn(t, b)
			if tracking {
				ingressWorker(t, func() { _ = b.Close() }, func() error { _, err := io.Copy(io.Discard, b); return err })
			} else {
				_ = b.Close()
			}
			release := make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })
			t.Cleanup(unblock)
			backend := &gatedOpenBackend{entered: make(chan struct{}), release: release, connection: a}
			metrics := &testMetrics{visitorOutcomes: make(chan string, 1)}
			config := publicURLConfig(backend)
			config.Metrics = metrics
			server, address := startIngress(t, config)
			client := ingressClient(t, address, "route.example", "")
			result := ingressWorker(t, func() { unblock(); _ = client.Close() }, client.Handshake)
			ingressAwait(t, backend.entered)
			if tracking {
				server.mu.Lock()
				server.closing = true
				server.mu.Unlock()
			}
			unblock()
			if err := ingressAwait(t, result); err == nil {
				t.Fatal("failed setup completed TLS")
			}
			outcome := ingressAwait(t, metrics.visitorOutcomes)
			metrics.forwardedMu.Lock()
			bytes := metrics.forwardedBytes["visitor_to_publisher"]
			metrics.forwardedMu.Unlock()
			if tracking {
				if outcome != "committed_failed" || bytes <= 0 {
					t.Fatalf("committed tracking failure = %s, bytes=%d", outcome, bytes)
				}
			} else if outcome != "open_failed" || bytes != 0 {
				t.Fatalf("zero-byte setup failure = %s, bytes=%d", outcome, bytes)
			}
		})
	}
}
