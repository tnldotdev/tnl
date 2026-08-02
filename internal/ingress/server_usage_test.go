package ingress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/routebackend"
	"github.com/tnldotdev/tnl/internal/sourcelimiter"
)

func TestIngressRoutesTLSWithProxyMetadata(t *testing.T) {
	backend := newTLSBackend(t)
	usage, metrics := newUsageRecorder(), new(testMetrics)
	type recovery struct {
		id               string
		version, episode uint64
		at               time.Time
	}
	recovered := make(chan recovery, 1)
	config := routeConfig(backend)
	config.OpenUsage, config.Metrics = usage.Open, metrics
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
	u := ingressAwait(t, usage.opened)
	ingressAwait(t, u.closed)
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.routeID != "route_test" || u.routeVersion != 1 || !u.source.IsLoopback() || u.openedAt.IsZero() || u.closedAt.IsZero() || u.publisherOpeningAt.IsZero() || u.publisherOpenedAt.IsZero() || u.streams != 1 || u.ingressBytes <= 0 || u.egressBytes <= 0 {
		t.Fatalf("usage = %+v", u)
	}
	metrics.forwardedMu.Lock()
	defer metrics.forwardedMu.Unlock()
	if len(metrics.forwardedBytes) != 2 || metrics.forwardedBytes["visitor_to_publisher"] != u.ingressBytes || metrics.forwardedBytes["publisher_to_visitor"] != u.egressBytes {
		t.Fatalf("metrics=%v usage=%d/%d", metrics.forwardedBytes, u.ingressBytes, u.egressBytes)
	}
	r := ingressAwait(t, recovered)
	if r.id != "route_test" || r.version != 1 || r.episode != 7 || r.at.IsZero() {
		t.Fatalf("recovery=%+v", r)
	}
}

func TestIngressUsesProvisioningRouteOnlyForACMETLSALPN(t *testing.T) {
	backend := newTLSBackend(t, "acme-tls/1")
	var opened atomic.Bool
	config := Config{
		Lookup: func(string) (Route, bool) {
			return Route{AllowedIPPrefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}, true
		},
		LookupChallenge: func(host string) ([]routebackend.Backend, bool) {
			return []routebackend.Backend{backend}, host == "route.example"
		},
		OpenUsage: func(string, uint64, netip.Addr, time.Time) UsageConnection { opened.Store(true); return nil },
	}
	_, address := startIngress(t, config)
	client := ingressClient(t, address, "route.example", "", "acme-tls/1")
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if client.ConnectionState().NegotiatedProtocol != "acme-tls/1" {
		t.Fatal("ACME ALPN not negotiated")
	}
	exchangePing(t, client)
	if result := ingressAwait(t, backend.result); result.err != nil {
		t.Fatal(result.err)
	}
	if opened.Load() {
		t.Fatal("challenge opened usage accounting")
	}
	ordinary := ingressClient(t, address, "route.example", "")
	if err := ordinary.Handshake(); err == nil {
		t.Fatal("ordinary visitor used provisioning route")
	}
	if backend.opens.Load() != 1 {
		t.Fatal("ordinary visitor opened challenge backend")
	}
}

func TestIngressEnforcesProxySourceLimitsAndRouteAllowlistInOrder(t *testing.T) {
	backend, usage := newTLSBackend(t), newUsageRecorder()
	metrics := &testMetrics{entriesChanged: make(chan int, 8)}
	var lookups atomic.Int32
	config := Config{RequireProxyHeader: true, Metrics: metrics, OpenUsage: usage.Open, Lookup: func(host string) (Route, bool) {
		lookups.Add(1)
		return Route{ID: "route_test", RouteVersion: 1, Backends: []routebackend.Backend{backend}, AllowedIPPrefixes: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}}, host == "route.example"
	}}
	server, address := startIngress(t, config, func(server *Server) {
		var err error
		server.limiter, err = sourcelimiter.New(sourcelimiter.Config{Rate: 0.000001, Burst: 1, MaxEntries: 8, IdleExpiration: time.Hour, Shards: 4, OnEntriesChanged: metrics.SetSourceLimiterEntries})
		if err != nil {
			t.Fatal(err)
		}
	})
	malformed := ingressClient(t, address, "route.example", "198.51.100.1:40001")
	// Write malformed bytes on the underlying connection, before TLS.
	_, _ = malformed.NetConn().Write([]byte("not TLS"))
	_ = malformed.Close()
	for ingressAwait(t, metrics.entriesChanged) != 1 {
	}
	if lookups.Load() != 0 {
		t.Fatal("malformed connection looked up route")
	}
	allowed := ingressClient(t, address, "route.example", "198.51.100.2:40002")
	exchangePing(t, allowed)
	result := ingressAwait(t, backend.result)
	if result.err != nil || result.header.Source != netip.MustParseAddrPort("198.51.100.2:40002") {
		t.Fatalf("allowed = %+v", result)
	}
	for _, source := range []string{"198.51.100.2:40003", "203.0.113.3:40004"} {
		client := ingressClient(t, address, "route.example", source)
		if err := client.Handshake(); err == nil {
			t.Fatalf("denied source %s completed TLS", source)
		}
	}
	var policies, streams int
	for range 2 {
		u := ingressAwait(t, usage.opened)
		ingressAwait(t, u.closed)
		policies += u.policyDenials
		streams += u.streams
	}
	if policies != 1 || streams != 1 || metrics.sourceLimiterRejections.Load() != 1 || metrics.ipAllowlistDenials.Load() != 1 || lookups.Load() != 2 || backend.opens.Load() != 1 {
		t.Fatalf("policy=%d streams=%d limiter=%d allowlist=%d lookups=%d opens=%d", policies, streams, metrics.sourceLimiterRejections.Load(), metrics.ipAllowlistDenials.Load(), lookups.Load(), backend.opens.Load())
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if len(server.byRoute) != 0 {
		t.Fatalf("route capacity retained: %v", server.byRoute)
	}
}

type gatedOpenBackend struct {
	entered    chan struct{}
	release    <-chan struct{}
	connection net.Conn
	err        error
}

func (b *gatedOpenBackend) Open(ctx context.Context, _ string) (net.Conn, error) {
	close(b.entered)
	select {
	case <-b.release:
		return b.connection, b.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestIngressRecordsRouteCapacityAndPublisherOpenFailure(t *testing.T) {
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	t.Cleanup(unblock)
	backend := &gatedOpenBackend{entered: make(chan struct{}), release: release, err: errors.New("publisher unavailable")}
	usage := newUsageRecorder()
	config := routeConfig(backend)
	config.OpenUsage = usage.Open
	config.MaxRouteConnections = 1
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
	var capacity, failures, streams int
	for range 2 {
		u := ingressAwait(t, usage.opened)
		ingressAwait(t, u.closed)
		capacity += u.capacityDenials
		failures += u.publisherFailures
		streams += u.streams
	}
	if capacity != 1 || failures != 1 || streams != 0 {
		t.Fatalf("capacity=%d failure=%d streams=%d", capacity, failures, streams)
	}
}

func TestIngressRecordsPublisherSetupFailures(t *testing.T) {
	for _, tracking := range []bool{false, true} {
		t.Run(fmt.Sprintf("tracking_failure=%t", tracking), func(t *testing.T) {
			a, b := net.Pipe()
			ownIngressConn(t, a)
			ownIngressConn(t, b)
			_ = b.Close()
			release := make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })
			t.Cleanup(unblock)
			backend := &gatedOpenBackend{entered: make(chan struct{}), release: release, connection: a}
			usage := newUsageRecorder()
			config := routeConfig(backend)
			config.OpenUsage = usage.Open
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
			u := ingressAwait(t, usage.opened)
			ingressAwait(t, u.closed)
			if u.publisherOpeningAt.IsZero() || u.publisherOpenedAt.IsZero() || u.publisherFailures != 1 || u.streams+u.policyDenials+u.capacityDenials != 0 {
				t.Fatalf("usage=%+v", u)
			}
		})
	}
}
