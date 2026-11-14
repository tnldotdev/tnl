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

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
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

func TestDeniedConnectionsHaveSeparateCapacity(t *testing.T) {
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	t.Cleanup(unblock)
	entered := make(chan struct{})
	metrics := &testMetrics{visitorOutcomes: make(chan string, 2)}
	var opens atomic.Int32
	config := serviceIngressConfig(t, func(ctx context.Context, _ tunnelv1.ServiceForwardingHeader) (net.Conn, error) {
		if opens.Add(1) != 1 {
			return nil, errors.New("pending capacity opened another service stream")
		}
		close(entered)
		select {
		case <-release:
			return nil, errors.New("relay unavailable")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	p := config.PublicServices
	config.Pending.Connections, config.Pending.PublicURLConnections, config.Pending.SourceConnections = 2, 1, 2
	config.Metrics, p.config.Metrics = metrics, metrics
	server, address := startIngress(t, config)
	first := ingressClient(t, address, "route.example", "192.0.2.4:40001")
	result := ingressWorker(t, func() { unblock(); _ = first.Close() }, first.Handshake)
	ingressAwait(t, entered)
	pending, active := publicServiceAdmissionCounts(p)
	if pending != 1 || active != 0 {
		t.Fatal("unauthenticated setup did not retain separate pending capacity", pending, active)
	}
	second := ingressClient(t, address, "route.example", "192.0.2.4:40002")
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
	server.active.Wait()
	p.mu.Lock()
	defer p.mu.Unlock()
	if opens.Load() != 1 || p.sessions != 0 || !publicServiceCapacityReleased(p) {
		t.Fatal("denied service setup opened another relay or retained capacity")
	}
}

func TestIngressRecordsRouteCapacityAndVisitorStreamOpenFailure(t *testing.T) {
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	t.Cleanup(unblock)
	entered := make(chan struct{})
	var opens atomic.Int32
	config := serviceIngressConfig(t, func(ctx context.Context, _ tunnelv1.ServiceForwardingHeader) (net.Conn, error) {
		if opens.Add(1) != 1 {
			return nil, errors.New("exhausted run opened another relay stream")
		}
		close(entered)
		select {
		case <-release:
			return nil, errors.New("publisher unavailable")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	control := config.PublicServices.config.Control.(*httpsServiceControl)
	control.anonymous = true
	total := int64(1)
	control.traffic.TotalConnections = &total
	metrics := &testMetrics{visitorOutcomes: make(chan string, 3)}
	config.Metrics = metrics
	config.PublicServices.config.Metrics = metrics
	config.MaxConnections = 2
	server, address := startIngress(t, config)
	first := ingressClient(t, address, "route.example", "192.0.2.4:40001")
	result := ingressWorker(t, func() { unblock(); _ = first.Close() }, first.Handshake)
	ingressAwait(t, entered)
	second := ingressClient(t, address, "route.example", "192.0.2.4:40002")
	if err := second.Handshake(); err == nil {
		t.Fatal("capacity-denied visitor completed TLS")
	}
	unblock()
	if err := ingressAwait(t, result); err == nil {
		t.Fatal("failed publisher completed TLS")
	}
	// ordinary concurrency is available again, but the failed anonymous open
	// retains its lifetime debit and cannot consume another relay opening.
	third := ingressClient(t, address, "route.example", "192.0.2.4:40003")
	if err := third.Handshake(); err == nil {
		t.Fatal("failed open released the lifetime connection debit")
	}
	outcomes := map[string]int{}
	for range 3 {
		outcomes[ingressAwait(t, metrics.visitorOutcomes)]++
	}
	if outcomes["capacity_denied"] != 2 || outcomes["open_failed"] != 1 || opens.Load() != 1 {
		t.Fatalf("outcomes = %v", outcomes)
	}
	server.active.Wait()
	if !publicServiceCapacityReleased(config.PublicServices) {
		t.Fatal("anonymous failed open retained concurrent capacity")
	}
}

type serviceSetupDrainConn struct {
	net.Conn
	writes    int
	committed chan struct{}
	resume    <-chan struct{}
}

func (c *serviceSetupDrainConn) Write(data []byte) (int, error) {
	n, err := c.Conn.Write(data)
	c.writes++
	if c.writes == 2 && n > 0 {
		close(c.committed)
		<-c.resume
	}
	return n, err
}

func TestIngressRecordsPublisherSetupFailures(t *testing.T) {
	for _, visitorBytes := range []int{0, 1} {
		t.Run(fmt.Sprintf("visitor_bytes=%d", visitorBytes), func(t *testing.T) {
			a, b := net.Pipe()
			ownIngressConn(t, a)
			ownIngressConn(t, b)
			if visitorBytes != 0 {
				ingressWorker(t, func() { _ = b.Close() }, func() error { _, err := io.Copy(io.Discard, b); return err })
			} else {
				_ = b.Close()
			}
			release := make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })
			t.Cleanup(unblock)
			entered := make(chan struct{})
			committed, resume := make(chan struct{}), make(chan struct{})
			resumeWrite := sync.OnceFunc(func() { close(resume) })
			t.Cleanup(resumeWrite)
			var opens atomic.Int32
			metrics := &testMetrics{visitorOutcomes: make(chan string, 1)}
			config := serviceIngressConfig(t, func(ctx context.Context, _ tunnelv1.ServiceForwardingHeader) (net.Conn, error) {
				if opens.Add(1) != 1 {
					return nil, errors.New("failed setup opened another service stream")
				}
				close(entered)
				select {
				case <-release:
					if visitorBytes != 0 {
						return &serviceSetupDrainConn{Conn: a, committed: committed, resume: resume}, nil
					}
					return a, nil
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			})
			p := config.PublicServices
			config.Metrics, p.config.Metrics = metrics, metrics
			server, address := startIngress(t, config)
			client := ingressClient(t, address, "route.example", "192.0.2.4:42000")
			result := ingressWorker(t, func() { unblock(); _ = client.Close() }, client.Handshake)
			ingressAwait(t, entered)
			unblock()
			if visitorBytes != 0 {
				// the service owner stops while a completed prefix write is still
				// returning. shutdown must retain commitment and close its backend.
				ingressAwait(t, committed)
				p.StopAccepting()
				server.cancelOpens()
				resumeWrite()
			}
			if err := ingressAwait(t, result); err == nil {
				t.Fatal("failed setup completed TLS")
			}
			outcome := ingressAwait(t, metrics.visitorOutcomes)
			metrics.forwardedMu.Lock()
			bytes := metrics.forwardedBytes["visitor_to_publisher"]
			metrics.forwardedMu.Unlock()
			if visitorBytes != 0 {
				if outcome != "committed_failed" || bytes <= 0 {
					t.Fatalf("committed setup failure = %s, bytes=%d", outcome, bytes)
				}
			} else if outcome != "open_failed" || bytes != 0 {
				t.Fatalf("zero-byte setup failure = %s, bytes=%d", outcome, bytes)
			}
			server.active.Wait()
			p.mu.Lock()
			defer p.mu.Unlock()
			if opens.Load() != 1 || p.sessions != 0 || p.streams != 0 || len(p.connections) != 0 ||
				metrics.visitorOpenSuccesses.Load() != 0 || metrics.visitorOpenFailures.Load() != 1 || len(metrics.visitorOutcomes) != 0 {
				t.Fatal("failed service setup retained ownership or duplicated an observation")
			}
		})
	}
}
