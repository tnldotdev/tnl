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

	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestIngressRoutesTLSWithProxyMetadata(t *testing.T) {
	authorized := make(chan struct{})
	backend := newServiceTLSRelay(t, authorized)
	metrics := &testMetrics{visitorOutcomes: make(chan string, 1)}
	events := make(chan serviceaudit.Observation, 2)
	config := serviceIngressConfig(t, backend.open)
	control := config.Control.(*httpsServiceControl)
	config.Metrics = metrics
	unblock := sync.OnceFunc(func() { close(authorized) })
	config.AuditSink = auditSinkFunc(func(event serviceaudit.Observation) bool {
		events <- event
		if event.EventType == "connection.open" && event.Outcome == "allowed" {
			unblock()
		}
		return true
	})
	server, address := startIngress(t, config)
	client := ingressClient(t, address, "route.example", "192.0.2.4:42000")
	exchangePing(t, client)
	result := ingressAwait(t, backend.result)
	claim := ingressAwait(t, control.claims)
	if result.err != nil || result.request != "ping" || result.header.Source != netip.MustParseAddrPort("192.0.2.4:42000") ||
		result.header.Destination != netip.MustParseAddrPort("203.0.113.10:443") || result.visitorConnectionID != claim.VisitorConnectionId ||
		claim.Hostname == nil || *claim.Hostname != "route.example" || claim.ObservedSourceIp != "192.0.2.4" || claim.DestinationPort != 443 {
		t.Fatalf("backend = %+v", result)
	}
	ingressAwait(t, metrics.visitorOutcomes)
	if metrics.visitorOpenSuccesses.Load() != 1 || metrics.visitorOpenFailures.Load() != 0 {
		t.Fatal("visitor stream did not open successfully")
	}
	server.active.Wait()
	opened, closed := ingressAwait(t, events), ingressAwait(t, events)
	if opened.Validate() != nil || closed.Validate() != nil || opened.EventType != "connection.open" || opened.Outcome != "allowed" ||
		opened.ServiceKind != "service" || opened.ServiceID != control.service || opened.RunID != control.run || opened.RunNumber != 1 ||
		opened.VisitorConnectionID != result.visitorConnectionID || opened.SourceIP != "192.0.2.4" ||
		closed.EventType != "connection.close" || closed.ServiceID != opened.ServiceID || closed.RunID != opened.RunID ||
		closed.VisitorConnectionID != opened.VisitorConnectionID || closed.EventID == opened.EventID || closed.SourceIP != opened.SourceIP {
		t.Fatalf("service audit = %+v, %+v", opened, closed)
	}
	metrics.forwardedMu.Lock()
	defer metrics.forwardedMu.Unlock()
	if len(metrics.forwardedBytes) != 2 || metrics.forwardedBytes["visitor_to_publisher"] <= 0 || metrics.forwardedBytes["publisher_to_visitor"] <= 0 {
		t.Fatalf("forwarded bytes=%v", metrics.forwardedBytes)
	}
}

func TestIngressEnforcesProxySourceBeforeServiceRelayOpen(t *testing.T) {
	backend := newServiceTLSRelay(t)
	metrics := &testMetrics{visitorOutcomes: make(chan string, 2)}
	config := serviceIngressConfig(t, backend.open)
	control := config.Control.(*httpsServiceControl)
	control.sources = netip.MustParsePrefix("198.51.100.0/24")
	config.Metrics = metrics
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
	denied := ingressClient(t, address, "route.example", "203.0.113.3:40004")
	if err := denied.Handshake(); err == nil {
		t.Fatal("denied source completed TLS")
	}
	_ = denied.Close()
	for range 2 {
		ingressAwait(t, metrics.visitorOutcomes)
	}
	server.active.Wait()
	allowedClaim, deniedClaim := ingressAwait(t, control.claims), ingressAwait(t, control.claims)
	if allowedClaim.ObservedSourceIp != "198.51.100.2" || deniedClaim.ObservedSourceIp != "203.0.113.3" || len(control.claims) != 0 ||
		metrics.visitorOpenSuccesses.Load() != 1 || metrics.visitorOpenFailures.Load() != 0 || backend.opens.Load() != 1 {
		t.Fatalf("claims=%+v, %+v, relay opens=%d", allowedClaim, deniedClaim, backend.opens.Load())
	}
	if !publicServiceCapacityReleased(server) {
		t.Fatal("service capacity retained after source rejection")
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
	config.Pending.Connections, config.Pending.PublicURLConnections, config.Pending.SourceConnections = 2, 1, 2
	config.Metrics = metrics
	server, address := startIngress(t, config)
	p := server
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
	if opens.Load() != 1 || p.admitted[serviceConnection] != 0 || !publicServiceCapacityReleased(p) {
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
	control := config.Control.(*httpsServiceControl)
	control.anonymous = true
	total := int64(1)
	control.traffic.TotalConnections = &total
	metrics := &testMetrics{visitorOutcomes: make(chan string, 3)}
	config.Metrics = metrics
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
	if !publicServiceCapacityReleased(server) {
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
			config.Metrics = metrics
			server, address := startIngress(t, config)
			p := server
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
			if opens.Load() != 1 || p.admitted[serviceConnection] != 0 || len(p.backends) != 0 || len(p.connections) != 0 ||
				metrics.visitorOpenSuccesses.Load() != 0 || metrics.visitorOpenFailures.Load() != 1 || len(metrics.visitorOutcomes) != 0 {
				t.Fatal("failed service setup retained ownership or duplicated an observation")
			}
		})
	}
}
