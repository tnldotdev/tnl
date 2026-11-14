package ingress

import (
	"context"
	"errors"
	"net"
	"slices"
	"sync"
	"testing"

	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type pendingTLSBackend struct{ connection net.Conn }

func (pendingTLSBackend) ConnectionSlot() uint8 { return 0 }

func (b pendingTLSBackend) Start(ctx context.Context, _ string, _ bool, proxy, initial []byte) (net.Conn, error) {
	return startTestBackend(ctx, b.connection, proxy, initial)
}

type relayAttemptMetrics struct {
	testMetrics
	mu    sync.Mutex
	slots []string
}

func (m *relayAttemptMetrics) ObserveRelayAttempt(slot string, _ observability.RelayAttemptOutcome) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.slots = append(m.slots, slot)
}

func TestRelayAttemptReportsAssignedConnectionSlot(t *testing.T) {
	first, second := newServiceTLSRelay(t), newServiceTLSRelay(t)
	metrics := &relayAttemptMetrics{testMetrics: testMetrics{visitorOutcomes: make(chan string, 2)}}
	config := serviceIngressConfig(t, first.open, second.open)
	config.Metrics, config.PublicServices.config.Metrics = metrics, metrics
	_, address := startIngress(t, config)
	for range 2 {
		visitor := ingressClient(t, address, "route.example", "192.0.2.4:42000")
		exchangePing(t, visitor)
		// this payload fixture fully closes its pipes; the separate real TCP
		// completion proof distinguishes clean shutdown from a half-close failure.
		ingressAwait(t, metrics.visitorOutcomes)
	}
	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	if !slices.Equal(metrics.slots, []string{"0", "1"}) {
		t.Fatalf("reported slots=%v, want [0 1]", metrics.slots)
	}
}

func TestRestrictedVisitorForwardingHasSuccessfulOutcome(t *testing.T) {
	result := restrictedCompletionFixture(t, false)
	if result.outcome != "forwarded" || result.err != nil || result.halfClose != nil {
		t.Fatal("clean restricted visitor completion was not successful", result)
	}
}

func TestVisitorLookupFailureIsCountedOnce(t *testing.T) {
	metrics := &testMetrics{visitorOutcomes: make(chan string, 2)}
	var opened bool
	config := serviceIngressConfig(t, func(context.Context, tunnelv1.ServiceForwardingHeader) (net.Conn, error) {
		opened = true
		return nil, errors.New("missing service reached relay forwarding")
	})
	config.Metrics, config.PublicServices.config.Metrics = metrics, metrics
	server, address := startIngress(t, config)
	visitor := ingressClient(t, address, "missing.example", "192.0.2.4:42000")
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
	server.active.Wait()
	if opened {
		t.Fatal("missing service opened a relay stream")
	}
}

func TestConcurrentBackendGaugeReturnsToZero(t *testing.T) {
	metrics := observability.New("ingress")
	p, _, _, _ := publicServiceTestSetup(t)
	p.config.Metrics = metrics
	var group sync.WaitGroup
	for range 64 {
		group.Add(1)
		go func() {
			defer group.Done()
			left, right := net.Pipe()
			defer right.Close()
			backend := p.observeBackend(t.Context(), left)
			if err := backend.Close(); err != nil {
				t.Error(err)
			}
			if err := backend.Close(); err != nil {
				t.Error(err)
			}
		}()
	}
	group.Wait()
	if p.streams != 0 {
		t.Fatal("closed service backends retained ownership", p.streams)
	}
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
