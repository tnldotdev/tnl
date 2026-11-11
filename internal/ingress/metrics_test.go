package ingress

import (
	"context"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
)

type pendingTLSBackend struct{ connection net.Conn }

func (pendingTLSBackend) ConnectionSlot() uint8 { return 0 }

func (b pendingTLSBackend) Start(ctx context.Context, _ string, _ bool, proxy, initial []byte) (net.Conn, error) {
	return startTestBackend(ctx, b.connection, proxy, initial)
}

type relayAttemptMetrics struct {
	testMetrics
	slots []string
}

func (m *relayAttemptMetrics) ObserveRelayAttempt(slot string, _ observability.RelayAttemptOutcome) {
	m.slots = append(m.slots, slot)
}

func TestRelayAttemptReportsAssignedConnectionSlot(t *testing.T) {
	forwarder := newTestForwarder(t, newForwardingTestMaterial(t))
	metrics := &relayAttemptMetrics{}
	server := &Server{config: Config{Metrics: metrics}}
	for _, slot := range []int{0, 1} {
		entry := forwardingTestEntry(time.Now(), "relay.example:443")
		entry.PublisherConnections[0].ConnectionSlot = slot
		backend := mustOnlyBackend(t, forwarder, entry)
		if backend.ConnectionSlot() != uint8(slot) {
			t.Fatalf("backend slot=%d, want %d", backend.ConnectionSlot(), slot)
		}
		server.observeRelayAttempt(backend, observability.RelayAttemptCommitted)
	}
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
	_, address := startIngress(t, Config{
		Metrics: metrics,
		Lookup:  func(string) ([]PublicURL, LookupReason) { return nil, LookupNotFound },
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
			if err := server.releaseBackend(t.Context(), left); err != nil {
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
