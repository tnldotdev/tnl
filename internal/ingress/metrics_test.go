package ingress

import (
	"net"
	"sync"
	"testing"

	"github.com/tnldotdev/tnl/internal/observability"
)

func TestVisitorLookupFailureIsCountedOnce(t *testing.T) {
	metrics := &testMetrics{visitorOutcomes: make(chan string, 2)}
	_, address := startIngress(t, Config{
		Metrics: metrics,
		Lookup:  func(string) (PublicURL, string) { return PublicURL{}, "not_found" },
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
