package ingress

import (
	"crypto/tls"
	"testing"

	ingressbackend "github.com/tnldotdev/tnl/internal/ingress/backend"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
)

func TestPublisherPoolReservesHealthyCapacityForEachNewConnection(t *testing.T) {
	server, _ := startIngress(t, Config{})
	limits := trafficlimits.Default()
	limits.Connections = 1
	runs := []PublicURL{
		{ID: "saved", PublishRunID: "publisher-a", Traffic: &limits, Backends: []ingressbackend.Backend{&singleBackend{}}},
		{ID: "saved", PublishRunID: "publisher-b", Traffic: &limits, Backends: []ingressbackend.Backend{&singleBackend{}}},
	}
	first, releaseFirst, reason := server.selectPoolRun(runs)
	if reason != LookupCurrent {
		t.Fatal(reason)
	}
	defer releaseFirst()
	second, releaseSecond, reason := server.selectPoolRun(runs)
	if reason != LookupCurrent || second.PublishRunID == first.PublishRunID {
		t.Fatal("new connection selected a full publisher")
	}
	defer releaseSecond()
	if _, release, reason := server.selectPoolRun(runs); reason != LookupNoBackends || release != nil {
		t.Fatal("full pool admitted another connection")
	}
	releaseFirst()
	releaseFirst()
	next, releaseNext, reason := server.selectPoolRun(runs)
	if reason != LookupCurrent || next.PublishRunID != first.PublishRunID {
		t.Fatal("closed connection did not release exact-run capacity")
	}
	defer releaseNext()
	if second.PublishRunID == next.PublishRunID {
		t.Fatal("established stream migrated during selection")
	}
}

func TestIngressPublisherPoolForwardsHealthySiblingsAndRejectsFullPool(t *testing.T) {
	first, second := newTLSBackend(t), newTLSBackend(t)
	limits := trafficlimits.Default()
	limits.Connections = 1
	runs := []PublicURL{
		{ID: "url_0123456789ABCDEFGHIJKL", PublishRunID: "pr_0123456789ABCDEFGHIJKL", PublishRunNumber: 1, Traffic: &limits, AllowAll: true, AttestSource: testBackendSourceProof, Backends: []ingressbackend.Backend{first}},
		{ID: "url_0123456789ABCDEFGHIJKL", PublishRunID: "pr_1123456789ABCDEFGHIJKL", PublishRunNumber: 2, Traffic: &limits, AllowAll: true, AttestSource: testBackendSourceProof, Backends: []ingressbackend.Backend{second}},
		// an unavailable sibling must not hide either healthy run.
		{ID: "url_0123456789ABCDEFGHIJKL", PublishRunID: "pr_2123456789ABCDEFGHIJKL", PublishRunNumber: 3},
	}
	usage := newUsageRecorder()
	metrics := &testMetrics{visitorOutcomes: make(chan string, 3)}
	events := make(chan serviceaudit.Observation, 5)
	server, address := startIngress(t, Config{
		Lookup:    func(string) ([]PublicURL, LookupReason) { return append([]PublicURL(nil), runs...), LookupCurrent },
		OpenUsage: usage.Open, Metrics: metrics,
		AuditSink: auditSinkFunc(func(o serviceaudit.Observation) bool { events <- o; return true }),
	})
	// keep both visitors open so each run's only slot stays reserved.
	a, b := ingressClient(t, address, "route.example", ""), ingressClient(t, address, "route.example", "")
	for _, visitor := range []*tls.Conn{a, b} {
		if err := visitor.Handshake(); err != nil {
			t.Fatal("healthy pool could not forward", err)
		}
	}
	if first.opens.Load() != 1 || second.opens.Load() != 1 {
		t.Fatal("new visitor did not select the sibling with spare capacity")
	}
	for range 2 {
		if event := ingressAwait(t, events); event.EventType != "connection.open" || event.Outcome != "forwarded" || event.RunID == "" {
			t.Fatal("selected run lost its audit identity", event)
		}
	}
	full := ingressClient(t, address, "route.example", "")
	if err := full.Handshake(); err == nil {
		t.Fatal("full pool admitted another visitor")
	}
	ingressAwait(t, metrics.visitorOutcomes)
	if event := ingressAwait(t, events); event.Validate() != nil || event.Outcome != "denied" || event.Reason != "unavailable" || event.RunID != "" || event.RunNumber != 0 {
		t.Fatal("full pool invented a selected run", event)
	}
	if len(usage.opened) != 2 || first.opens.Load() != 1 || second.opens.Load() != 1 {
		t.Fatal("full pool attributed usage or opened a backend without selecting a run")
	}
	for _, visitor := range []*tls.Conn{a, b} {
		exchangePing(t, visitor)
		ingressAwait(t, metrics.visitorOutcomes)
	}
	for _, backend := range []*tlsBackend{first, second} {
		if result := ingressAwait(t, backend.result); result.err != nil || result.request != "ping" {
			t.Fatal("established visitor moved or lost bytes", result)
		}
	}
	seen := map[uint64]bool{}
	for range 2 {
		u := ingressAwait(t, usage.opened)
		ingressAwait(t, u.closed)
		if u.streams != 1 || u.capacityDenials != 0 || u.publisherFailures != 0 || u.ingressBytes == 0 || u.egressBytes == 0 {
			t.Fatal("selected run lost usage", u)
		}
		seen[u.publishRunNumber] = true
	}
	if len(seen) != 2 || !seen[1] || !seen[2] {
		t.Fatal("usage did not follow the selected runs", seen)
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if len(server.poolRuns) != 0 || len(server.byPublicURL) != 0 || len(server.backends) != 0 {
		t.Fatal("closed visitors retained pool or admission capacity")
	}
}
