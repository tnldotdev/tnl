package ingress

import (
	"crypto/tls"
	"net/netip"
	"testing"

	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
)

func TestPublisherPoolReservesHealthyCapacityForEachNewConnection(t *testing.T) {
	config, control, _ := serviceSelectionConfig(t, 2, true)
	server := serviceSelectionServer(t, config)
	limits := trafficlimits.Default()
	limits.Connections = 1
	keys := make([]trafficKey, 2)
	for i, run := range control.runs {
		keys[i] = trafficKey{service: run.ServiceId, id: run.ServiceRunId, run: uint64(run.RunNumber)}
	}
	newVisitor := func() *visitorAdmission {
		t.Helper()
		v, reason := server.admitPendingService()
		if v == nil {
			t.Fatal(reason)
		}
		t.Cleanup(v.close)
		return v
	}
	source := netip.MustParseAddr("192.0.2.4")
	first := newVisitor()
	if reason := first.selectRun(keys[0], limits, source, true); reason != "" {
		t.Fatal(reason)
	}
	second := newVisitor()
	if reason := second.selectRun(keys[0], limits, source, true); reason != "service_connections" {
		t.Fatal("new connection selected a full publisher", reason)
	}
	if reason := second.selectRun(keys[1], limits, source, true); reason != "" {
		t.Fatal("failed selection retained the full publisher", reason)
	}
	next := newVisitor()
	for _, key := range keys {
		if reason := next.selectRun(key, limits, source, true); reason != "service_connections" {
			t.Fatal("full pool admitted another connection", reason)
		}
	}
	first.close()
	first.close()
	if reason := next.selectRun(keys[0], limits, source, true); reason != "" || next.key != first.key {
		t.Fatal("closed connection did not release exact-run capacity", reason)
	}
	if second.key != keys[1] || second.key == next.key {
		t.Fatal("established stream migrated during selection")
	}
}

func TestIngressPublisherPoolForwardsHealthySiblingsAndRejectsFullPool(t *testing.T) {
	first, second := newServiceTLSRelay(t), newServiceTLSRelay(t)
	config, control, forwarder := serviceSelectionConfig(t, 3, true)
	runs := append([]ingressv1.PublicServiceVisitorAdmission(nil), control.runs[:2]...)
	for i := range runs {
		runs[i].Traffic.Connections = 1
	}
	// an unavailable sibling must not hide either healthy run.
	unavailable := control.runs[2]
	unavailable.ConnectedRelays = nil
	control.runs = append([]ingressv1.PublicServiceVisitorAdmission{unavailable}, runs...)
	forwarder.openings[runs[0].ServiceRunId], forwarder.openings[runs[1].ServiceRunId] = first.open, second.open
	metrics := &testMetrics{visitorOutcomes: make(chan string, 3)}
	events := make(chan serviceaudit.Observation, 5)
	config.Metrics, config.AuditSink = metrics, auditSinkFunc(func(o serviceaudit.Observation) bool { events <- o; return true })
	server, address := startIngress(t, config)
	// keep both visitors open so each run's only slot stays reserved.
	a, b := ingressClient(t, address, "route.example", "192.0.2.4:40001"), ingressClient(t, address, "route.example", "192.0.2.4:40002")
	for _, visitor := range []*tls.Conn{a, b} {
		if err := visitor.Handshake(); err != nil {
			t.Fatal("healthy pool could not forward", err)
		}
	}
	if first.opens.Load() != 1 || second.opens.Load() != 1 {
		t.Fatal("new visitor did not select the sibling with spare capacity")
	}
	opened := make(map[string]serviceaudit.Observation)
	for range 2 {
		event := ingressAwait(t, events)
		if event.Validate() != nil || event.EventType != "connection.open" || event.Outcome != "allowed" || event.ServiceID != control.service || event.RunID == "" {
			t.Fatal("selected run lost its audit identity", event)
		}
		opened[event.RunID] = event
	}
	full := ingressClient(t, address, "route.example", "192.0.2.4:40003")
	if err := full.Handshake(); err == nil {
		t.Fatal("full pool admitted another visitor")
	}
	ingressAwait(t, metrics.visitorOutcomes)
	if event := ingressAwait(t, events); event.Validate() != nil || event.Outcome != "denied" || event.Reason != "unavailable" || event.RunID != "" || event.RunNumber != 0 {
		t.Fatal("full pool invented a selected run", event)
	}
	if first.opens.Load() != 1 || second.opens.Load() != 1 {
		t.Fatal("full pool opened a backend without selecting a run")
	}
	for _, visitor := range []*tls.Conn{a, b} {
		exchangePing(t, visitor)
		ingressAwait(t, metrics.visitorOutcomes)
	}
	for i, backend := range []*serviceTLSRelay{first, second} {
		if result := ingressAwait(t, backend.result); result.err != nil || result.request != "ping" || result.visitorConnectionID != opened[runs[i].ServiceRunId].VisitorConnectionID {
			t.Fatal("established visitor moved or lost bytes", result)
		}
	}
	seen := map[uint64]bool{}
	for range 2 {
		event := ingressAwait(t, events)
		// the fixture closes TLS peers after the exchange; copying may observe
		// that close as a forwarding error after the stream opened successfully.
		if event.Validate() != nil || event.EventType != "connection.close" ||
			(event.Outcome != "closed" && (event.Outcome != "failed" || event.Reason != "forwarding")) {
			t.Fatal("selected run lost its close observation", event)
		}
		seen[uint64(event.RunNumber)] = true
	}
	if len(seen) != 2 || !seen[1] || !seen[2] {
		t.Fatal("audit did not follow the selected runs", seen)
	}
	if metrics.visitorOpenSuccesses.Load() != 2 || metrics.visitorOpenFailures.Load() != 0 {
		t.Fatal("selected runs did not open successfully")
	}
	server.active.Wait()
	if !publicServiceCapacityReleased(server) || server.Load() != 0 || len(server.backends) != 0 || len(control.live) != 0 {
		t.Fatal("closed visitors retained pool or admission capacity")
	}
	if len(forwarder.observed) != 2 {
		t.Fatal("sibling search opened a rejected run")
	}
	for _, header := range forwarder.observed {
		event := opened[header.ServiceRunID]
		if event.RunNumber != int64(header.RunNumber) || event.VisitorConnectionID != header.VisitorConnectionID || header.ServiceID != event.ServiceID {
			t.Fatal("forwarding changed the selected sibling's identity or run number", header, event)
		}
	}
}
