package ingress

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
)

func TestPublicServicePendingSourceAndServiceCapacity(t *testing.T) {
	p, _, _, _ := publicServiceTestSetup(t)
	s := p.server
	s.config.Pending.Connections = 3
	s.traffic.pending.PublicURLConnections, s.traffic.pending.SourceConnections = 2, 1
	limits := s.config.Traffic.Default
	pending := func(service, source string) (*visitorAdmission, string) {
		v, reason := s.admitPendingService()
		if v != nil {
			reason = v.selectRun(trafficKey{service: service, id: "run", run: 1}, limits, netip.MustParseAddr(source), false)
			if reason != "" {
				v.close()
				v = nil
			}
		}
		return v, reason
	}
	first, reason := pending("a", "192.0.2.1")
	if first == nil {
		t.Fatal("first pending visitor rejected", reason)
	}
	if a, _ := pending("b", "192.0.2.1"); a != nil {
		a.close()
		t.Fatal("source bound ignored across services")
	}
	second, reason := pending("a", "192.0.2.2")
	if second == nil {
		t.Fatal("second source rejected", reason)
	}
	if a, _ := pending("a", "192.0.2.3"); a != nil {
		a.close()
		t.Fatal("service bound ignored across sources")
	}
	third, reason := pending("b", "192.0.2.3")
	if third == nil {
		t.Fatal("independent service rejected", reason)
	}
	if a, _ := pending("c", "192.0.2.4"); a != nil {
		a.close()
		t.Fatal("pending bound ignored")
	}
	if first.selectRun(trafficKey{service: "b", id: "run", run: 1}, limits, first.source, false) == "" {
		t.Fatal("selected run was replaceable")
	}
	if first.reserve(limits) != "" || first.reserve(limits) == "" || first.selectRun(trafficKey{service: "c", id: "run", run: 1}, limits, first.source, false) == "" {
		t.Fatal("promotion was not exactly once and service-bound")
	}
	if pending, active := publicServiceAdmissionCounts(p); pending != 2 || active != 1 {
		t.Fatal("promotion did not release pending capacity")
	}
	fourth, reason := pending("c", "192.0.2.4")
	if fourth == nil {
		t.Fatal("promoted visitor retained pending capacity", reason)
	}
	for _, a := range []*visitorAdmission{first, second, third, fourth} {
		a.close()
		a.close()
	}
	if !publicServiceCapacityReleased(p) {
		t.Fatal("joined visitors retained capacity")
	}
	p.StopAccepting()
	connection, peer := net.Pipe()
	defer connection.Close()
	defer peer.Close()
	if _, release, ok := p.acquireSession(t.Context(), connection); ok {
		release()
		t.Fatal("stopped owner admitted work")
	}
}

func publicServiceAdmissionCounts(p *PublicServices) (pending, active int) {
	p.server.mu.Lock()
	defer p.server.mu.Unlock()
	return p.server.admitted[pendingConnection], p.server.admitted[visitorConnection]
}

func publicServiceCapacityReleased(p *PublicServices) bool {
	pending, active := publicServiceAdmissionCounts(p)
	if pending != 0 || active != 0 {
		return false
	}
	p.server.traffic.mu.Lock()
	defer p.server.traffic.mu.Unlock()
	for _, run := range p.server.traffic.runs {
		if run.active != 0 {
			return false
		}
	}
	for _, run := range p.server.traffic.pendingRuns {
		if run.active != 0 {
			return false
		}
	}
	for _, source := range p.server.traffic.sources {
		if source.active != 0 || source.connections != 0 {
			return false
		}
	}
	return true
}

func TestPublicServicePromotionWaitsForControlAcknowledgment(t *testing.T) {
	p, c, f, _ := publicServiceTestSetup(t)
	c.authenticated, c.promoteErr, c.promoteStarted = true, errors.New("promotion unavailable"), make(chan struct{}, 1)
	events := make(chan serviceaudit.Observation, 2)
	p.config.AuditSink = auditSinkFunc(func(o serviceaudit.Observation) bool { events <- o; return true })
	_, stop := publicServiceActiveStream(t, p, f)
	select {
	case <-c.promoteStarted:
	case <-time.After(time.Second):
		t.Fatal("promotion did not reach control")
	}
	select {
	case <-events:
		t.Fatal("unacknowledged promotion emitted allowed admission")
	default:
	}
	c.mu.Lock()
	c.promoteErr = nil
	c.mu.Unlock()
	select {
	case event := <-events:
		if event.Validate() != nil || event.EventType != "connection.open" || event.Outcome != "allowed" {
			t.Fatalf("promotion event = %+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("acknowledged promotion never became allowed")
	}
	stop()
}
