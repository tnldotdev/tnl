package ingress

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
)

func TestDirectServicePendingSourceAndServiceCapacity(t *testing.T) {
	p, _, _, _ := directTestSetup(t)
	p.config.MaxPending, p.config.MaxServiceStreams, p.config.MaxSourceStreams = 3, 2, 1
	first, ok := p.pendingStream("a", netip.MustParseAddr("192.0.2.1"))
	if !ok {
		t.Fatal("first pending visitor rejected")
	}
	if a, ok := p.pendingStream("b", netip.MustParseAddr("192.0.2.1")); ok {
		a.close()
		t.Fatal("source bound ignored across services")
	}
	second, ok := p.pendingStream("a", netip.MustParseAddr("192.0.2.2"))
	if !ok {
		t.Fatal("second source rejected")
	}
	if a, ok := p.pendingStream("a", netip.MustParseAddr("192.0.2.3")); ok {
		a.close()
		t.Fatal("service bound ignored across sources")
	}
	third, ok := p.pendingStream("b", netip.MustParseAddr("192.0.2.3"))
	if !ok {
		t.Fatal("independent service rejected")
	}
	if a, ok := p.pendingStream("c", netip.MustParseAddr("192.0.2.4")); ok {
		a.close()
		t.Fatal("pending bound ignored")
	}
	if first.selectService("b") != true || first.selectService("missing") != true {
		t.Fatal("pending service selection failed")
	}
	if !first.promote() || first.promote() || first.selectService("c") {
		t.Fatal("promotion was not exactly once and service-bound")
	}
	if p.pending != 2 || p.active != 1 {
		t.Fatal("promotion did not release pending capacity")
	}
	fourth, ok := p.pendingStream("c", netip.MustParseAddr("192.0.2.4"))
	if !ok {
		t.Fatal("promoted visitor retained pending capacity")
	}
	for _, a := range []*privateStreamAdmission{first, second, third, fourth} {
		a.close()
		a.close()
	}
	if p.pending != 0 || p.active != 0 || len(p.services) != 0 || len(p.sources) != 0 {
		t.Fatal("joined visitors retained capacity")
	}
	p.StopAccepting()
	if a, ok := p.pendingStream("a", netip.MustParseAddr("192.0.2.1")); ok {
		a.close()
		t.Fatal("stopped owner admitted work")
	}
}

func TestDirectPromotionWaitsForControlAcknowledgment(t *testing.T) {
	p, c, f, _ := directTestSetup(t)
	c.authenticated, c.promoteErr, c.promoteStarted = true, errors.New("promotion unavailable"), make(chan struct{}, 1)
	events := make(chan serviceaudit.Observation, 2)
	p.config.AuditSink = auditSinkFunc(func(o serviceaudit.Observation) bool { events <- o; return true })
	_, stop := directActiveStream(t, p, f)
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
