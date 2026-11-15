package ingress

import (
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
)

func TestPublicServiceVisitorAuditCorrelatesAdmissionAndRevocationClose(t *testing.T) {
	connector, control, forwarder, _ := publicServiceTestSetup(t)
	events := make(chan serviceaudit.Observation, 2)
	connector.config.AuditSink = auditSinkFunc(func(o serviceaudit.Observation) bool { events <- o; return true })
	connector.config.RecheckInterval = 20 * time.Millisecond
	stream, stop := publicServiceActiveStream(t, connector, forwarder)
	defer stop()
	var opened serviceaudit.Observation
	select {
	case opened = <-events:
	case <-time.After(time.Second):
		t.Fatal("private admission did not emit")
	}
	if opened.Validate() != nil || opened.EventType != "connection.open" || opened.Outcome != "allowed" || opened.RunID != control.run || opened.PairID != "" {
		t.Fatalf("private admission scope: %+v", opened)
	}
	control.mu.Lock()
	control.deny = true
	control.mu.Unlock()
	_ = stream.SetReadDeadline(time.Now().Add(time.Second))
	var one [1]byte
	_, _ = stream.Read(one[:])
	select {
	case closed := <-events:
		if closed.Validate() != nil || closed.EventType != "connection.close" || closed.VisitorConnectionID != opened.VisitorConnectionID || closed.EventID == opened.EventID || closed.Reason != "authorization" {
			t.Fatalf("uncorrelated private close: %+v", closed)
		}
	case <-time.After(time.Second):
		t.Fatal("private revocation did not emit close")
	}
}
