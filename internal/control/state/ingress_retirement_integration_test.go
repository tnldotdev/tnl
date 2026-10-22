package controlstate

import (
	"testing"
	"time"
)

func TestIntegrationIngressTerminalRetirementProof(t *testing.T) {
	f := newPublishRunFixture(t)
	claims := readyTestSession(t, f)
	ingress := registerTestIngress(t, f.database, f.now)
	for slot, claim := range claims {
		if _, err := f.database.DisconnectPublisherConnection(t.Context(), claim, f.now.Add(time.Duration(slot+1)*time.Second), true); err != nil {
			t.Fatal(err)
		}
	}
	page, err := f.database.ReadIngressRoutingTableEvents(t.Context(), ingress.IngressLeaseIdentity, 0, 100, f.now.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	last := page.Events[len(page.Events)-1]
	if last.Kind != IngressPublicURLTombstone || last.Projection.PublishRunClosed {
		t.Fatalf("temporary outage carried terminal proof: %+v", last)
	}
	if err := f.database.ClosePublishRun(t.Context(), f.setup.PublishRunID, f.setup.PublishRunToken, f.now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	terminal, err := f.database.ReadIngressRoutingTableEvents(t.Context(), ingress.IngressLeaseIdentity, page.NextRevision, 100, f.now.Add(4*time.Second))
	if err != nil || len(terminal.Events) != 1 {
		t.Fatalf("terminal page: %+v %v", terminal, err)
	}
	last = terminal.Events[0]
	if last.Kind != IngressPublicURLTombstone || !last.Projection.PublishRunClosed || last.Projection.PublishRunID != f.setup.PublishRunID || last.PublishRunNumber != f.setup.PublishRunNumber {
		t.Fatalf("closed run missing exact terminal proof: %+v", last)
	}
}
