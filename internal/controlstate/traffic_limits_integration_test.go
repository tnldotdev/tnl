package controlstate

import (
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/trafficlimits"
)

func TestIntegrationRunTrafficProjectionAndRetry(t *testing.T) {
	database, now, request, leases := newPublishRunPrerequisites(t)
	selected := trafficlimits.Limits{Connections: 12, Rate: 5, RatePer: 2 * time.Second,
		Burst: 9, UploadBytes: 2 << 20, DownloadBytes: 4 << 20}
	request.Traffic = &selected
	setup, err := database.CreatePublishRun(t.Context(), request, now, 30*time.Second, time.Minute)
	if err != nil || !reflect.DeepEqual(setup.Traffic, &selected) {
		t.Fatalf("created traffic = %+v, %v", setup.Traffic, err)
	}
	f := publishRunFixture{database: database, now: now, request: request, setup: setup, leases: leases}
	ingress := registerTestIngress(t, database, now)
	claims := readyTestSession(t, f)
	snapshot, err := database.ReadIngressRoutingTableSnapshot(t.Context(), ingress.IngressLeaseIdentity, now)
	if err != nil || len(snapshot.Entries) != 1 || !reflect.DeepEqual(snapshot.Entries[0].Projection.Traffic, &selected) {
		t.Fatalf("routable traffic = %+v, %v", snapshot, err)
	}
	repeated, err := database.CreatePublishRun(t.Context(), request, now.Add(time.Second), 30*time.Second, time.Minute)
	if err != nil || repeated.PublishRunID != setup.PublishRunID || !reflect.DeepEqual(repeated.Traffic, &selected) {
		t.Fatalf("idempotent traffic = %+v, %v", repeated, err)
	}
	if _, err := database.DisconnectPublisherConnection(t.Context(), claims[0], now.Add(2*time.Second), true); err != nil {
		t.Fatal(err)
	}
	// replacement events retain the same run's traffic even as assignments change.
	page, err := database.ReadIngressRoutingTableEvents(t.Context(), ingress.IngressLeaseIdentity,
		snapshot.RoutingTableRevision, 10, now.Add(2*time.Second))
	if err != nil || len(page.Events) == 0 || !reflect.DeepEqual(page.Events[len(page.Events)-1].Projection.Traffic, &selected) {
		t.Fatalf("replacement event traffic = %+v, %v", page, err)
	}
}
