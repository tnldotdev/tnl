package controlstate

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/trafficlimits"
)

func TestIntegrationPublishRunTrafficStoredRetryAndProjection(t *testing.T) {
	database, now, request, leases := newPublishRunPrerequisites(t)
	rate, period, connections, total := 40, "2s", 48, int64(1000)
	request.TrafficSelection = &trafficlimits.Selection{Connections: &connections, Rate: &rate, RatePer: &period, TotalConnections: &total}
	setup, err := database.CreatePublishRun(t.Context(), request, now, time.Minute, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	want := trafficlimits.Default()
	want.Connections, want.Rate, want.RatePer, want.TotalConnections = connections, rate, 2*time.Second, total
	if setup.Traffic != want {
		t.Fatalf("stored limits: %+v", setup.Traffic)
	}
	request.TrafficDefaults = trafficlimits.Default()
	request.TrafficDefaults.UploadBytes = 4 << 20
	request.TrafficCeiling = trafficlimits.Ceiling()
	request.TrafficCeiling.Connections = 32
	period = "2000ms"
	retry, err := database.CreatePublishRun(t.Context(), request, now.Add(time.Second), time.Minute, time.Minute)
	if err != nil || !reflect.DeepEqual(setup, retry) {
		t.Fatalf("retry re-resolved stored limits: %+v %v", retry, err)
	}
	changed := 24
	request.TrafficSelection = &trafficlimits.Selection{Connections: &changed}
	if _, err := database.CreatePublishRun(t.Context(), request, now.Add(time.Second), time.Minute, time.Minute); !errors.Is(err, ErrPublishRunIdempotency) {
		t.Fatalf("changed selection: %v", err)
	}
	f := publishRunFixture{database: database, now: now, request: request, setup: setup, leases: leases}
	readyTestSession(t, f)
	ingress := registerTestIngress(t, database, now)
	snapshot, err := database.ReadIngressRoutingTableSnapshot(t.Context(), ingress.IngressLeaseIdentity, now)
	if err != nil || len(snapshot.Entries) != 1 || snapshot.Entries[0].Projection.Traffic == nil || *snapshot.Entries[0].Projection.Traffic != want {
		t.Fatalf("snapshot traffic: %+v %v", snapshot, err)
	}
	page, err := database.ReadIngressRoutingTableEvents(t.Context(), ingress.IngressLeaseIdentity, 0, 100, now)
	if err != nil || len(page.Events) != 1 || page.Events[0].Projection.Traffic == nil || *page.Events[0].Projection.Traffic != want {
		t.Fatalf("event traffic: %+v %v", page, err)
	}
	heartbeat, err := database.HeartbeatPublishRun(t.Context(), f.authentication(), now.Add(2*time.Second), time.Minute, time.Minute)
	if err != nil || heartbeat.Traffic != want {
		t.Fatalf("heartbeat traffic: %+v %v", heartbeat, err)
	}
}
