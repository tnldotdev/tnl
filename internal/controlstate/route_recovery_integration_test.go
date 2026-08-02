package controlstate

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestIntegrationRouteRecovery(t *testing.T) {
	f := newRouteSessionFixture(t)
	claims := readyTestSession(t, f)
	database, now := f.database, f.now
	ingress := registerTestIngress(t, database, now)
	for slot, claim := range claims {
		if _, err := database.DisconnectPublisherConnection(t.Context(), claim, now.Add(time.Duration(slot+1)*time.Second), true); err != nil {
			t.Fatal(err)
		}
	}
	var episodeID int64
	var openedAt time.Time
	if err := database.pool.QueryRow(t.Context(), `SELECT episode_id, opened_at FROM control.route_recovery_episodes
		WHERE route_id = $1 AND route_version = $2 AND state = 'open'`, f.setup.RouteID, f.setup.RouteVersion).Scan(&episodeID, &openedAt); err != nil {
		t.Fatal(err)
	}
	replenishAt := now.Add(3 * time.Second)
	replenished, err := database.HeartbeatRouteSession(t.Context(), f.authentication(), replenishAt, 30*time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for slot, connection := range replenished.PublisherConnections {
		previous := f.setup.PublisherConnections[slot]
		if connection.State != PublisherConnectionAssigned ||
			connection.ConnectionAssignmentRevision != previous.ConnectionAssignmentRevision+1 ||
			connection.PublisherConnectionID == previous.PublisherConnectionID {
			t.Fatalf("replenished slot %d = %#v", slot, connection)
		}
	}
	f.setup = replenished
	recoveredAt := replenishAt.Add(2 * time.Second)
	claimTestConnection(t, f, 0, recoveredAt)
	var payload []byte
	if err := database.pool.QueryRow(t.Context(), `SELECT projection FROM control.ingress_routing_table_events
		WHERE route_id = $1 AND route_version = $2 ORDER BY routing_table_revision DESC LIMIT 1`, f.setup.RouteID, f.setup.RouteVersion).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var projection IngressRoutingTableProjection
	if err := json.Unmarshal(payload, &projection); err != nil {
		t.Fatal(err)
	}
	if projection.RecoveryEpisodeID == nil || *projection.RecoveryEpisodeID != uint64(episodeID) ||
		len(projection.PublisherConnections) != 1 || projection.RouteVersion != f.setup.RouteVersion {
		t.Fatalf("recovered projection = %#v", projection)
	}
	observedAt := recoveredAt.Add(750 * time.Millisecond)
	wantSeconds := observedAt.Sub(openedAt).Seconds()
	observation, err := database.ObserveRouteRecovery(t.Context(), ingress.IngressLeaseIdentity, f.setup.RouteID, f.setup.RouteVersion, uint64(episodeID), observedAt)
	if err != nil || observation.ObservedSeconds != wantSeconds {
		t.Fatalf("recovery observation = %#v, %v", observation, err)
	}
	repeated, err := database.ObserveRouteRecovery(t.Context(), ingress.IngressLeaseIdentity, f.setup.RouteID, f.setup.RouteVersion, uint64(episodeID), observedAt.Add(time.Second))
	if err != nil || !reflect.DeepEqual(repeated, observation) {
		t.Fatalf("observation replay = %#v, %v", repeated, err)
	}
	var count, half, one, ten, infinite int64
	var sum float64
	if err := database.pool.QueryRow(t.Context(), `
		SELECT observation_count, observation_sum_seconds, bucket_le_0_5, bucket_le_1, bucket_le_10, bucket_le_120
		FROM control.route_recovery_histogram WHERE singleton = true
	`).Scan(&count, &sum, &half, &one, &ten, &infinite); err != nil {
		t.Fatal(err)
	}
	if count != 1 || sum != wantSeconds || half != 0 || one != 0 || ten != 1 || infinite != 1 {
		t.Fatalf("recovery histogram = %d/%f, buckets %d/%d/%d/%d", count, sum, half, one, ten, infinite)
	}
}

func TestIntegrationRouteRoutingTableLifecycle(t *testing.T) {
	f := newRouteSessionFixture(t)
	ingress := registerTestIngress(t, f.database, f.now)
	claims := readyTestSession(t, f)
	database, now := f.database, f.now
	snapshot, err := database.ReadIngressRoutingTableSnapshot(t.Context(), ingress.IngressLeaseIdentity, now)
	if err != nil || len(snapshot.Routes) != 1 || len(snapshot.Routes[0].Projection.PublisherConnections) != routeSessionConnectionCount {
		t.Fatalf("ready snapshot = %#v, %v", snapshot, err)
	}
	for slot, claim := range claims {
		if _, err := database.DisconnectPublisherConnection(t.Context(), claim, now.Add(time.Duration(slot+1)*time.Second), true); err != nil {
			t.Fatal(err)
		}
	}
	empty, err := database.ReadIngressRoutingTableSnapshot(t.Context(), ingress.IngressLeaseIdentity, now.Add(3*time.Second))
	if err != nil || len(empty.Routes) != 0 || empty.RoutingTableRevision <= snapshot.RoutingTableRevision {
		t.Fatalf("disconnected snapshot = %#v, %v", empty, err)
	}
	// Read one event at a time to exercise cursor boundaries and prove no event
	// is skipped. Entry revisions remain contiguous within this route version.
	var cursor uint64
	var events int
	wantKinds := []IngressRoutingTableEventKind{IngressRouteUpsert, IngressRouteUpsert, IngressRouteTombstone}
	for {
		page, err := database.ReadIngressRoutingTableEvents(t.Context(), ingress.IngressLeaseIdentity, cursor, 1, now.Add(3*time.Second))
		if err != nil || page.ResnapshotRequired || len(page.Events) != 1 || page.NextRevision <= cursor {
			t.Fatalf("event page = %#v, %v", page, err)
		}
		events++
		event := page.Events[0]
		if events > len(wantKinds) || event.Kind != wantKinds[events-1] {
			t.Fatalf("event %d kind = %s, want sequence %v", events, event.Kind, wantKinds)
		}
		if event.RouteID != f.setup.RouteID || event.RouteVersion != f.setup.RouteVersion {
			t.Fatalf("event identity = %#v", event)
		}
		cursor = page.NextRevision
		if !page.More {
			if cursor != empty.RoutingTableRevision || event.Kind != "route_tombstone" {
				t.Fatalf("final event page = %#v", page)
			}
			break
		}
	}
	if events != len(wantKinds) {
		t.Fatalf("routing lifecycle emitted %d events, want %d", events, len(wantKinds))
	}
	rows, err := database.pool.Query(t.Context(), `SELECT entry_revision, projection FROM control.ingress_routing_table_events WHERE route_id = $1 ORDER BY routing_table_revision`, f.setup.RouteID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var read int
	for rows.Next() {
		var revision int64
		var payload []byte
		if err := rows.Scan(&revision, &payload); err != nil {
			t.Fatal(err)
		}
		read++
		var projection IngressRoutingTableProjection
		if err := json.Unmarshal(payload, &projection); err != nil {
			t.Fatal(err)
		}
		if revision != int64(read) || projection.CanonicalHostname != f.request.CertificateIdentifiers[0] ||
			projection.RouteID != f.setup.RouteID || projection.RouteVersion != f.setup.RouteVersion {
			t.Fatalf("event %d = revision %d, %#v", read, revision, projection)
		}
		if read == events && len(projection.PublisherConnections) != 0 {
			t.Fatal("tombstone retained publisher connections")
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if read != events {
		t.Fatalf("persisted events %d, paged %d", read, events)
	}
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.ingress_routing_table_clock SET retained_after_revision = $1, updated_at = $2 WHERE singleton = true`, cursor, now); err != nil {
		t.Fatal(err)
	}
	page, err := database.ReadIngressRoutingTableEvents(t.Context(), ingress.IngressLeaseIdentity, cursor-1, 10, now.Add(3*time.Second))
	if err != nil || !page.ResnapshotRequired || len(page.Events) != 0 || page.RetainedAfterRevision != cursor {
		t.Fatalf("retained event page = %#v, %v", page, err)
	}
}
