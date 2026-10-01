package controlstate

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
)

func TestIntegrationPublicURLRecovery(t *testing.T) {
	f := newPublishRunFixture(t)
	claims := readyTestSession(t, f)
	database, now := f.database, f.now
	metrics := observability.New("control")
	database.Instrument(metrics)
	ingress := registerTestIngress(t, database, now)
	for slot, claim := range claims {
		if _, err := database.DisconnectPublisherConnection(t.Context(), claim, now.Add(time.Duration(slot+1)*time.Second), true); err != nil {
			t.Fatal(err)
		}
	}
	var recoveryEpisodeID int64
	var openedAt time.Time
	if err := database.pool.QueryRow(t.Context(), `SELECT recovery_episode_id, opened_at FROM control.public_url_recovery_episodes
		WHERE public_url_id = $1 AND publish_run_number = $2 AND state = 'open'`, f.setup.PublicURLID, f.setup.PublishRunNumber).Scan(&recoveryEpisodeID, &openedAt); err != nil {
		t.Fatal(err)
	}
	replenishAt := now.Add(3 * time.Second)
	replenished, err := database.HeartbeatPublishRun(t.Context(), f.authentication(), replenishAt, 30*time.Second, time.Minute)
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
		WHERE public_url_id = $1 AND publish_run_number = $2 ORDER BY routing_table_revision DESC LIMIT 1`, f.setup.PublicURLID, f.setup.PublishRunNumber).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var projection IngressRoutingTableProjection
	if err := json.Unmarshal(payload, &projection); err != nil {
		t.Fatal(err)
	}
	if projection.RecoveryEpisodeID == nil || *projection.RecoveryEpisodeID != uint64(recoveryEpisodeID) ||
		len(projection.PublisherConnections) != 1 || projection.PublishRunNumber != f.setup.PublishRunNumber {
		t.Fatalf("recovered projection = %#v", projection)
	}
	observedAt := recoveredAt.Add(750 * time.Millisecond)
	wantSeconds := observedAt.Sub(openedAt).Seconds()
	observation, err := database.ObservePublicURLRecovery(t.Context(), ingress.IngressLeaseIdentity, f.setup.PublicURLID, f.setup.PublishRunNumber, uint64(recoveryEpisodeID), observedAt)
	if err != nil || observation.ObservedSeconds != wantSeconds {
		t.Fatalf("recovery observation = %#v, %v", observation, err)
	}
	repeated, err := database.ObservePublicURLRecovery(t.Context(), ingress.IngressLeaseIdentity, f.setup.PublicURLID, f.setup.PublishRunNumber, uint64(recoveryEpisodeID), observedAt.Add(time.Second))
	if err != nil || !reflect.DeepEqual(repeated, observation) {
		t.Fatalf("observation replay = %#v, %v", repeated, err)
	}
	var count, half, one, ten, infinite int64
	var sum float64
	if err := database.pool.QueryRow(t.Context(), `
		SELECT observation_count, observation_sum_seconds, bucket_le_0_5, bucket_le_1, bucket_le_10, bucket_le_120
		FROM control.public_url_recovery_histogram WHERE singleton = true
	`).Scan(&count, &sum, &half, &one, &ten, &infinite); err != nil {
		t.Fatal(err)
	}
	if count != 1 || sum != wantSeconds || half != 0 || one != 0 || ten != 1 || infinite != 1 {
		t.Fatalf("recovery histogram = %d/%f, buckets %d/%d/%d/%d", count, sum, half, one, ten, infinite)
	}
	families, err := metrics.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var recoveryCount uint64
	var replacements float64
	for _, family := range families {
		switch family.GetName() {
		case "tnl_control_public_url_recovery_duration_seconds":
			recoveryCount = family.Metric[0].GetHistogram().GetSampleCount()
		case "tnl_control_connection_assignments_replaced_total":
			for _, metric := range family.Metric {
				replacements += metric.GetCounter().GetValue()
			}
		}
	}
	if recoveryCount != 1 || replacements != 2 {
		t.Fatalf("committed recovery metrics: observations=%d replacements=%g", recoveryCount, replacements)
	}
}

func TestIntegrationRouteRoutingTableLifecycle(t *testing.T) {
	f := newPublishRunFixture(t)
	ingress := registerTestIngress(t, f.database, f.now)
	claims := readyTestSession(t, f)
	database, now := f.database, f.now
	snapshot, err := database.ReadIngressRoutingTableSnapshot(t.Context(), ingress.IngressLeaseIdentity, now)
	if err != nil || len(snapshot.Entries) != 1 || len(snapshot.Entries[0].Projection.PublisherConnections) != publishRunConnectionCount {
		t.Fatalf("ready snapshot = %#v, %v", snapshot, err)
	}
	for slot, claim := range claims {
		if _, err := database.DisconnectPublisherConnection(t.Context(), claim, now.Add(time.Duration(slot+1)*time.Second), true); err != nil {
			t.Fatal(err)
		}
	}
	empty, err := database.ReadIngressRoutingTableSnapshot(t.Context(), ingress.IngressLeaseIdentity, now.Add(3*time.Second))
	if err != nil || len(empty.Entries) != 0 || empty.RoutingTableRevision <= snapshot.RoutingTableRevision {
		t.Fatalf("disconnected snapshot = %#v, %v", empty, err)
	}
	// read one event at a time to exercise cursor boundaries and prove no event
	// is skipped. entry revisions remain contiguous within this publish run number.
	var cursor uint64
	var events int
	wantKinds := []IngressRoutingTableEventKind{IngressPublicURLUpsert, IngressPublicURLUpsert, IngressPublicURLTombstone}
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
		if event.PublicURLID != f.setup.PublicURLID || event.PublishRunNumber != f.setup.PublishRunNumber {
			t.Fatalf("event identity = %#v", event)
		}
		cursor = page.NextRevision
		if !page.More {
			if cursor != empty.RoutingTableRevision || event.Kind != "public_url_tombstone" {
				t.Fatalf("final event page = %#v", page)
			}
			break
		}
	}
	if events != len(wantKinds) {
		t.Fatalf("routing lifecycle emitted %d events, want %d", events, len(wantKinds))
	}
	rows, err := database.pool.Query(t.Context(), `SELECT entry_revision, projection FROM control.ingress_routing_table_events WHERE public_url_id = $1 ORDER BY routing_table_revision`, f.setup.PublicURLID)
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
			projection.PublicURLID != f.setup.PublicURLID || projection.PublishRunNumber != f.setup.PublishRunNumber {
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
