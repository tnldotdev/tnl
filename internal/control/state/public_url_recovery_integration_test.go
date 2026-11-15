package state

import (
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
)

func TestIntegrationServiceRecovery(t *testing.T) {
	f, _ := guestAuthorityFixture(t, true)
	database, now := f.database, f.now
	metrics := observability.New("control")
	database.Instrument(metrics)
	ingress, err := database.RegisterIngress(t.Context(), IngressRegistration{
		IngressID: "recovery", IngressRunID: mustOpaqueID(t, opaqueid.IngressRunPrefix), ProtocolVersion: 1,
		HTTPS: true, ConnectionCapacity: 100, IngressPoolID: PrimaryIngressPoolID,
	}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	previous := f.run.Connections
	for index, slot := range previous {
		if _, err := database.DisconnectServicePublisherConnection(t.Context(), slot.PublisherConnectionID, f.run.RunID,
			f.run.RunNumber, slot.Revision, f.leases[slot.RelayServiceID].RelayLeaseIdentity, now.Add(time.Duration(index+1)*time.Second), true); err != nil {
			t.Fatal(err)
		}
	}
	var recoveryEpisodeID int64
	var openedAt time.Time
	if err := database.pool.QueryRow(t.Context(), `SELECT id, opened_at FROM control.service_recovery_episodes
		WHERE service_run_id=$1 AND state='open'`, f.run.RunID).Scan(&recoveryEpisodeID, &openedAt); err != nil {
		t.Fatal(err)
	}
	replenishAt := now.Add(3 * time.Second)
	replenished, err := f.heartbeat(replenishAt)
	if err != nil {
		t.Fatal(err)
	}
	for index, connection := range replenished.Connections {
		if connection.State != "assigned" ||
			connection.Revision != previous[index].Revision+1 ||
			connection.PublisherConnectionID == previous[index].PublisherConnectionID {
			t.Fatalf("replenished slot %d = %#v", index, connection)
		}
	}
	recoveredAt := replenishAt.Add(2 * time.Second)
	connection := replenished.Connections[0]
	lease := f.leases[connection.RelayServiceID].RelayLeaseIdentity
	if _, err := database.ClaimServicePublisherConnection(f.ctx, connection.PublisherConnectionID, f.service.ID, f.run.RunID,
		f.run.RunNumber, connection.Revision, connection.Credential, f.guest.SourceIP, lease, recoveredAt); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ReadyServicePublisherConnection(f.ctx, connection.PublisherConnectionID, f.run.RunID,
		f.run.RunNumber, connection.Revision, lease, recoveredAt); err != nil {
		t.Fatal(err)
	}
	visitor := mustOpaqueID(t, opaqueid.VisitorConnectionPrefix)
	admission, err := database.AdmitPublicServiceVisitor(t.Context(), ingress.IngressLeaseIdentity, PrimaryIngressPoolID,
		visitor, f.service.Endpoint.Hostname, 443, netip.MustParseAddr("192.0.2.10"), recoveredAt)
	if err != nil || admission.RecoveryEpisodeID == nil || *admission.RecoveryEpisodeID != recoveryEpisodeID ||
		len(admission.Relays) != 1 || admission.RunID != f.run.RunID || admission.RunNumber != f.run.RunNumber {
		t.Fatalf("recovered service admission = %#v, %v", admission, err)
	}
	observedAt := recoveredAt.Add(750 * time.Millisecond)
	wantSeconds := observedAt.Sub(openedAt).Seconds()
	ref := ServiceRunReference{ServiceID: f.service.ID, RunID: f.run.RunID, RunNumber: f.run.RunNumber}
	observation, err := database.ObserveServiceRecovery(t.Context(), ingress.IngressLeaseIdentity, ref, visitor, uint64(recoveryEpisodeID), observedAt, observedAt)
	if err != nil || observation.ObservedSeconds != wantSeconds {
		t.Fatalf("recovery observation = %#v, %v", observation, err)
	}
	repeated, err := database.ObserveServiceRecovery(t.Context(), ingress.IngressLeaseIdentity, ref, visitor, uint64(recoveryEpisodeID), observedAt, observedAt.Add(time.Second))
	if err != nil || !reflect.DeepEqual(repeated, observation) {
		t.Fatalf("observation replay = %#v, %v", repeated, err)
	}
	// several ingress deliveries may race, or retry after a committed reply was
	// lost. all return the original measurement without recounting it.
	concurrent := make(chan error, 4)
	for range 4 {
		go func() {
			got, err := database.ObserveServiceRecovery(t.Context(), ingress.IngressLeaseIdentity, ref, visitor,
				uint64(recoveryEpisodeID), observedAt, observedAt.Add(2*time.Second))
			if err == nil && !reflect.DeepEqual(got, observation) {
				err = errors.New("replay changed the committed recovery")
			}
			concurrent <- err
		}()
	}
	for range 4 {
		if err := <-concurrent; err != nil {
			t.Error(err)
		}
	}
	var count, half, one, ten, infinite int64
	var sum float64
	if err := database.pool.QueryRow(t.Context(), `
		SELECT observation_count, observation_sum_seconds, bucket_le_0_5, bucket_le_1, bucket_le_10, bucket_le_120
		FROM control.service_recovery_histogram WHERE id = 1
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
		case "tnl_control_service_recovery_duration_seconds":
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

func TestIntegrationServiceRecoveryRequiresExactAdmissionAndCurrentLease(t *testing.T) {
	f, _ := guestAuthorityFixture(t, true)
	ctx := t.Context()
	ingress, err := f.database.RegisterIngress(ctx, IngressRegistration{
		IngressID: "recovery-binding", IngressRunID: mustOpaqueID(t, opaqueid.IngressRunPrefix),
		ProtocolVersion: 1, HTTPS: true, ConnectionCapacity: 100, IngressPoolID: PrimaryIngressPoolID,
	}, f.now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	slot := f.run.Connections[0]
	if _, err := f.database.DisconnectServicePublisherConnection(ctx, slot.PublisherConnectionID, f.run.RunID,
		f.run.RunNumber, slot.Revision, f.leases[slot.RelayServiceID].RelayLeaseIdentity, f.now.Add(time.Second), true); err != nil {
		t.Fatal(err)
	}
	visitor := mustOpaqueID(t, opaqueid.VisitorConnectionPrefix)
	at := f.now.Add(2 * time.Second)
	admission, err := f.database.AdmitPublicServiceVisitor(ctx, ingress.IngressLeaseIdentity, PrimaryIngressPoolID,
		visitor, f.service.Endpoint.Hostname, 443, netip.MustParseAddr("192.0.2.10"), at)
	if err != nil || admission.RecoveryEpisodeID == nil {
		t.Fatal("surviving relay did not retain the open recovery episode", err)
	}
	ref := ServiceRunReference{ServiceID: f.service.ID, RunID: f.run.RunID, RunNumber: f.run.RunNumber}
	for _, field := range []string{"service", "run", "number", "visitor", "lease", "before-admission", "future", "expired-lease"} {
		t.Run(field, func(t *testing.T) {
			run, connection, lease, observed, delivered := ref, visitor, ingress.IngressLeaseIdentity, at, at
			switch field {
			case "service":
				run.ServiceID = mustOpaqueID(t, opaqueid.ServicePrefix)
			case "run":
				run.RunID = mustOpaqueID(t, opaqueid.ServiceRunPrefix)
			case "number":
				run.RunNumber++
			case "visitor":
				connection = mustOpaqueID(t, opaqueid.VisitorConnectionPrefix)
			case "lease":
				lease.IngressLeaseRevision++
			case "before-admission":
				observed = at.Add(-time.Second)
			case "future":
				observed = at.Add(2 * time.Second)
			case "expired-lease":
				delivered = f.now.Add(2 * time.Minute)
			}
			if _, err := f.database.ObserveServiceRecovery(ctx, lease, run, connection,
				uint64(*admission.RecoveryEpisodeID), observed, delivered); err == nil {
				t.Fatal("recovery accepted another admission, run, timestamp, or expired sender")
			}
		})
	}
	if err := f.database.CloseServiceRun(f.ctx, ref.ServiceID, ref.RunID, f.run.Token, at.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.ObserveServiceRecovery(ctx, ingress.IngressLeaseIdentity, ref, visitor,
		uint64(*admission.RecoveryEpisodeID), at, at.Add(2*time.Second)); !errors.Is(err, ErrServiceRecoveryEpisodeStale) {
		t.Fatal("closed run completed its canceled recovery", err)
	}
	var canceled bool
	if err := f.database.pool.QueryRow(ctx, `SELECT state='canceled' AND canceled_at IS NOT NULL AND observed_at IS NULL
		FROM control.service_recovery_episodes WHERE id=$1`, *admission.RecoveryEpisodeID).Scan(&canceled); err != nil || !canceled {
		t.Fatal("run closure did not cancel its exact open recovery", canceled, err)
	}
}

func TestIntegrationServiceRecoveryIgnoresIntentionalAndNeverReadyDisconnects(t *testing.T) {
	for _, mode := range []string{"intentional", "never-ready", "relay-drain", "lease-loss"} {
		t.Run(mode, func(t *testing.T) {
			f, _ := guestAuthorityFixture(t, mode != "never-ready")
			slot := f.run.Connections[0]
			at := f.now.Add(time.Second)
			lease := f.leases[slot.RelayServiceID].RelayLeaseIdentity
			switch mode {
			case "never-ready":
				if _, err := f.database.ClaimServicePublisherConnection(f.ctx, slot.PublisherConnectionID, f.service.ID,
					f.run.RunID, f.run.RunNumber, slot.Revision, slot.Credential, f.guest.SourceIP, lease, at); err != nil {
					t.Fatal(err)
				}
				fallthrough
			case "intentional":
				if _, err := f.database.DisconnectServicePublisherConnection(t.Context(), slot.PublisherConnectionID,
					f.run.RunID, f.run.RunNumber, slot.Revision, lease, at, mode != "intentional"); err != nil {
					t.Fatal(err)
				}
			case "relay-drain":
				if _, err := f.database.BeginRelayDrain(t.Context(), lease, at, at.Add(time.Minute)); err != nil {
					t.Fatal(err)
				}
				if _, err := f.heartbeat(at); err != nil {
					t.Fatal(err)
				}
			case "lease-loss":
				if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.relay_leases SET lease_expires_at=$1
					WHERE relay_id=$2`, at, lease.RelayID); err != nil {
					t.Fatal(err)
				}
				if _, err := f.heartbeat(at.Add(time.Second)); err != nil {
					t.Fatal(err)
				}
			}
			var count int
			want := 0
			if mode == "lease-loss" {
				want = 1
			}
			if err := f.database.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.service_recovery_episodes
				WHERE service_run_id=$1`, f.run.RunID).Scan(&count); err != nil || count != want {
				t.Fatal("recovery did not distinguish unexpected loss from setup or intentional drain", count, err)
			}
		})
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
	wantKinds := []IngressRoutingTableEventKind{IngressPublicURLUpsert, IngressPublicURLUpsert, IngressPublicURLUpsert, IngressPublicURLTombstone}
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
	rows, err := database.pool.Query(t.Context(), `SELECT entry_revision, projection FROM control.ingress_routing_table_events WHERE public_url_id = $1 ORDER BY id`, f.setup.PublicURLID)
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
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.ingress_routing_table_clock SET retained_after_revision = $1, updated_at = $2 WHERE id = 1`, cursor, now); err != nil {
		t.Fatal(err)
	}
	page, err := database.ReadIngressRoutingTableEvents(t.Context(), ingress.IngressLeaseIdentity, cursor-1, 10, now.Add(3*time.Second))
	if err != nil || !page.ResnapshotRequired || len(page.Events) != 0 || page.RetainedAfterRevision != cursor {
		t.Fatalf("retained event page = %#v, %v", page, err)
	}
}
