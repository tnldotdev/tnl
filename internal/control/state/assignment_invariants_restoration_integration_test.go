package state

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationAssignmentRestoredParentEligibilityRejectsDrift(t *testing.T) {
	f := newServicePublicationFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	before := restoredAssignmentSnapshot(t, ctx, f.database.pool, f.run.RunID)
	assertRestoredAssignmentState(t, ctx, f.database.pool, 2)
	tx, err := f.database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, tx)
	updated, err := tx.Exec(ctx, `UPDATE control.service_connection_slots SET session_open=false
		WHERE service_run_id=$1 AND connection_slot=0`, f.run.RunID)
	if err != nil || updated.RowsAffected() != 1 {
		t.Fatal("eligibility drift did not reach deferred constraint validation", updated.RowsAffected(), err)
	}
	requireRestoredPostgresFailure(t, tx.Commit(ctx), "23503", "service_connection_slots_open", "")
	if after := restoredAssignmentSnapshot(t, ctx, f.database.pool, f.run.RunID); after != before {
		t.Fatal("rejected eligibility drift changed the stored run or children")
	}
	assertRestoredAssignmentState(t, ctx, f.database.pool, 2)
}

func TestIntegrationAssignmentRestoredTransitionMatrix(t *testing.T) {
	f := newServicePublicationFixture(t)
	f.readyConnections(t, f.now)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if _, err := f.database.RegisterRelay(ctx, relayLifecycleRegistration("restored-spare"), f.now, time.Hour); err != nil {
		t.Fatal(err)
	}
	tx, err := f.database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, tx)
	// closed represents expired slots; connected retains a live reservation
	// without reintroducing the retired draining slot state.
	steps := []struct {
		name, query string
		want        int64
	}{
		{"connected reservation", `UPDATE control.service_connection_slots SET state='connected' WHERE connection_slot=0`, 2},
		{"service transfer", `UPDATE control.service_connection_slots SET relay_service_id='restored-spare' WHERE connection_slot=0`, 2},
		{"expire slot", `UPDATE control.service_connection_slots SET state='closed' WHERE connection_slot=1`, 1},
		{"reassign expired", `UPDATE control.service_connection_slots SET state='assigned',relay_id=NULL,relay_run_id=NULL,relay_lease_revision=NULL WHERE connection_slot=1`, 2},
		{"close slot", `UPDATE control.service_connection_slots SET state='closed' WHERE connection_slot=1`, 1},
		{"reassign closed", `UPDATE control.service_connection_slots SET state='assigned',relay_id=NULL,relay_run_id=NULL,relay_lease_revision=NULL WHERE connection_slot=1`, 2},
		{"close parent first", `UPDATE control.service_runs SET state='closed',closed_at=publisher_expires_at`, 0},
		{"close slot after parent", `UPDATE control.service_connection_slots SET state='closed' WHERE connection_slot=1`, 0},
		{"reopen parent", `UPDATE control.service_runs SET state='starting',closed_at=NULL`, 1},
		{"save slots", `CREATE TEMP TABLE restored_saved_assignments ON COMMIT DROP AS TABLE control.service_connection_slots`, 1},
		{"delete slots", `DELETE FROM control.service_connection_slots`, 0},
		{"insert active and closed slots", `INSERT INTO control.service_connection_slots SELECT * FROM restored_saved_assignments`, 1},
		{"insert conflict retry", `INSERT INTO control.service_connection_slots SELECT * FROM restored_saved_assignments ON CONFLICT DO NOTHING`, 1},
		{"close children first", `UPDATE control.service_connection_slots SET state='closed'`, 0},
		{"close parent after children", `UPDATE control.service_runs SET state='closed',closed_at=publisher_expires_at`, 0},
		{"delete closed children", `DELETE FROM control.service_connection_slots`, 0},
		{"prepare historical slots", `UPDATE restored_saved_assignments SET session_open=false`, 0},
		{"insert into closed parent", `INSERT INTO control.service_connection_slots SELECT * FROM restored_saved_assignments`, 0},
		{"reopen with inserted slots", `UPDATE control.service_runs SET state='starting',closed_at=NULL`, 1},
		{"close children and parent in one statement", `WITH closed AS (
			UPDATE control.service_connection_slots SET state='closed' RETURNING service_run_id
		) UPDATE control.service_runs SET state='closed',closed_at=publisher_expires_at
		WHERE id IN (SELECT service_run_id FROM closed)`, 0},
		{"reopen after compound closure", `UPDATE control.service_runs SET state='starting',closed_at=NULL`, 0},
		{"restore assignment", `UPDATE control.service_connection_slots SET state='assigned',relay_id=NULL,relay_run_id=NULL,relay_lease_revision=NULL WHERE connection_slot=1`, 1},
		{"close parent and children in one statement", `WITH closed AS (
			UPDATE control.service_runs SET state='closed',closed_at=publisher_expires_at RETURNING id
		) UPDATE control.service_connection_slots SET state='closed'
		WHERE service_run_id IN (SELECT id FROM closed)`, 0},
	}
	if len(steps) != 23 {
		t.Fatal("reservation transition workload changed", len(steps))
	}
	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			if _, err := tx.Exec(ctx, step.query); err != nil {
				t.Fatal(err)
			}
			assertRestoredAssignmentState(t, ctx, tx, step.want)
		})
		if t.Failed() {
			return
		}
	}
	if _, err := tx.Exec(ctx, "SET CONSTRAINTS ALL IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	assertRestoredAssignmentState(t, ctx, f.database.pool, 2)
	for range 2 {
		if err := f.database.CloseServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, f.now); err != nil {
			t.Fatal(err)
		}
		assertRestoredAssignmentState(t, ctx, f.database.pool, 0)
	}
}

func TestIntegrationAssignmentRestoredRetryDisconnectAndDisabledRelayTotals(t *testing.T) {
	f := newServicePublicationFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	d := f.database
	if _, err := d.StartServiceRun(ctx, f.service.ID, f.run.RunID, f.run.RunNumber, f.publisher, f.now); err != nil {
		t.Fatal(err)
	}
	assertRestoredAssignmentState(t, ctx, d.pool, 2)
	for index, slot := range f.run.Connections {
		lease := f.leases[slot.RelayServiceID].RelayLeaseIdentity
		for range 2 {
			if _, err := d.ClaimServicePublisherConnection(ctx, slot.PublisherConnectionID, f.service.ID,
				f.run.RunID, f.run.RunNumber, slot.Revision, slot.Credential, netip.MustParseAddr("127.0.0.1"), lease, f.now); err != nil {
				t.Fatal(err)
			}
			assertRestoredAssignmentState(t, ctx, d.pool, 2)
		}
		t.Run(fmt.Sprintf("slot-%d/readiness-and-retry", index), func(t *testing.T) {
			for attempt := range 2 {
				if _, err := d.ReadyServicePublisherConnection(ctx, slot.PublisherConnectionID, f.run.RunID,
					f.run.RunNumber, slot.Revision, lease, f.now); err != nil {
					t.Fatalf("readiness attempt %d: %v", attempt+1, err)
				}
				assertRestoredAssignmentState(t, ctx, d.pool, 2)
			}
		})
	}
	// a failed retry assertion stays visible without hiding the later totals
	// checks behind that subtest's failure.
	if _, err := d.RegisterRelay(ctx, relayLifecycleRegistration("restored-spare"), f.now, time.Hour); err != nil {
		t.Fatal(err)
	}
	slot := f.run.Connections[0]
	lease := f.leases[slot.RelayServiceID].RelayLeaseIdentity
	if _, err := d.DisconnectServicePublisherConnection(ctx, slot.PublisherConnectionID, f.run.RunID,
		f.run.RunNumber, slot.Revision, lease, f.now, true); err != nil {
		t.Fatal(err)
	}
	assertRestoredAssignmentState(t, ctx, d.pool, 1)
	_, err := d.DisconnectServicePublisherConnection(ctx, slot.PublisherConnectionID, f.run.RunID,
		f.run.RunNumber, slot.Revision, lease, f.now, true)
	requireRestoredOnlyError(t, err, ErrServiceAccess)
	assertRestoredAssignmentState(t, ctx, d.pool, 1)
	recovered, err := d.HeartbeatServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, f.now,
		ServiceRunHealth{StreamCapacity: 64})
	if err != nil || len(recovered.Connections) != 2 || recovered.Connections[0].PublisherConnectionID == slot.PublisherConnectionID ||
		recovered.Connections[0].Revision != slot.Revision+1 {
		t.Fatal("disconnected slot did not receive a fresh assignment", err)
	}
	assertRestoredAssignmentState(t, ctx, d.pool, 2)
	disabled := recovered.Connections[0].RelayServiceID
	if disabled == "restored-spare" {
		t.Fatal("fixture consumed the spare before disabled-relay recovery")
	}
	if _, err := d.pool.Exec(ctx, `UPDATE control.relay_services SET enabled=false WHERE relay_service_id=$1`, disabled); err != nil {
		t.Fatal(err)
	}
	assertRestoredAssignmentState(t, ctx, d.pool, 2)
	recovered, err = d.HeartbeatServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, f.now,
		ServiceRunHealth{StreamCapacity: 64})
	if err != nil || len(recovered.Connections) != 2 || recovered.Connections[0].RelayServiceID != "restored-spare" {
		t.Fatal("disabled-relay recovery did not select the spare", err)
	}
	assertRestoredAssignmentState(t, ctx, d.pool, 2)
	for range 2 {
		if err := d.CloseServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, f.now); err != nil {
			t.Fatal(err)
		}
		assertRestoredAssignmentState(t, ctx, d.pool, 0)
	}
}

func TestIntegrationAssignmentRestoredStartAuditRollback(t *testing.T) {
	f := newServicePublicationFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	d := f.database
	if err := d.CloseServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, f.now); err != nil {
		t.Fatal(err)
	}
	assertRestoredAssignmentState(t, ctx, d.pool, 0)
	prepared, err := d.PrepareServiceRun(ctx, f.service.ID, f.publisher, "restored-audit-rollback", f.now,
		ServiceRunRequest{Metadata: f.service.ServiceMetadata})
	if err != nil {
		t.Fatal(err)
	}
	before := restoredAssignmentSnapshot(t, ctx, d.pool, prepared.RunID)
	// this fault exists only in this disposable database. it observes the real
	// slots and trigger-maintained reservations before rejecting the real audit.
	for _, statement := range []string{
		`CREATE FUNCTION control.restored_reject_start_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		DECLARE slots bigint; relays bigint; reservations bigint;
		BEGIN
			SELECT count(*),count(DISTINCT relay_service_id) INTO slots,relays
			FROM control.service_connection_slots WHERE service_run_id=NEW.run_id AND session_open;
			SELECT COALESCE(sum(reserved_slot_count),0) INTO reservations FROM control.relay_service_reservations;
			IF slots<>2 OR relays<>2 OR reservations<>2 THEN
				RAISE EXCEPTION 'start audit reached without both reservations'
					USING ERRCODE='P0001',DETAIL=format('slots=%s relays=%s reservations=%s',slots,relays,reservations);
			END IF;
			RAISE EXCEPTION 'selected late start audit failure'
				USING ERRCODE='23514',CONSTRAINT='restored_reject_start_audit',
					DETAIL='slots=2 relays=2 reservations=2';
		END; $$`,
		`CREATE TRIGGER restored_reject_start_audit BEFORE INSERT ON control.service_audit_events
			FOR EACH ROW WHEN (NEW.event_type='run.start') EXECUTE FUNCTION control.restored_reject_start_audit()`,
	} {
		if _, err := d.pool.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	_, err = d.StartServiceRun(ctx, f.service.ID, prepared.RunID, prepared.RunNumber, f.publisher, f.now)
	requireRestoredPostgresFailure(t, err, "23514", "restored_reject_start_audit", "slots=2 relays=2 reservations=2")
	if after := restoredAssignmentSnapshot(t, ctx, d.pool, prepared.RunID); after != before {
		t.Fatal("late start-audit failure retained run, number, slot, or audit changes")
	}
	assertRestoredAssignmentState(t, ctx, d.pool, 0)
	for _, statement := range []string{
		`DROP TRIGGER restored_reject_start_audit ON control.service_audit_events`,
		`DROP FUNCTION control.restored_reject_start_audit()`,
	} {
		if _, err := d.pool.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	run, err := d.StartServiceRun(ctx, f.service.ID, prepared.RunID, prepared.RunNumber, f.publisher, f.now)
	if err != nil || run.RunID != prepared.RunID || run.RunNumber != prepared.RunNumber || len(run.Connections) != 2 {
		t.Fatal("same preparation could not retry after late audit rollback", err)
	}
	var audits int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.service_audit_events
		WHERE run_id=$1 AND event_type='run.start'`, run.RunID).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("successful retry did not commit exactly one start audit", audits, err)
	}
	assertRestoredAssignmentState(t, ctx, d.pool, 2)
}

func TestIntegrationAssignmentRestoredExpiredPlacementRetainsReservations(t *testing.T) {
	f := newServicePublicationFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	d := f.database
	if updated, err := d.pool.Exec(ctx, `UPDATE control.relay_leases SET lease_expires_at=$1`, f.now.Add(time.Second)); err != nil || updated.RowsAffected() != 2 {
		t.Fatal("did not establish two actually expired relay leases", updated.RowsAffected(), err)
	}
	at := f.now.Add(2 * time.Second)
	var live int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.relay_leases WHERE lease_expires_at>$1`, at).Scan(&live); err != nil || live != 0 {
		t.Fatal("expired-placement fixture still has live relay leases", live, err)
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, tx)
	services, leases, err := availableRelayServicePlacements(ctx, controlstatedb.New(tx), at)
	if err != nil || len(services) != 0 || len(leases) != 0 {
		t.Fatal("actual expired leases remained available for placement", len(services), len(leases), err)
	}
	assertRestoredAssignmentState(t, ctx, tx, 2)
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	assertRestoredAssignmentState(t, ctx, d.pool, 2)
	if err := d.CloseServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, at); err != nil {
		t.Fatal(err)
	}
	assertRestoredAssignmentState(t, ctx, d.pool, 0)
}

func TestIntegrationAssignmentRestoredExpiryPlacementAllowsUnrelatedProgress(t *testing.T) {
	topology := newRestoredAssignmentTopology(t)
	f, sibling, unrelated := topology.fixtures[0], topology.fixtures[1], topology.fixtures[2]
	d, at := f.database, f.now.Add(2*time.Second)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if _, err := d.pool.Exec(ctx, `UPDATE control.service_runs SET publisher_expires_at=$2 WHERE id=$1`,
		f.run.RunID, f.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.pool.Exec(ctx, `UPDATE control.service_connection_slots SET credential_expires_at=$2 WHERE service_run_id=$1`,
		sibling.run.RunID, f.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	assertRestoredAssignmentState(t, ctx, d.pool, 10)
	mutationGateKey := installRestoredAssignmentMutationGate(t, ctx, d, f.run.RunID)
	gate, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	// preparation expires the old run before a separate start places the new
	// one. pause an eligibility change after its real reservation update.
	if _, err := gate.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::text,0))`, mutationGateKey); err != nil {
		t.Fatal(err)
	}
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	replacementDone, heartbeatDone := make(chan error, 1), make(chan error, 1)
	var replacement, heartbeat ServiceRunState
	workers.Go(func() {
		prepared, err := d.PrepareServiceRun(ctx, f.service.ID, f.publisher, "restored-expired-replacement", at,
			ServiceRunRequest{Metadata: f.service.ServiceMetadata})
		if err == nil {
			replacement, err = d.StartServiceRun(ctx, f.service.ID, prepared.RunID, prepared.RunNumber, f.publisher, at)
		}
		replacementDone <- err
	})
	expiryPID := waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), replacementDone)
	assertRestoredAssignmentGuard(t, ctx, d, expiryPID, true)
	workers.Go(func() {
		var err error
		heartbeat, err = d.HeartbeatServiceRun(ctx, sibling.service.ID, sibling.run.RunID, sibling.run.Token, at,
			ServiceRunHealth{StreamCapacity: 64})
		heartbeatDone <- err
	})
	heartbeatPID := waitForPostgresBlock(t, ctx, d, expiryPID, heartbeatDone)
	assertRestoredAssignmentGuard(t, ctx, d, heartbeatPID, false)
	// two distinct assigned slots provide two progressing claim/readiness
	// calls while expiry and placement are both blocked, without a ready-slot
	// duplicate claim masking the lock graph.
	if len(unrelated.run.Connections) != 2 {
		t.Fatal("unrelated progress requires two slots")
	}
	for _, slot := range unrelated.run.Connections {
		lease := unrelated.leases[slot.RelayServiceID].RelayLeaseIdentity
		if _, err := d.ClaimServicePublisherConnection(ctx, slot.PublisherConnectionID, unrelated.service.ID,
			unrelated.run.RunID, unrelated.run.RunNumber, slot.Revision, slot.Credential, netip.MustParseAddr("127.0.0.1"), lease, at); err != nil {
			t.Fatal("unrelated claim could not progress before gate release", err)
		}
		assertRestoredAssignmentState(t, ctx, d.pool, 10)
		if _, err := d.ReadyServicePublisherConnection(ctx, slot.PublisherConnectionID, unrelated.run.RunID,
			unrelated.run.RunNumber, slot.Revision, lease, at); err != nil {
			t.Fatal("unrelated readiness could not progress before gate release", err)
		}
		assertRestoredAssignmentState(t, ctx, d.pool, 10)
	}
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	replacementErr := awaitIntegrationResult(t, ctx, replacementDone)
	heartbeatErr := awaitIntegrationResult(t, ctx, heartbeatDone)
	if err := errors.Join(replacementErr, heartbeatErr); err != nil {
		t.Fatal(err)
	}
	if replacement.RunID == f.run.RunID || replacement.RunNumber != f.run.RunNumber+1 || len(replacement.Connections) != 2 ||
		heartbeat.RunID != sibling.run.RunID || len(heartbeat.Connections) != 2 {
		t.Fatal("joined expiry/placement changed the replacement or sibling identity")
	}
	var closed bool
	if err := d.pool.QueryRow(ctx, `SELECT state='closed' AND closed_at IS NOT NULL AND NOT assignments_open
		FROM control.service_runs WHERE id=$1`, f.run.RunID).Scan(&closed); err != nil || !closed {
		t.Fatal("expired predecessor retained assignment authority", err)
	}
	assertRestoredAssignmentState(t, ctx, d.pool, 10)
}

func TestIntegrationAssignmentRestoredBulkClosureLockOrder(t *testing.T) {
	for _, cleanup := range []bool{false, true} {
		t.Run(fmt.Sprintf("ephemeral-cleanup=%t", cleanup), func(t *testing.T) {
			topology := newRestoredAssignmentTopology(t)
			fixtures := topology.fixtures
			d, now := fixtures[0].database, fixtures[0].now
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			for _, name := range []string{"a", "b", "y", "z"} {
				registration := relayLifecycleRegistration(name)
				registration.ConnectionCapacity = 100
				if _, err := d.RegisterRelay(ctx, registration, now, time.Hour); err != nil {
					t.Fatal(err)
				}
			}
			// membership closure orders by service identity. expiration below
			// uses matching finite serving and liveness deadlines in that order.
			slices.SortFunc(fixtures[:2], func(a, b servicePublicationFixture) int {
				if a.service.ID < b.service.ID {
					return -1
				}
				if a.service.ID > b.service.ID {
					return 1
				}
				return 0
			})
			for index, names := range [][2]string{{"y", "z"}, {"a", "b"}, {"a", "z"}} {
				for slot, name := range names {
					updated, err := d.pool.Exec(ctx, `UPDATE control.service_connection_slots slot
						SET relay_service_id=service.relay_service_id,relay_address=service.relay_address,tls_server_name=service.tls_server_name
						FROM control.relay_services service WHERE slot.service_run_id=$1 AND slot.connection_slot=$2
						AND service.relay_service_id=$3`, fixtures[index].run.RunID, slot, name)
					if err != nil || updated.RowsAffected() != 1 {
						t.Fatal("adversarial reservation assignment failed", updated.RowsAffected(), err)
					}
				}
			}
			if cleanup {
				for index, f := range fixtures[:2] {
					if _, err := d.pool.Exec(ctx, `UPDATE control.services SET ephemeral=true WHERE id=$1`, f.service.ID); err != nil {
						t.Fatal(err)
					}
					if _, err := d.pool.Exec(ctx, `UPDATE control.service_runs SET publisher_expires_at=$2,serving_until=$2 WHERE id=$1`,
						f.run.RunID, now.Add(time.Second+time.Duration(index)*500*time.Millisecond)); err != nil {
						t.Fatal(err)
					}
				}
			}
			assertRestoredAssignmentState(t, ctx, d.pool, 10)
			var mutationGateKey string
			if cleanup {
				mutationGateKey = installRestoredAssignmentMutationGate(t, ctx, d, fixtures[1].run.RunID)
			}
			gate, err := d.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if cleanup {
				// expiration commits each run separately. pause the second
				// candidate after its actual reservation update; the first
				// candidate's release must already be externally visible.
				if _, err := gate.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::text,0))`, mutationGateKey); err != nil {
					t.Fatal(err)
				}
			} else {
				gatedSlot := 0
				var locked string
				if err := gate.QueryRow(ctx, `SELECT publisher_connection_id FROM control.service_connection_slots
					WHERE service_run_id=$1 AND connection_slot=$2 FOR UPDATE`, fixtures[1].run.RunID, gatedSlot).Scan(&locked); err != nil {
					t.Fatal(err)
				}
			}
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			bulkDone, singleDone := make(chan error, 1), make(chan error, 1)
			bulkIDs := []string{fixtures[0].run.RunID, fixtures[1].run.RunID}
			workers.Go(func() {
				var err error
				if cleanup {
					var closed int
					closed, err = d.ExpireServiceRuns(ctx, now.Add(2*time.Second))
					if err == nil && closed != 2 {
						err = fmt.Errorf("ephemeral serving expiration closed %d, want 2", closed)
					}
				} else {
					err = d.RemoveMembership(ctx, topology.owner, topology.member.TeamID, topology.member.ID, now)
				}
				if err == nil {
					var closed int
					err = d.pool.QueryRow(ctx, `SELECT count(*) FROM control.service_runs
						WHERE id=ANY($1::text[]) AND state='closed' AND closed_at IS NOT NULL AND NOT assignments_open`,
						bulkIDs).Scan(&closed)
					if err == nil && closed != 2 {
						err = fmt.Errorf("bulk operation durably closed %d selected runs, want 2", closed)
					}
				}
				bulkDone <- err
			})
			bulkPID := waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), bulkDone)
			assertRestoredAssignmentGuard(t, ctx, d, bulkPID, true)
			blockedTotal := int64(10)
			if cleanup {
				blockedTotal = 8
			}
			assertRestoredAssignmentState(t, ctx, d.pool, blockedTotal)
			workers.Go(func() {
				f := fixtures[2]
				singleDone <- d.CloseServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, now)
			})
			singlePID := waitForPostgresBlock(t, ctx, d, bulkPID, singleDone)
			assertRestoredAssignmentGuard(t, ctx, d, singlePID, false)
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			bulkErr := awaitIntegrationResult(t, ctx, bulkDone)
			singleErr := awaitIntegrationResult(t, ctx, singleDone)
			if err := errors.Join(bulkErr, singleErr); err != nil {
				t.Fatal(err)
			}
			for index, f := range fixtures {
				var closed bool
				if err := d.pool.QueryRow(ctx, `SELECT state='closed' AND closed_at IS NOT NULL AND NOT assignments_open
					FROM control.service_runs WHERE id=$1`, f.run.RunID).Scan(&closed); err != nil || closed != (index < 3) {
					t.Fatal("bulk/single closure changed an unintended run", index, closed, err)
				}
			}
			assertRestoredAssignmentState(t, ctx, d.pool, 4)
		})
	}
}

type restoredAssignmentTopology struct {
	owner    string
	member   Membership
	fixtures []servicePublicationFixture
}

func newRestoredAssignmentTopology(t *testing.T) restoredAssignmentTopology {
	t.Helper()
	d, now, owner, team := newAuthorityTeam(t)
	_, member := allocationVisitorMember(t, d, team.ID, owner, "restored-assignment-member", TeamRoleAdmin, now)
	other, err := d.CreateTeam(t.Context(), CreateTeamRequest{
		IdentityID: owner, DisplayName: "assignment-progress", MemberSlug: "owner",
		IdempotencyKey: "restored-assignment-progress", RequestDigest: sha256.Sum256([]byte("restored-assignment-progress")),
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	leases := make(map[string]RelayLease)
	for index := range 2 {
		registration := relayLifecycleRegistration(fmt.Sprintf("restored-primary-%d", index))
		registration.ConnectionCapacity = 100
		lease, err := d.RegisterRelay(t.Context(), registration, now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		leases[lease.RelayServiceID] = lease
	}
	topology := restoredAssignmentTopology{owner: owner, member: member}
	for index := range 5 {
		teamID, actor := other.ID, owner
		if index < 2 {
			teamID, actor = team.ID, member.IdentityID
		}
		name := fmt.Sprintf("restored-assignment-%d", index)
		service, err := d.CreateServiceAt(t.Context(), teamID, actor, name, name, ServicePlacement{}, now,
			ServiceMetadata{}, &ProjectServiceConfiguration{Target: "localhost:3000"})
		if err != nil {
			t.Fatal(err)
		}
		authority, err := controlstatedb.New(d.pool).GetTeamActorContext(t.Context(),
			controlstatedb.GetTeamActorContextParams{TeamID: teamID, IdentityID: actor})
		if err != nil {
			t.Fatal(err)
		}
		enrollment, err := d.IssuePublisherEnrollment(t.Context(), CreatePublisherEnrollmentRequest{
			Scope: PublisherScope{TeamID: teamID, Kind: "service", ServiceID: service.ID}, Ownership: "member",
			Name: name, Kind: "installed", EditorID: actor, EditorMembershipID: authority.ActorMembershipID,
			PolicyRevision: uint64(authority.PolicyRevision), Now: now,
		})
		if err != nil {
			t.Fatal(err)
		}
		public, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		publisher, err := d.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, now)
		if err != nil {
			t.Fatal(err)
		}
		f := servicePublicationFixture{database: d, now: now, service: service, publisher: publisher, leases: leases}
		f.start(t, "initial", now)
		topology.fixtures = append(topology.fixtures, f)
	}
	return topology
}

func assertRestoredAssignmentState(t *testing.T, ctx context.Context, db controlstatedb.DBTX, want int64) {
	t.Helper()
	var mismatches, total, eligibilityDrift int64
	err := db.QueryRow(ctx, `WITH actual AS (
		SELECT slot.relay_service_id,count(*) AS assignments
		FROM control.service_connection_slots slot JOIN control.service_runs run ON run.id=slot.service_run_id
		WHERE run.closed_at IS NULL AND slot.state IN ('assigned','connected','ready')
		GROUP BY slot.relay_service_id
	) SELECT count(*) FILTER(WHERE reservation.reserved_slot_count IS DISTINCT FROM COALESCE(actual.assignments,0)),
		COALESCE(sum(reservation.reserved_slot_count),0)::bigint,
		(SELECT count(*) FROM control.service_connection_slots slot JOIN control.service_runs run ON run.id=slot.service_run_id
			WHERE slot.session_open IS DISTINCT FROM run.assignments_open)
	FROM control.relay_services service LEFT JOIN control.relay_service_reservations reservation USING(relay_service_id)
	LEFT JOIN actual USING(relay_service_id)`).Scan(&mismatches, &total, &eligibilityDrift)
	if err != nil || mismatches != 0 || total != want || eligibilityDrift != 0 {
		t.Fatalf("reservations mismatches=%d total=%d eligibility-drift=%d, want 0/%d/0: %v",
			mismatches, total, eligibilityDrift, want, err)
	}
}

func restoredAssignmentSnapshot(t *testing.T, ctx context.Context, db controlstatedb.DBTX, runID string) string {
	t.Helper()
	var snapshot string
	err := db.QueryRow(ctx, `SELECT jsonb_build_object(
		'run',to_jsonb(run),'next_run_number',service.next_run_number,
		'slots',(SELECT jsonb_agg(to_jsonb(slot) ORDER BY connection_slot)
			FROM control.service_connection_slots slot WHERE slot.service_run_id=run.id),
		'audit',(SELECT jsonb_agg(to_jsonb(event) ORDER BY cursor)
			FROM control.service_audit_events event WHERE event.run_id=run.id))::text
		FROM control.service_runs run JOIN control.services service ON service.id=run.service_id WHERE run.id=$1`,
		runID).Scan(&snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func installRestoredAssignmentMutationGate(t *testing.T, ctx context.Context, d *Database, runID string) string {
	t.Helper()
	key := "tnl:test:restored-assignment-mutation:" + runID
	// only this disposable database gets the test hook. its name orders it
	// after the real counter trigger; it acquires only the separate test key.
	if _, err := d.pool.Exec(ctx, `CREATE FUNCTION control.restored_assignment_mutation_gate()
		RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			PERFORM pg_advisory_xact_lock(hashtextextended(TG_ARGV[0],0));
			RETURN NULL;
		END; $$`); err != nil {
		t.Fatal(err)
	}
	var statement string
	if err := d.pool.QueryRow(ctx, `SELECT format(
		'CREATE TRIGGER zz_restored_assignment_mutation_gate
		 AFTER UPDATE OF session_open ON control.service_connection_slots
		 FOR EACH ROW WHEN (OLD.session_open AND NOT NEW.session_open
			AND OLD.state IN (''assigned'',''connected'',''ready'')
			AND NEW.service_run_id=%L)
		 EXECUTE FUNCTION control.restored_assignment_mutation_gate(%L)',
		$1::text,$2::text)`, runID, key).Scan(&statement); err != nil {
		t.Fatal(err)
	}
	if _, err := d.pool.Exec(ctx, statement); err != nil {
		t.Fatal(err)
	}
	return key
}

func assertRestoredAssignmentGuard(t *testing.T, ctx context.Context, d *Database, pid int32, granted bool) {
	t.Helper()
	var count int
	err := d.pool.QueryRow(ctx, `SELECT count(*) FROM pg_locks WHERE pid=$1 AND locktype='advisory'
		AND database=(SELECT oid FROM pg_database WHERE datname=current_database())
		AND mode='ExclusiveLock' AND granted=$2 AND objsubid=1
		AND classid=((hashtextextended('tnl:relay-assignment-totals',0)>>32)&4294967295)::oid
		AND objid=(hashtextextended('tnl:relay-assignment-totals',0)&4294967295)::oid`,
		pid, granted).Scan(&count)
	if err != nil || count != 1 {
		var snapshot string
		diagnosticErr := d.pool.QueryRow(ctx, `WITH subjects AS MATERIALIZED (
			SELECT activity.pid FROM pg_stat_activity activity
			WHERE activity.datname=current_database() AND (
				activity.pid=$1 OR activity.pid=ANY(pg_blocking_pids($1))
				OR $1=ANY(pg_blocking_pids(activity.pid)))
		) SELECT jsonb_build_object(
			'expected',jsonb_build_object(
				'database',(SELECT oid FROM pg_database WHERE datname=current_database()),
				'hash',hashtextextended('tnl:relay-assignment-totals',0),
				'classid',((hashtextextended('tnl:relay-assignment-totals',0)>>32)&4294967295)::oid,
				'objid',(hashtextextended('tnl:relay-assignment-totals',0)&4294967295)::oid,
				'objsubid',1,'mode','ExclusiveLock','granted',$2::boolean),
			'activity',(SELECT jsonb_agg(jsonb_build_object(
				'pid',activity.pid,'query',activity.query,'state',activity.state,
				'wait_event_type',activity.wait_event_type,'wait_event',activity.wait_event,
				'xact_start',activity.xact_start,'query_start',activity.query_start,
				'blockers',pg_blocking_pids(activity.pid)) ORDER BY activity.pid)
				FROM pg_stat_activity activity JOIN subjects USING(pid)),
			'locks',(SELECT jsonb_agg(to_jsonb(locks) ORDER BY
				locks.pid,locks.locktype,locks.database,locks.relation,locks.page,locks.tuple,
				locks.classid,locks.objid,locks.objsubid,locks.mode,locks.granted)
				FROM pg_locks locks JOIN subjects USING(pid)),
			'triggers',(SELECT jsonb_agg(jsonb_build_object(
				'relation',trigger_record.tgrelid::regclass::text,'name',trigger_record.tgname,
				'internal',trigger_record.tgisinternal,'deferrable',trigger_record.tgdeferrable,
				'initially_deferred',trigger_record.tginitdeferred,
				'definition',pg_get_triggerdef(trigger_record.oid,true)) ORDER BY trigger_record.tgrelid,trigger_record.tgname)
				FROM pg_trigger trigger_record WHERE trigger_record.tgrelid IN (
					'control.service_runs'::regclass,'control.service_connection_slots'::regclass)),
			'constraints',(SELECT jsonb_agg(jsonb_build_object(
				'relation',constraint_record.conrelid::regclass::text,'name',constraint_record.conname,
				'definition',pg_get_constraintdef(constraint_record.oid,true))
				ORDER BY constraint_record.conrelid,constraint_record.conname)
				FROM pg_constraint constraint_record WHERE constraint_record.conrelid IN (
					'control.service_runs'::regclass,'control.service_connection_slots'::regclass)),
			'functions',(SELECT jsonb_agg(pg_get_functiondef(function_record.oid) ORDER BY function_record.proname)
				FROM pg_proc function_record WHERE function_record.pronamespace='control'::regnamespace
					AND function_record.proname IN (
						'update_relay_assignment_totals','audit_service_run','append_service_audit'))
		)::text`, pid, granted).Scan(&snapshot)
		if diagnosticErr != nil {
			t.Log("reservation guard diagnostics failed within the existing caller", diagnosticErr)
		} else {
			t.Log("reservation guard wait snapshot", snapshot)
		}
		t.Fatal("wait graph did not use the actual reservation guard", pid, granted, count, err)
	}
}

func requireRestoredPostgresFailure(t *testing.T, err error, code, constraint, detail string) {
	t.Helper()
	var failure *pgconn.PgError
	if !errors.As(err, &failure) || failure.Code != code || failure.ConstraintName != constraint ||
		detail != "" && failure.Detail != detail {
		t.Fatalf("selected PostgreSQL failure code=%s constraint=%s detail=%q: %v", code, constraint, detail, err)
	}
	requireRestoredOnlyError(t, err, failure)
}

func requireRestoredOnlyError(t *testing.T, err, expected error) {
	t.Helper()
	if err == nil || !errors.Is(err, expected) {
		t.Fatalf("expected %v: %v", expected, err)
	}
	var inspect func(error)
	inspect = func(cause error) {
		if cause == nil || cause == expected {
			return
		}
		if joined, ok := cause.(interface{ Unwrap() []error }); ok {
			for _, child := range joined.Unwrap() {
				inspect(child)
			}
		} else if wrapped, ok := cause.(interface{ Unwrap() error }); ok {
			inspect(wrapped.Unwrap())
		} else {
			t.Errorf("expected failure also retained an independent cause: %v; complete error: %v", cause, err)
		}
	}
	inspect(err)
}
