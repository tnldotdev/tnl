package state

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationExpirationProgressRestoredBusyAuthorityWriter(t *testing.T) {
	for _, phase := range []string{"held-writer", "queued-writer", "team-row"} {
		t.Run(phase, func(t *testing.T) {
			busy := newServicePublicationFixture(t)
			other := newRestorationOtherTeamPublication(t, busy, "expiry-writer", busy.now)
			other.start(t, "first", busy.now.Add(time.Second))
			setExpirationProgressServingDeadline(t, &busy, busy.run.ExpiresAt)
			setExpirationProgressServingDeadline(t, &other, other.run.ExpiresAt)
			d, at, actor := busy.database, other.run.ServingUntil, busy.actor(t)
			if busy.service.TeamID == other.service.TeamID || !busy.run.ServingUntil.Before(at) {
				t.Fatal("authority contrast needs an older run under a different owner")
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			gate, err := d.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			switch phase {
			case "held-writer":
				_, err = controlstatedb.New(gate).LockLocalTeamForMutation(ctx, busy.service.TeamID)
			case "queued-writer":
				_, err = controlstatedb.New(gate).LockLocalTeamForSession(ctx, busy.service.TeamID)
			case "team-row":
				_, err = gate.Exec(ctx, `SELECT id FROM control.teams WHERE id=$1 FOR NO KEY UPDATE`, busy.service.TeamID)
			}
			if err != nil {
				t.Fatal(err)
			}
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			written := make(chan error, 1)
			if phase == "queued-writer" {
				workers.Go(func() {
					_, err := d.CreateServiceAt(ctx, busy.service.TeamID, actor, "writer", "writer", ServicePlacement{},
						busy.now, ServiceMetadata{Protocol: "tcp"}, nil)
					written <- err
				})
				waitForExpirationProgressAdvisory(t, ctx, d, int32(gate.Conn().PgConn().PID()),
					"ShareLock", "ExclusiveLock", "tnl:local-team:"+busy.service.TeamID,
					"-- name: LockLocalTeamForMutation", written)
			}
			before := expirationProgressSnapshot(t, ctx, d, busy.run.RunID)
			if count, err := d.ExpireServiceRuns(ctx, at); err != nil || count != 1 {
				t.Fatal("busy authority prevented another owner's committed expiry", count, err)
			}
			if after := expirationProgressSnapshot(t, ctx, d, busy.run.RunID); after != before {
				t.Fatal("cleanup bypassed the busy authority writer or its queue")
			}
			assertExpirationProgressClosed(t, ctx, d, other.run.RunID)
			assertAssignmentTotals(t, d.pool, 2)
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if phase == "queued-writer" {
				if err := awaitIntegrationResult(t, ctx, written); err != nil {
					t.Fatal("queued authority writer did not finish", err)
				}
			}
			if count, err := d.ExpireServiceRuns(ctx, at); err != nil || count != 1 {
				t.Fatal("released owner did not close within the original five-second caller", count, err)
			}
			assertExpirationProgressClosed(t, ctx, d, busy.run.RunID)
			assertAssignmentTotals(t, d.pool, 0)
		})
	}
}

func TestIntegrationExpirationProgressRestoredOwnerFilledBatch(t *testing.T) {
	busy := newServicePublicationFixture(t)
	d := busy.database
	setExpirationProgressServingDeadline(t, &busy, busy.run.ExpiresAt)
	// real preparations need no extra relay capacity. together with the initial
	// started run, this owner has 101 older candidates, not copied SQL grants.
	for index := range 100 {
		sibling := busy.sibling(t, fmt.Sprintf("batch-%03d", index), busy.now)
		if _, err := d.PrepareServiceRun(t.Context(), sibling.service.ID, sibling.publisher, "first", busy.now,
			ServiceRunRequest{Metadata: sibling.service.ServiceMetadata}); err != nil {
			t.Fatal(err)
		}
	}
	other := newRestorationOtherTeamPublication(t, busy, "expiry-batch", busy.now)
	other.start(t, "first", busy.now.Add(3*time.Minute))
	setExpirationProgressServingDeadline(t, &other, other.run.ExpiresAt)
	at := other.run.ServingUntil
	var earlier int
	if err := d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.service_runs
		WHERE team_id=$1 AND closed_at IS NULL
			AND (serving_until<$2 OR state='prepared' AND preparation_expires_at<$2)`,
		busy.service.TeamID, at).Scan(&earlier); err != nil || earlier != 101 {
		t.Fatal("fixture did not fill the old global candidate limit with one owner", earlier, err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	gate, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := controlstatedb.New(gate).LockLocalTeamForMutation(ctx, busy.service.TeamID); err != nil {
		t.Fatal(err)
	}
	if count, err := d.ExpireServiceRuns(ctx, at); err != nil || count != 1 {
		t.Fatal("one owner's first hundred busy runs hid the other owner", count, err)
	}
	assertExpirationProgressClosed(t, ctx, d, other.run.RunID)
	var open int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.service_runs WHERE team_id=$1 AND closed_at IS NULL`,
		busy.service.TeamID).Scan(&open); err != nil || open != 101 {
		t.Fatal("busy owner was mutated during the owner-diverse pass", open, err)
	}
	assertAssignmentTotals(t, d.pool, 2)
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	// all later passes reuse the same caller. one available owner can make
	// multiple closures, but no pass may attempt more than the original 100.
	if count, err := d.ExpireServiceRuns(ctx, at); err != nil || count != 100 {
		t.Fatal("released owner did not make bounded multi-run progress", count, err)
	}
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.service_runs WHERE team_id=$1 AND closed_at IS NULL`,
		busy.service.TeamID).Scan(&open); err != nil || open != 1 {
		t.Fatal("expiration drained beyond its single-pass candidate bound", open, err)
	}
	if count, err := d.ExpireServiceRuns(ctx, at); err != nil || count != 1 {
		t.Fatal("bounded remainder did not close within the same five-second caller", count, err)
	}
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.service_audit_events
		WHERE team_id=$1 AND event_type='run.close'`, busy.service.TeamID).Scan(&open); err != nil || open != 101 {
		t.Fatal("bounded closure lost or duplicated run audit events", open, err)
	}
	assertAssignmentTotals(t, d.pool, 0)
}

func TestIntegrationExpirationProgressRestoredRenewedCandidate(t *testing.T) {
	first := newServicePublicationFixture(t)
	renewed := first.sibling(t, "expiry-renewed", first.now)
	renewed.start(t, "first", first.now.Add(time.Second))
	setExpirationProgressServingDeadline(t, &first, first.run.ExpiresAt)
	setExpirationProgressServingDeadline(t, &renewed, renewed.run.ExpiresAt)
	d, at := first.database, renewed.run.ServingUntil
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	gate, key := newExpirationProgressCloseGate(t, ctx, d, first.run.RunID)
	defer rollbackTestTransaction(t, gate)
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	done := make(chan error, 1)
	workers.Go(func() {
		count, err := d.ExpireServiceRuns(ctx, at)
		if err == nil && count != 1 {
			err = errors.New("stale discovery closed the concurrently renewed candidate")
		}
		done <- err
	})
	// both runs were expired at discovery. the first actual closure cannot
	// reach this exact-run hook until discovery has finished and its own
	// owner/service/run locks are held.
	waitForExpirationProgressAdvisory(t, ctx, d, int32(gate.Conn().PgConn().PID()),
		"ExclusiveLock", "ExclusiveLock", key, "-- name: CloseServiceRun", done)
	current, err := d.HeartbeatServiceRun(ctx, renewed.service.ID, renewed.run.RunID, renewed.run.Token,
		first.now.Add(30*time.Second), ServiceRunHealth{Healthy: true, StreamCapacity: 64})
	if err != nil || current.RunID != renewed.run.RunID || current.RunNumber != renewed.run.RunNumber ||
		!current.ExpiresAt.After(at) || !current.ServingUntil.After(at) {
		t.Fatal("real heartbeat did not renew the exact discovered candidate", err)
	}
	before := expirationProgressSnapshot(t, ctx, d, renewed.run.RunID)
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, done); err != nil {
		t.Fatal(err)
	}
	if after := expirationProgressSnapshot(t, ctx, d, renewed.run.RunID); after != before {
		t.Fatal("expiration changed current authority using a stale discovery deadline")
	}
	assertExpirationProgressClosed(t, ctx, d, first.run.RunID)
	assertAssignmentTotals(t, d.pool, 2)
	if count, err := d.ExpireServiceRuns(ctx, current.ServingUntil); err != nil || count != 1 {
		t.Fatal("renewed run could not later close at its actual current deadline", count, err)
	}
	assertExpirationProgressClosed(t, ctx, d, renewed.run.RunID)
	assertAssignmentTotals(t, d.pool, 0)
}

// keep the original expiry workload and caller bounds while making its serving
// authority explicit. publisher liveness remains a separate persisted deadline.
func setExpirationProgressServingDeadline(t *testing.T, f *servicePublicationFixture, until time.Time) {
	t.Helper()
	if !until.After(f.run.ObservedAt) || until.After(f.run.ServingUntil) {
		t.Fatal("expiration fixture needs a finite shortened serving interval")
	}
	updated, err := f.database.pool.Exec(t.Context(), `UPDATE control.service_runs
		SET serving_until=$2 WHERE id=$1 AND serving_observed_at=$3 AND serving_until=$4`,
		f.run.RunID, until, f.run.ObservedAt, f.run.ServingUntil)
	if err != nil || updated.RowsAffected() != 1 {
		t.Fatal("did not set the exact run's serving deadline", updated.RowsAffected(), err)
	}
	f.run.ServingUntil = until
}

// the disposable database owns this exact-run pause. the gate holds only a
// separate test advisory key, never a placement lock.
func newExpirationProgressCloseGate(t *testing.T, ctx context.Context, d *Database, runID string) (pgx.Tx, string) {
	t.Helper()
	if _, err := d.pool.Exec(ctx, `CREATE TABLE control.expiry_progress_test_runs(id text PRIMARY KEY);
		CREATE FUNCTION control.expiry_progress_pause() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF EXISTS(SELECT 1 FROM control.expiry_progress_test_runs WHERE id=NEW.id) THEN
				PERFORM pg_advisory_xact_lock(hashtextextended('tnl:test:expiry-progress:' || NEW.id,0));
			END IF;
			RETURN NEW;
		END $$;
		CREATE TRIGGER expiry_progress_pause AFTER UPDATE OF closed_at ON control.service_runs
		FOR EACH ROW WHEN (OLD.closed_at IS NULL AND NEW.closed_at IS NOT NULL)
		EXECUTE FUNCTION control.expiry_progress_pause()`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.pool.Exec(ctx, `INSERT INTO control.expiry_progress_test_runs(id) VALUES($1)`, runID); err != nil {
		t.Fatal(err)
	}
	gate, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	key := "tnl:test:expiry-progress:" + runID
	if _, err := gate.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::text,0))`, key); err != nil {
		rollbackTestTransaction(t, gate)
		t.Fatal(err)
	}
	return gate, key
}

// verify the actual blocked query, wait event, blocker edge and both full
// one-bigint advisory identities in this database, not just a blocker PID.
func waitForExpirationProgressAdvisory(t *testing.T, ctx context.Context, d *Database, holder int32,
	holderMode, waiterMode, key, query string, done <-chan error) int32 {
	t.Helper()
	pid := waitForPostgresBlock(t, ctx, d, holder, done)
	var statement, waitType, waitEvent, blockers, locks string
	var held, waiting bool
	err := d.pool.QueryRow(ctx, `SELECT activity.query,activity.wait_event_type,activity.wait_event,
		pg_blocking_pids(activity.pid)::text,
		(SELECT jsonb_agg(jsonb_build_object('pid',pid,'locktype',locktype,'database',database,
			'classid',classid,'objid',objid,'objsubid',objsubid,'mode',mode,'granted',granted,
			'relation',relation,'page',page,'tuple',tuple,'transactionid',transactionid,'virtualxid',virtualxid))::text
		 FROM pg_locks WHERE pid IN($1,$2) AND locktype IN('advisory','transactionid','tuple')),
		EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND granted AND mode=$3
			AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND objsubid=1
			AND classid=((hashtextextended($5::text,0)>>32)&4294967295)::oid
			AND objid=(hashtextextended($5::text,0)&4294967295)::oid),
		EXISTS(SELECT 1 FROM pg_locks WHERE pid=$2 AND locktype='advisory' AND NOT granted AND mode=$4
			AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND objsubid=1
			AND classid=((hashtextextended($5::text,0)>>32)&4294967295)::oid
			AND objid=(hashtextextended($5::text,0)&4294967295)::oid)
		FROM pg_stat_activity activity WHERE activity.pid=$2`, holder, pid, holderMode, waiterMode, key).
		Scan(&statement, &waitType, &waitEvent, &blockers, &locks, &held, &waiting)
	if err != nil {
		t.Fatal("read full expiration wait tuples", err)
	}
	t.Logf("expiry wait holder=%d waiter=%d blockers=%s event=%s/%s query=%q locks=%s",
		holder, pid, blockers, waitType, waitEvent, statement, locks)
	if !strings.Contains(statement, query) || waitType != "Lock" || waitEvent != "advisory" || !held || !waiting {
		t.Fatal("expiration wait did not match the exact query and full advisory identities")
	}
	return pid
}

func expirationProgressSnapshot(t *testing.T, ctx context.Context, d *Database, runID string) string {
	t.Helper()
	var snapshot string
	if err := d.pool.QueryRow(ctx, `SELECT jsonb_build_object(
		'id',run.id,'number',run.run_number,'state',run.state,'closed',run.closed_at,
		'publisher_expiry',run.publisher_expires_at,'preparation_expiry',run.preparation_expires_at,
		'serving_observed_at',run.serving_observed_at,'serving_until',run.serving_until,
		'assignments_open',run.assignments_open,
		'slots',(SELECT jsonb_agg(jsonb_build_array(connection_slot,publisher_connection_id,
			connection_assignment_revision,state,session_open) ORDER BY connection_slot)
			FROM control.service_connection_slots WHERE service_run_id=run.id),
		'closures',(SELECT count(*) FROM control.service_audit_events WHERE run_id=run.id AND event_type='run.close'),
		'episodes',(SELECT jsonb_agg(jsonb_build_array(id,state,canceled_at,observed_at) ORDER BY id)
			FROM control.service_recovery_episodes WHERE service_run_id=run.id))::text
		FROM control.service_runs run WHERE run.id=$1`, runID).Scan(&snapshot); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func assertExpirationProgressClosed(t *testing.T, ctx context.Context, d *Database, runID string) {
	t.Helper()
	var closed bool
	if err := d.pool.QueryRow(ctx, `SELECT state='closed' AND closed_at>=publisher_expires_at
		AND closed_at>=serving_until AND NOT assignments_open
		AND NOT EXISTS(SELECT 1 FROM control.service_connection_slots WHERE service_run_id=run.id AND session_open)
		AND NOT EXISTS(SELECT 1 FROM control.service_recovery_episodes WHERE service_run_id=run.id AND state='open')
		AND (SELECT count(*)=1 FROM control.service_audit_events WHERE run_id=run.id AND event_type='run.close')
		FROM control.service_runs run WHERE run.id=$1`, runID).Scan(&closed); err != nil || !closed {
		t.Fatal("expiry did not durably close exact run, slots and audit once", closed, err)
	}
}
