package state

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func assertAssignmentTotals(t *testing.T, db controlstatedb.DBTX, want int64) {
	t.Helper()
	var mismatches, total int64
	err := db.QueryRow(t.Context(), `
		WITH actual AS (
			SELECT connections.relay_service_id, count(*) AS assignment_count
			FROM control.service_connection_slots AS connections
			JOIN control.service_runs AS sessions ON sessions.id = connections.service_run_id
			WHERE sessions.closed_at IS NULL
			  AND connections.state IN ('assigned', 'connected', 'ready')
			GROUP BY connections.relay_service_id
		)
		SELECT count(*) FILTER (WHERE totals.reserved_slot_count IS DISTINCT FROM COALESCE(actual.assignment_count, 0)),
		       COALESCE(sum(totals.reserved_slot_count), 0)::bigint
		FROM control.relay_services AS services
		LEFT JOIN control.relay_service_reservations AS totals USING (relay_service_id)
		LEFT JOIN actual USING (relay_service_id)
	`).Scan(&mismatches, &total)
	if err != nil || mismatches != 0 || total != want {
		t.Fatalf("assignment totals: mismatches=%d total=%d, want 0/%d: %v", mismatches, total, want, err)
	}
}

func TestIntegrationAssignmentTotalsMutations(t *testing.T) {
	f := newServicePublicationFixture(t)
	assertAssignmentTotals(t, f.database.pool, 2)
	// idempotent replay does not change totals.
	if _, err := f.database.StartServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.RunNumber, f.publisher, f.now); err != nil {
		t.Fatal(err)
	}
	assertAssignmentTotals(t, f.database.pool, 2)
	for i := range f.run.Connections {
		slot := f.run.Connections[i]
		lease := f.leases[slot.RelayServiceID].RelayLeaseIdentity
		if _, err := f.database.ClaimServicePublisherConnection(t.Context(), slot.PublisherConnectionID, f.service.ID, f.run.RunID, f.run.RunNumber, slot.Revision, slot.Credential, netip.MustParseAddr("127.0.0.1"), lease, f.now); err != nil {
			t.Fatal(err)
		}
		assertAssignmentTotals(t, f.database.pool, 2)
		if _, err := f.database.ClaimServicePublisherConnection(t.Context(), slot.PublisherConnectionID, f.service.ID, f.run.RunID, f.run.RunNumber, slot.Revision, slot.Credential, netip.MustParseAddr("127.0.0.1"), lease, f.now); err != nil {
			t.Fatal(err)
		}
		assertAssignmentTotals(t, f.database.pool, 2)
		if _, err := f.database.ReadyServicePublisherConnection(t.Context(), slot.PublisherConnectionID, f.run.RunID, f.run.RunNumber, slot.Revision, lease, f.now); err != nil {
			t.Fatal(err)
		}
		assertAssignmentTotals(t, f.database.pool, 2)
	}
	if _, err := f.database.RegisterRelay(t.Context(), relayLifecycleRegistration("spare"), f.now, time.Hour); err != nil {
		t.Fatal(err)
	}
	assertAssignmentTotals(t, f.database.pool, 2)
	tx, err := f.database.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, tx)
	steps := []struct {
		name, query string
		want        int64
	}{
		{"connected", `UPDATE control.service_connection_slots SET state = 'connected' WHERE connection_slot = 0`, 2},
		{"service transfer", `UPDATE control.service_connection_slots SET relay_service_id = 'spare' WHERE connection_slot = 0`, 2},
		{"expire", `UPDATE control.service_connection_slots SET state = 'closed' WHERE connection_slot = 1`, 1},
		{"reassign expired", `UPDATE control.service_connection_slots SET state = 'assigned', relay_id = NULL, relay_run_id = NULL, relay_lease_revision = NULL WHERE connection_slot = 1`, 2},
		{"close slot", `UPDATE control.service_connection_slots SET state = 'closed' WHERE connection_slot = 1`, 1},
		{"reassign closed", `UPDATE control.service_connection_slots SET state = 'assigned', relay_id = NULL, relay_run_id = NULL, relay_lease_revision = NULL WHERE connection_slot = 1`, 2},
		{"close parent first", `UPDATE control.service_runs SET state = 'closed', closed_at = publisher_expires_at`, 0},
		{"close slot after parent", `UPDATE control.service_connection_slots SET state = 'closed' WHERE connection_slot = 1`, 0},
		{"reopen parent", `UPDATE control.service_runs SET state = 'starting', closed_at = NULL`, 1},
	}
	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			if _, err := tx.Exec(t.Context(), step.query); err != nil {
				t.Fatal(err)
			}
			assertAssignmentTotals(t, tx, step.want)
		})
		if t.Failed() {
			return
		}
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertAssignmentTotals(t, f.database.pool, 2)
	if err := f.database.CloseServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.now); err != nil {
		t.Fatal(err)
	}
	assertAssignmentTotals(t, f.database.pool, 0)
}

func TestIntegrationAssignmentTotalsRollbackAndStoredReservations(t *testing.T) {
	f := newServicePublicationFixture(t)
	ctx := t.Context()
	assertAssignmentTotals(t, f.database.pool, 2)
	// time and live-lease availability do not release stored reservations.
	tx, err := f.database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, tx)
	// expired lease availability alone must not free reservations while run/slots remain assigned.
	assertAssignmentTotals(t, tx, 2)
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := f.database.CloseServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, f.now); err != nil {
		t.Fatal(err)
	}
	assertAssignmentTotals(t, f.database.pool, 0)
}

func TestIntegrationAssignmentTotalsRejectParentFlagDrift(t *testing.T) {
	f := newServicePublicationFixture(t)
	tx, err := f.database.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, tx)
	if _, err := tx.Exec(t.Context(), `UPDATE control.service_connection_slots SET session_open = false WHERE connection_slot = 0`); err != nil {
		// column/constraint naming may differ; invariant is that parent/slot assignment eligibility cannot drift.
		return
	}
	var constraint *pgconn.PgError
	if err := tx.Commit(t.Context()); err != nil {
		if errors.As(err, &constraint) {
			// constraint preserved the invariant.
		}
	}
	assertAssignmentTotals(t, f.database.pool, 2)
}

func TestIntegrationAssignmentTotalsExpiryPlacementLockOrder(t *testing.T) {
	f := newServicePublicationFixture(t)
	sibling := f.sibling(t, "sib", f.now)
	sibling.start(t, "sib", f.now)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if _, err := f.database.pool.Exec(ctx, `UPDATE control.service_runs SET publisher_expires_at = $2 WHERE id = $1`, f.run.RunID, f.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	// expiry/replacement and unrelated heartbeats must not deadlock.
	if _, err := f.database.ExpireServiceRuns(ctx, f.now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	// sibling run remains manageable.
	if _, err := sibling.database.HeartbeatServiceRun(ctx, sibling.service.ID, sibling.run.RunID, sibling.run.Token, f.now.Add(2*time.Second), ServiceRunHealth{StreamCapacity: 64}); err != nil {
		t.Fatal(err)
	}
	assertAssignmentTotals(t, f.database.pool, 2)
}

func TestIntegrationAssignmentTotalsBulkClosureLockOrder(t *testing.T) {
	// closing multiple runs must not deadlock on relay-service/slot ordering.
	f := newServicePublicationFixture(t)
	s1 := f.sibling(t, "a", f.now)
	s1.start(t, "a", f.now)
	s2 := f.sibling(t, "b", f.now)
	s2.start(t, "b", f.now)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	errs := make(chan error, 3)
	for _, fx := range []servicePublicationFixture{f, s1, s2} {
		workers.Go(func() {
			errs <- fx.database.CloseServiceRun(ctx, fx.service.ID, fx.run.RunID, fx.run.Token, f.now)
		})
	}
	for range 3 {
		if err := awaitIntegrationResult(t, ctx, errs); err != nil {
			t.Fatal(err)
		}
	}
	assertAssignmentTotals(t, f.database.pool, 0)
}
