package state

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/failure"
)

func TestServiceStartReclamationRestorationCapacityErrorTree(t *testing.T) {
	capacity := fmt.Errorf("%w: %w", ErrInsufficientRelayServices, errRelayPlacementCapacity)
	independent := errors.New("independent rollback failure")
	for _, test := range []struct {
		name string
		err  error
		want bool
	}{
		{"exact-capacity", capacity, true},
		{"wrapped-capacity", fmt.Errorf("placement: %w", capacity), true},
		{"missing-capacity", ErrInsufficientRelayServices, false},
		{"missing-insufficient", errRelayPlacementCapacity, false},
		{"rollback", errors.Join(capacity, independent), false},
		{"sql", errors.Join(capacity, &pgconn.PgError{Code: "23514"}), false},
		{"canceled", errors.Join(capacity, context.Canceled), false},
		{"duplicate-cause", errors.Join(capacity, errRelayPlacementCapacity), false},
		{"nil", nil, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := serviceRunCapacityOnly(test.err); got != test.want {
				t.Fatal("capacity classification ignored an independent or missing cause", got, test.want)
			}
		})
	}
}

func TestIntegrationServiceStartReclamationRestoredDeniedCallerDoesNotClean(t *testing.T) {
	for _, denial := range []string{"wrong-key", "stale-number", "revoked-grant", "expired-preparation"} {
		t.Run(denial, func(t *testing.T) {
			old, requested := newStartReclamationFixture(t)
			d, at := old.database, old.run.ExpiresAt
			publisher, number := requested.publisher, requested.prepared.RunNumber
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			switch denial {
			case "wrong-key":
				publisher.KeyID = old.publisher.KeyID
			case "stale-number":
				number++
			case "revoked-grant":
				if err := d.RevokePublisherGrant(ctx, requested.service.TeamID, publisher.ID, publisher.GrantID,
					old.actor(t), old.now.Add(time.Second)); err != nil {
					t.Fatal(err)
				}
			case "expired-preparation":
				at = requested.prepared.ExpiresAt
			}
			beforeOld := expirationProgressSnapshot(t, ctx, d, old.run.RunID)
			beforeRequested := expirationProgressSnapshot(t, ctx, d, requested.prepared.RunID)
			if _, err := d.StartServiceRun(ctx, requested.service.ID, requested.prepared.RunID, number, publisher, at); !failure.Only(err, ErrServiceAccess) {
				t.Fatal("unauthorized or stale caller did not fail before reclamation", err)
			}
			if expirationProgressSnapshot(t, ctx, d, old.run.RunID) != beforeOld ||
				expirationProgressSnapshot(t, ctx, d, requested.prepared.RunID) != beforeRequested {
				t.Fatal("denied caller changed its preparation or another owner's expired run")
			}
			assertAssignmentTotals(t, d.pool, 2)
		})
	}
}

func TestIntegrationServiceStartReclamationRestoredBusyCandidate(t *testing.T) {
	old, requested := newStartReclamationFixture(t)
	d, at := old.database, old.run.ExpiresAt
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	gate, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if err := lockServiceOwner(ctx, gate, old.service.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := gate.Exec(ctx, `SELECT id FROM control.services WHERE id=$1 FOR UPDATE`, old.service.ID); err != nil {
		t.Fatal(err)
	}
	beforeOld := expirationProgressSnapshot(t, ctx, d, old.run.RunID)
	beforeRequested := expirationProgressSnapshot(t, ctx, d, requested.prepared.RunID)
	_, err = d.StartServiceRun(ctx, requested.service.ID, requested.prepared.RunID,
		requested.prepared.RunNumber, requested.publisher, at)
	insufficient, capacity, independent := startReclamationErrorLeaves(err)
	if insufficient != 1 || capacity != 1 || len(independent) != 0 {
		t.Fatal("busy cleanup did not return the isolated capacity denial within its caller", err)
	}
	if expirationProgressSnapshot(t, ctx, d, old.run.RunID) != beforeOld ||
		expirationProgressSnapshot(t, ctx, d, requested.prepared.RunID) != beforeRequested {
		t.Fatal("busy reclamation retained a closure, partial slots or start mutation")
	}
	assertAssignmentTotals(t, d.pool, 2)
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	started, err := d.StartServiceRun(ctx, requested.service.ID, requested.prepared.RunID,
		requested.prepared.RunNumber, requested.publisher, at)
	if err != nil {
		t.Fatal("released candidate did not permit a later start within the same five-second caller", err)
	}
	assertStartReclamationRun(t, ctx, d, requested, started, at)
	assertExpirationProgressClosed(t, ctx, d, old.run.RunID)
	assertAssignmentTotals(t, d.pool, 2)
}

func TestIntegrationServiceStartReclamationRestoredExpiredFirstAttemptDoesNotClean(t *testing.T) {
	old, requested := newStartReclamationFixture(t)
	d, at := old.database, old.run.ExpiresAt
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if _, err := d.pool.Exec(ctx, `UPDATE control.service_runs SET preparation_expires_at=$2 WHERE id=$1`,
		requested.prepared.RunID, at.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	gate, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	key := "tnl:relay-assignment-totals"
	if _, err := gate.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::text,0))`, key); err != nil {
		t.Fatal(err)
	}
	beforeOld := expirationProgressSnapshot(t, ctx, d, old.run.RunID)
	beforeRequested := expirationProgressSnapshot(t, ctx, d, requested.prepared.RunID)
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	done, entered := make(chan error, 1), make(chan time.Time, 1)
	workers.Go(func() {
		entered <- time.Now()
		_, err := d.StartServiceRun(ctx, requested.service.ID, requested.prepared.RunID,
			requested.prepared.RunNumber, requested.publisher, at)
		done <- err
	})
	waitForExpirationProgressAdvisory(t, ctx, d, int32(gate.Conn().PgConn().PID()),
		"ExclusiveLock", "ExclusiveLock", key, "-- name: LockRelayServicesForPlacement", done)
	entry := awaitIntegrationResult(t, ctx, entered)
	// the wait phase is established. spend this preparation's known deadline.
	timer := time.NewTimer(max(0, time.Until(entry.Add(1100*time.Millisecond))))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	err = awaitIntegrationResult(t, ctx, done)
	insufficient, capacity, independent := startReclamationErrorLeaves(err)
	if insufficient != 1 || capacity != 1 || len(independent) != 1 || independent[0] != ErrServiceAccess {
		t.Fatal("expired first attempt lost its capacity/authority causes or entered cleanup", err)
	}
	if expirationProgressSnapshot(t, ctx, d, old.run.RunID) != beforeOld ||
		expirationProgressSnapshot(t, ctx, d, requested.prepared.RunID) != beforeRequested {
		t.Fatal("placement wait refreshed expired authority or triggered cross-owner cleanup")
	}
	assertAssignmentTotals(t, d.pool, 2)
}

func TestIntegrationServiceStartReclamationRestoredRetryClockAndAuthority(t *testing.T) {
	for _, outcome := range []string{"same-preparation", "preparation-expired", "revoked-grant"} {
		t.Run(outcome, func(t *testing.T) {
			old, requested := newStartReclamationFixture(t)
			d, at := old.database, old.run.ExpiresAt
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			if outcome == "preparation-expired" {
				if _, err := d.pool.Exec(ctx, `UPDATE control.service_runs SET preparation_expires_at=$2 WHERE id=$1`,
					requested.prepared.RunID, at.Add(time.Second)); err != nil {
					t.Fatal(err)
				}
			}
			before := expirationProgressSnapshot(t, ctx, d, requested.prepared.RunID)
			gate, key := newExpirationProgressCloseGate(t, ctx, d, old.run.RunID)
			defer rollbackTestTransaction(t, gate)
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			done, entered := make(chan error, 1), make(chan time.Time, 1)
			var started ServiceRunState
			workers.Go(func() {
				entered <- time.Now()
				var err error
				started, err = d.StartServiceRun(ctx, requested.service.ID, requested.prepared.RunID,
					requested.prepared.RunNumber, requested.publisher, at)
				done <- err
			})
			waitForExpirationProgressAdvisory(t, ctx, d, int32(gate.Conn().PgConn().PID()),
				"ExclusiveLock", "ExclusiveLock", key, "-- name: CloseServiceRun", done)
			entry := awaitIntegrationResult(t, ctx, entered)
			// the first start has returned through rollback before this other
			// owner's actual close can reach the gate. it left no partial start.
			if expirationProgressSnapshot(t, ctx, d, requested.prepared.RunID) != before {
				t.Fatal("first capacity attempt retained changes before cross-owner cleanup")
			}
			if outcome == "preparation-expired" {
				// wait for a known authority deadline, not for an assumed lock
				// phase. the actual SQL wait was already proved above.
				timer := time.NewTimer(max(0, time.Until(entry.Add(1100*time.Millisecond))))
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			if outcome == "revoked-grant" {
				// a real requesting-team mutation must finish while cleanup
				// holds the other owner: no requesting lock crossed attempts.
				if err := d.RevokePublisherGrant(ctx, requested.service.TeamID, requested.publisher.ID,
					requested.publisher.GrantID, old.actor(t), at); err != nil {
					t.Fatal("first attempt retained its requesting-team authority locks", err)
				}
				before = expirationProgressSnapshot(t, ctx, d, requested.prepared.RunID)
			}
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			err := awaitIntegrationResult(t, ctx, done)
			if outcome == "same-preparation" {
				if err != nil {
					t.Fatal(err)
				}
				assertStartReclamationRun(t, ctx, d, requested, started, at)
				assertAssignmentTotals(t, d.pool, 2)
			} else {
				if !failure.Only(err, ErrServiceAccess) {
					t.Fatal("retry reset its clock or reused revoked publisher authority", err)
				}
				if expirationProgressSnapshot(t, ctx, d, requested.prepared.RunID) != before {
					t.Fatal("denied retry retained a start mutation after cleanup")
				}
				assertAssignmentTotals(t, d.pool, 0)
			}
			assertExpirationProgressClosed(t, ctx, d, old.run.RunID)
		})
	}
}

func TestIntegrationServiceStartReclamationRestoredFailures(t *testing.T) {
	for _, fault := range []string{"cleanup-sql", "cleanup-rollback", "retry-start-audit"} {
		t.Run(fault, func(t *testing.T) {
			old, requested := newStartReclamationFixture(t)
			d, at := old.database, old.run.ExpiresAt
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			event, action := "run.close", `RAISE EXCEPTION 'reclamation SQL fault' USING ERRCODE='23514',CONSTRAINT='reclamation_fault';`
			if fault == "cleanup-rollback" {
				// this backend belongs only to this disposable test database.
				// termination makes the real candidate rollback fail as well.
				action = `PERFORM pg_terminate_backend(pg_backend_pid());`
			}
			if fault == "retry-start-audit" {
				event = "run.start"
			}
			if _, err := d.pool.Exec(ctx, `CREATE FUNCTION control.reclamation_fault() RETURNS trigger LANGUAGE plpgsql AS $$
				BEGIN `+action+` RETURN NEW; END $$;
				CREATE TRIGGER reclamation_fault BEFORE INSERT ON control.service_audit_events
				FOR EACH ROW WHEN (NEW.event_type='`+event+`') EXECUTE FUNCTION control.reclamation_fault()`); err != nil {
				t.Fatal(err)
			}
			beforeOld := expirationProgressSnapshot(t, ctx, d, old.run.RunID)
			beforeRequested := expirationProgressSnapshot(t, ctx, d, requested.prepared.RunID)
			_, err := d.StartServiceRun(ctx, requested.service.ID, requested.prepared.RunID,
				requested.prepared.RunNumber, requested.publisher, at)
			insufficient, capacity, independent := startReclamationErrorLeaves(err)
			if fault == "retry-start-audit" {
				if insufficient != 0 || capacity != 0 || len(independent) != 1 {
					t.Fatal("retry lost its actual start-audit failure", err)
				}
				assertExpirationProgressClosed(t, ctx, d, old.run.RunID)
				assertAssignmentTotals(t, d.pool, 0)
			} else {
				if insufficient != 1 || capacity != 1 || len(independent) == 0 {
					t.Fatal("cleanup failure was hidden as a capacity miss or retried", err)
				}
				if expirationProgressSnapshot(t, ctx, d, old.run.RunID) != beforeOld {
					t.Fatal("failed cleanup committed closure, audit or reservation changes")
				}
				assertAssignmentTotals(t, d.pool, 2)
			}
			if fault == "cleanup-rollback" {
				if len(independent) < 2 || !strings.Contains(err.Error(), "expire service run: rollback:") {
					t.Fatal("independent operation and candidate rollback failures were not both retained", err)
				}
			} else {
				var sqlFault *pgconn.PgError
				if !errors.As(err, &sqlFault) || sqlFault.Code != "23514" || sqlFault.ConstraintName != "reclamation_fault" ||
					len(independent) != 1 {
					t.Fatal("selected SQL failure changed or gained an unrelated cause", err)
				}
			}
			if expirationProgressSnapshot(t, ctx, d, requested.prepared.RunID) != beforeRequested {
				t.Fatal("failed cleanup or retry retained partial start state")
			}
			if _, err := d.pool.Exec(ctx, `DROP TRIGGER reclamation_fault ON control.service_audit_events;
				DROP FUNCTION control.reclamation_fault()`); err != nil {
				t.Fatal(err)
			}
			started, err := d.StartServiceRun(ctx, requested.service.ID, requested.prepared.RunID,
				requested.prepared.RunNumber, requested.publisher, at)
			if err != nil {
				t.Fatal("same preparation could not recover after the selected SQL fault", err)
			}
			assertStartReclamationRun(t, ctx, d, requested, started, at)
			assertExpirationProgressClosed(t, ctx, d, old.run.RunID)
			assertAssignmentTotals(t, d.pool, 2)
		})
	}
}

func TestIntegrationServiceStartReclamationRestoredEligibleReservationsOnly(t *testing.T) {
	old := newServicePublicationFixture(t)
	d := old.database
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.relay_leases SET connection_capacity=1`); err != nil {
		t.Fatal(err)
	}
	for index := range 2 {
		registration := relayLifecycleRegistration(fmt.Sprintf("reclamation-ineligible-%d", index))
		registration.ConnectionCapacity = 1
		if _, err := d.RegisterRelay(t.Context(), registration, old.now, 48*time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	unrelated := newRestorationOtherTeamPublication(t, old, "ineligible", old.now)
	unrelated.start(t, "first", old.now.Add(time.Second))
	var ineligible []string
	for _, slot := range unrelated.run.Connections {
		if _, shared := old.leases[slot.RelayServiceID]; shared {
			t.Fatal("ineligible contrast did not consume its own full relay services")
		}
		ineligible = append(ineligible, slot.RelayServiceID)
	}
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.relay_services SET enabled=false WHERE relay_service_id=ANY($1::text[])`,
		ineligible); err != nil {
		t.Fatal(err)
	}
	requested := newRestorationOtherTeamPublication(t, old, "eligible", old.now)
	var err error
	requested.prepared, err = d.PrepareServiceRun(t.Context(), requested.service.ID, requested.publisher, "first", old.now,
		ServiceRunRequest{Metadata: requested.service.ServiceMetadata})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	before := expirationProgressSnapshot(t, ctx, d, unrelated.run.RunID)
	at := unrelated.run.ExpiresAt
	started, err := d.StartServiceRun(ctx, requested.service.ID, requested.prepared.RunID,
		requested.prepared.RunNumber, requested.publisher, at)
	if err != nil {
		t.Fatal("eligible relay reservations were not reclaimed", err)
	}
	assertStartReclamationRun(t, ctx, d, requested, started, at)
	assertExpirationProgressClosed(t, ctx, d, old.run.RunID)
	if expirationProgressSnapshot(t, ctx, d, unrelated.run.RunID) != before {
		t.Fatal("admission performed unrelated expiry outside its eligible relay selection")
	}
	assertAssignmentTotals(t, d.pool, 4)
}

func newStartReclamationFixture(t *testing.T) (servicePublicationFixture, servicePublicationFixture) {
	t.Helper()
	old := newServicePublicationFixture(t)
	requested := newRestorationOtherTeamPublication(t, old, "reclamation", old.now)
	if _, err := old.database.pool.Exec(t.Context(), `UPDATE control.relay_leases SET connection_capacity=1`); err != nil {
		t.Fatal(err)
	}
	var err error
	requested.prepared, err = old.database.PrepareServiceRun(t.Context(), requested.service.ID, requested.publisher,
		"first", old.now, ServiceRunRequest{Metadata: requested.service.ServiceMetadata})
	if err != nil {
		t.Fatal(err)
	}
	return old, requested
}

func assertStartReclamationRun(t *testing.T, ctx context.Context, d *Database, requested servicePublicationFixture, started ServiceRunState, at time.Time) {
	t.Helper()
	if started.ServiceID != requested.service.ID || started.RunID != requested.prepared.RunID ||
		started.RunNumber != requested.prepared.RunNumber || started.Token != requested.prepared.Token ||
		!started.ExpiresAt.Equal(at.Add(45*time.Second)) || len(started.Connections) != 2 {
		t.Fatal("reclamation replaced the preparation, token, run number, assignments or entry-time issuance budget")
	}
	var exact bool
	if err := d.pool.QueryRow(ctx, `SELECT run.state='starting' AND run.started_at=$2 AND run.publisher_expires_at=$3
		AND run.preparation_expires_at=$4 AND service.next_run_number=run.run_number+1
		AND (SELECT count(*)=1 FROM control.service_runs WHERE service_id=service.id)
		AND (SELECT count(*)=2 AND count(DISTINCT relay_service_id)=2 FROM control.service_connection_slots WHERE service_run_id=run.id AND session_open)
		AND (SELECT count(*)=1 FROM control.service_audit_events WHERE run_id=run.id AND event_type='run.start')
		FROM control.service_runs run JOIN control.services service ON service.id=run.service_id WHERE run.id=$1`,
		started.RunID, at, at.Add(45*time.Second), requested.prepared.ExpiresAt).Scan(&exact); err != nil || !exact {
		t.Fatal("reclamation left a second run, duplicate start, partial slots or changed preparation deadline", exact, err)
	}
}

// this test oracle enumerates error leaves independently of the retry classifier.
func startReclamationErrorLeaves(err error) (insufficient, capacity int, independent []error) {
	var inspect func(error)
	inspect = func(cause error) {
		switch cause {
		case nil:
			return
		case ErrInsufficientRelayServices:
			insufficient++
			return
		case errRelayPlacementCapacity:
			capacity++
			return
		}
		if joined, ok := cause.(interface{ Unwrap() []error }); ok {
			children := joined.Unwrap()
			if len(children) == 0 {
				independent = append(independent, cause)
			}
			for _, child := range children {
				inspect(child)
			}
		} else if wrapped, ok := cause.(interface{ Unwrap() error }); ok {
			if child := wrapped.Unwrap(); child != nil {
				inspect(child)
			} else {
				independent = append(independent, cause)
			}
		} else {
			independent = append(independent, cause)
		}
	}
	inspect(err)
	return insufficient, capacity, independent
}
