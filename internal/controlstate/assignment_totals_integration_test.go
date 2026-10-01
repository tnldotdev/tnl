package controlstate

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

// use the full recount as an oracle, including zero-total relay services.
// read both sides in one statement so concurrent commits cannot skew them.
func assertAssignmentTotals(t *testing.T, db controlstatedb.DBTX, want int64) {
	t.Helper()
	var mismatches, total int64
	err := db.QueryRow(t.Context(), `
		WITH actual AS (
			SELECT connections.relay_service_id, count(*) AS assignment_count
			FROM control.publish_run_connections AS connections
			JOIN control.publish_runs AS sessions ON sessions.id = connections.publish_run_id
			WHERE sessions.closed_at IS NULL
			  AND connections.state IN ('assigned', 'connected', 'ready', 'draining')
			GROUP BY connections.relay_service_id
		)
		SELECT count(*) FILTER (WHERE totals.assignment_count IS DISTINCT FROM COALESCE(actual.assignment_count, 0)),
		       COALESCE(sum(totals.assignment_count), 0)::bigint
		FROM control.relay_services AS services
		LEFT JOIN control.relay_service_assignment_totals AS totals USING (relay_service_id)
		LEFT JOIN actual USING (relay_service_id)
	`).Scan(&mismatches, &total)
	if err != nil || mismatches != 0 || total != want {
		t.Fatalf("assignment totals: mismatches=%d total=%d, want 0/%d: %v", mismatches, total, want, err)
	}
}

func TestIntegrationAssignmentTotalsMutations(t *testing.T) {
	f := newPublishRunFixture(t)
	database, now := f.database, f.now
	ctx := t.Context()
	assertAssignmentTotals(t, database.pool, 2)
	if _, err := database.CreatePublishRun(ctx, f.request, now, time.Minute, time.Minute); err != nil {
		t.Fatal(err)
	}
	assertAssignmentTotals(t, database.pool, 2)
	claim := sessionClaim(t, f)
	for _, operation := range []func(context.Context, PublisherConnectionClaimRequest, time.Time) (ClaimedPublisherConnection, error){
		database.ClaimPublisherConnection, database.ClaimPublisherConnection,
		database.MarkPublisherConnectionReady, database.MarkPublisherConnectionReady,
	} {
		if _, err := operation(ctx, claim, now); err != nil {
			t.Fatal(err)
		}
		assertAssignmentTotals(t, database.pool, 2)
	}
	if _, err := database.RegisterRelay(ctx, relayLifecycleRegistration("spare"), now, time.Hour); err != nil {
		t.Fatal(err)
	}
	assertAssignmentTotals(t, database.pool, 2)
	tx, err := database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, tx)
	steps := []struct {
		name, query string
		want        int64
	}{
		{"draining", `UPDATE control.publish_run_connections SET state = 'draining' WHERE connection_slot = 0`, 2},
		{"service transfer", `UPDATE control.publish_run_connections SET relay_service_id = 'spare' WHERE connection_slot = 0`, 2},
		{"expire", `UPDATE control.publish_run_connections SET state = 'expired' WHERE connection_slot = 1`, 1},
		{"reassign expired", `UPDATE control.publish_run_connections SET state = 'assigned' WHERE connection_slot = 1`, 2},
		{"close slot", `UPDATE control.publish_run_connections SET state = 'closed' WHERE connection_slot = 1`, 1},
		{"reassign closed", `UPDATE control.publish_run_connections SET state = 'assigned' WHERE connection_slot = 1`, 2},
		{"close parent first", `UPDATE control.publish_runs SET state = 'closed', closed_at = publisher_expires_at, close_reason = 'test'`, 0},
		{"close slot after parent", `UPDATE control.publish_run_connections SET state = 'expired' WHERE connection_slot = 1`, 0},
		{"reopen parent", `UPDATE control.publish_runs SET state = 'starting', closed_at = NULL, close_reason = NULL`, 1},
		{"save slots", `CREATE TEMP TABLE saved_assignments ON COMMIT DROP AS TABLE control.publish_run_connections`, 1},
		{"delete slots", `DELETE FROM control.publish_run_connections`, 0},
		{"insert active and expired slots", `INSERT INTO control.publish_run_connections SELECT * FROM saved_assignments`, 1},
		{"insert conflict retry", `INSERT INTO control.publish_run_connections SELECT * FROM saved_assignments ON CONFLICT DO NOTHING`, 1},
		{"close children first", `UPDATE control.publish_run_connections SET state = 'closed'`, 0},
		{"close parent after children", `UPDATE control.publish_runs SET state = 'closed', closed_at = publisher_expires_at, close_reason = 'test'`, 0},
		{"delete closed children", `DELETE FROM control.publish_run_connections`, 0},
		{"prepare historical slots", `UPDATE saved_assignments SET session_open = false`, 0},
		{"insert into closed parent", `INSERT INTO control.publish_run_connections SELECT * FROM saved_assignments`, 0},
		{"reopen with inserted slots", `UPDATE control.publish_runs SET state = 'starting', closed_at = NULL, close_reason = NULL`, 1},
		{"close children and parent in one statement", `WITH closed AS (
			UPDATE control.publish_run_connections SET state = 'closed' RETURNING publish_run_id
		) UPDATE control.publish_runs SET state = 'closed', closed_at = publisher_expires_at, close_reason = 'test'
		WHERE id IN (SELECT publish_run_id FROM closed)`, 0},
		{"reopen after compound closure", `UPDATE control.publish_runs SET state = 'starting', closed_at = NULL, close_reason = NULL`, 0},
		{"restore assignment", `UPDATE control.publish_run_connections SET state = 'assigned' WHERE connection_slot = 1`, 1},
		{"close parent and children in one statement", `WITH closed AS (
			UPDATE control.publish_runs SET state = 'closed', closed_at = publisher_expires_at, close_reason = 'test' RETURNING id
		) UPDATE control.publish_run_connections SET state = 'closed'
		WHERE publish_run_id IN (SELECT id FROM closed)`, 0},
	}
	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			if _, err := tx.Exec(ctx, step.query); err != nil {
				t.Fatal(err)
			}
			assertAssignmentTotals(t, tx, step.want)
		})
		if t.Failed() {
			return
		}
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	assertAssignmentTotals(t, database.pool, 2)
	if _, err := database.DisconnectPublisherConnection(ctx, claim, now, true); err != nil {
		t.Fatal(err)
	}
	assertAssignmentTotals(t, database.pool, 1)
	if _, err := database.DisconnectPublisherConnection(ctx, claim, now, true); !errors.Is(err, ErrConnectionAssignmentStale) {
		t.Fatalf("disconnect retry = %v", err)
	}
	assertAssignmentTotals(t, database.pool, 1)
	if _, err := database.HeartbeatPublishRun(ctx, f.authentication(), now, time.Minute, time.Minute); err != nil {
		t.Fatal(err)
	}
	assertAssignmentTotals(t, database.pool, 2)
	if _, err := database.pool.Exec(ctx, `UPDATE control.relay_services SET enabled = false WHERE relay_service_id = $1`, claim.ConnectionAssignmentIdentity.RelayServiceID); err != nil {
		t.Fatal(err)
	}
	assertAssignmentTotals(t, database.pool, 2)
	recovered, err := database.HeartbeatPublishRun(ctx, f.authentication(), now, time.Minute, time.Minute)
	if err != nil || recovered.PublisherConnections[0].RelayServiceID != "spare" {
		t.Fatalf("disabled-service recovery chose %q: %v", recovered.PublisherConnections[0].RelayServiceID, err)
	}
	assertAssignmentTotals(t, database.pool, 2)
	for range 2 {
		if err := database.ClosePublishRun(ctx, f.setup.PublishRunID, f.setup.PublishRunToken, now); err != nil {
			t.Fatal(err)
		}
		assertAssignmentTotals(t, database.pool, 0)
	}
}

func TestIntegrationAssignmentTotalsRollbackAndStoredReservations(t *testing.T) {
	database, now, request, _ := newPublishRunPrerequisites(t)
	ctx := t.Context()
	// fail after the assignment triggers have run, at the final audit insertion.
	if _, err := database.pool.Exec(ctx, `ALTER TABLE control.admin_audit_events ADD CONSTRAINT reject_session_audit CHECK (operation <> 'publish_run.create')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreatePublishRun(ctx, request, now, time.Minute, time.Minute); err == nil {
		t.Fatal("creation unexpectedly succeeded")
	}
	assertAssignmentTotals(t, database.pool, 0)
	if _, err := database.pool.Exec(ctx, `ALTER TABLE control.admin_audit_events DROP CONSTRAINT reject_session_audit`); err != nil {
		t.Fatal(err)
	}
	setup, err := database.CreatePublishRun(ctx, request, now, time.Minute, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	assertAssignmentTotals(t, database.pool, 2)
	// time and live-lease availability do not release stored reservations.
	tx, err := database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, tx)
	services, leases, err := availableRelayServicePlacements(ctx, controlstatedb.New(tx), now.Add(2*time.Hour))
	if err != nil || len(services) != 0 || len(leases) != 0 {
		t.Fatalf("expired lease availability = %v/%v: %v", services, leases, err)
	}
	assertAssignmentTotals(t, tx, 2)
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := database.ClosePublishRun(ctx, setup.PublishRunID, setup.PublishRunToken, now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	assertAssignmentTotals(t, database.pool, 0)
}

func TestIntegrationAssignmentTotalsRejectParentFlagDrift(t *testing.T) {
	f := newPublishRunFixture(t)
	tx, err := f.database.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, tx)
	if _, err := tx.Exec(t.Context(), `UPDATE control.publish_run_connections SET session_open = false WHERE connection_slot = 0`); err != nil {
		t.Fatal(err)
	}
	var constraint *pgconn.PgError
	if err := tx.Commit(t.Context()); !errors.As(err, &constraint) || constraint.ConstraintName != "publish_run_connections_assignment_parent" {
		t.Fatalf("parent flag drift commit error = %v", err)
	}
	assertAssignmentTotals(t, f.database.pool, 2)
}

func TestIntegrationAssignmentTotalsParentTransitionRace(t *testing.T) {
	for _, reopen := range []bool{false, true} {
		for _, mutation := range []string{"expire", "delete", "transfer"} {
			t.Run(fmt.Sprintf("reopen=%t/%s", reopen, mutation), func(t *testing.T) {
				f := newPublishRunFixture(t)
				database := f.database
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				if _, err := database.RegisterRelay(ctx, relayLifecycleRegistration("spare"), f.now, time.Hour); err != nil {
					t.Fatal(err)
				}
				closeParent := `UPDATE control.publish_runs SET state = 'closed', closed_at = publisher_expires_at, close_reason = 'test' WHERE id = $1`
				if reopen {
					if _, err := database.pool.Exec(ctx, closeParent, f.setup.PublishRunID); err != nil {
						t.Fatal(err)
					}
					assertAssignmentTotals(t, database.pool, 0)
				}
				child, err := database.pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer rollbackTestTransaction(t, child)
				if _, err := controlstatedb.New(child).GetPublisherConnectionForClaim(ctx, f.setup.PublisherConnections[0].PublisherConnectionID); err != nil {
					t.Fatal(err)
				}
				workers := newIntegrationWorkers(t, cancel)
				defer workers.stop()
				done := make(chan error, 1)
				parentQuery := closeParent
				if reopen {
					parentQuery = `UPDATE control.publish_runs SET state = 'starting', closed_at = NULL, close_reason = NULL WHERE id = $1`
				}
				workers.Go(func() { _, err := database.pool.Exec(ctx, parentQuery, f.setup.PublishRunID); done <- err })
				// the parent holds its row while its eligibility cascade waits for
				// this slot. A slot delta must not acquire the parent in reverse.
				waitForPostgresBlock(t, ctx, database, int32(child.Conn().PgConn().PID()), done)
				query := `UPDATE control.publish_run_connections SET state = 'expired' WHERE connection_slot = 0`
				if mutation == "delete" {
					query = `DELETE FROM control.publish_run_connections WHERE connection_slot = 0`
				} else if mutation == "transfer" {
					query = `UPDATE control.publish_run_connections SET relay_service_id = 'spare' WHERE connection_slot = 0`
				}
				if _, err := child.Exec(ctx, query); err != nil {
					t.Fatal(err)
				}
				before := int64(1)
				if mutation == "transfer" {
					before = 2
				}
				if reopen {
					before = 0
				}
				assertAssignmentTotals(t, child, before)
				if err := child.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				if err := awaitIntegrationResult(t, ctx, done); err != nil {
					t.Fatal(err)
				}
				want := int64(0)
				if reopen {
					want = 1
					if mutation == "transfer" {
						want = 2
					}
				}
				assertAssignmentTotals(t, database.pool, want)
			})
		}
	}
}

func TestIntegrationAssignmentTotalsExpiryPlacementLockOrder(t *testing.T) {
	fixtures, _ := relayServiceProgressSessions(t)
	f, database, now := fixtures[0], fixtures[0].database, fixtures[0].now
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if _, err := database.pool.Exec(ctx, `UPDATE control.publish_runs SET publisher_expires_at = $2 WHERE id = $1`, f.setup.PublishRunID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	gate, err := database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := gate.Exec(ctx, `SELECT control_name FROM control.maintenance_controls WHERE control_name = 'publish_run_creation' FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	replacement, heartbeat := make(chan error, 1), make(chan error, 1)
	request := f.request
	request.IdempotencyKey, request.RequestDigest, request.ExpectedMutationRevision = "replacement", sha256.Sum256([]byte("replacement")), 2
	workers.Go(func() {
		_, err := database.CreatePublishRun(ctx, request, now.Add(2*time.Second), time.Hour, time.Hour)
		replacement <- err
	})
	// expiry has released reservations and holds the totals guard, but placement
	// is paused at the maintenance row before taking any service locks.
	replacementPID := waitForPostgresBlock(t, ctx, database, int32(gate.Conn().PgConn().PID()), replacement)
	workers.Go(func() {
		_, err := database.HeartbeatPublishRun(ctx, fixtures[1].authentication(), now.Add(2*time.Second), time.Hour, time.Hour)
		heartbeat <- err
	})
	waitForPostgresBlock(t, ctx, database, replacementPID, heartbeat)
	// queued placement must not hold service locks ahead of the totals guard;
	// claim/readiness retries on another public URL must avoid the totals guard.
	claim := sessionClaim(t, fixtures[2])
	for range 2 {
		if _, err := database.ClaimPublisherConnection(ctx, claim, now); err != nil {
			t.Fatal(err)
		}
		if _, err := database.MarkPublisherConnectionReady(ctx, claim, now); err != nil {
			t.Fatal(err)
		}
		assertAssignmentTotals(t, database.pool, 10)
	}
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	for _, done := range []<-chan error{replacement, heartbeat} {
		if err := awaitIntegrationResult(t, ctx, done); err != nil {
			t.Fatal(err)
		}
	}
	assertAssignmentTotals(t, database.pool, 10)
}

func TestIntegrationAssignmentTotalsBulkClosureLockOrder(t *testing.T) {
	for _, cleanup := range []bool{false, true} {
		t.Run(fmt.Sprintf("cleanup=%t", cleanup), func(t *testing.T) {
			fixtures, _ := relayServiceProgressSessions(t)
			database, now := fixtures[0].database, fixtures[0].now
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			for _, service := range []string{"a", "b", "y", "z"} {
				if _, err := database.RegisterRelay(ctx, relayLifecycleRegistration(service), now, time.Hour); err != nil {
					t.Fatal(err)
				}
			}
			// bulk closure visits y/z before a/b; the competing single closure
			// visits a/z. per-statement ordered counter locks alone would cycle.
			for index, services := range [][2]string{{"y", "z"}, {"a", "b"}, {"a", "z"}} {
				if _, err := database.pool.Exec(ctx, `UPDATE control.publish_run_connections SET relay_service_id = CASE connection_slot WHEN 0 THEN $2 ELSE $3 END WHERE publish_run_id = $1`, fixtures[index].setup.PublishRunID, services[0], services[1]); err != nil {
					t.Fatal(err)
				}
			}
			if cleanup {
				for _, f := range fixtures[:2] {
					if _, err := database.pool.Exec(ctx, `UPDATE control.public_urls SET ephemeral = true, expires_at = $2 WHERE id = $1`, f.setup.PublicURLID, now.Add(time.Second)); err != nil {
						t.Fatal(err)
					}
					if _, err := database.pool.Exec(ctx, `UPDATE control.publish_runs SET publisher_expires_at = $2 WHERE id = $1`, f.setup.PublishRunID, now.Add(time.Second)); err != nil {
						t.Fatal(err)
					}
				}
			} else {
				if _, err := database.pool.Exec(ctx, `UPDATE control.public_urls SET team_id = $2 WHERE id = $1`, fixtures[1].setup.PublicURLID, fixtures[0].setup.TeamID); err != nil {
					t.Fatal(err)
				}
			}
			assertAssignmentTotals(t, database.pool, 10)
			gate, err := database.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if _, err := controlstatedb.New(gate).GetPublisherConnectionForClaim(ctx, fixtures[1].setup.PublisherConnections[0].PublisherConnectionID); err != nil {
				t.Fatal(err)
			}
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			bulk, single := make(chan error, 1), make(chan error, 1)
			workers.Go(func() {
				var closed int
				var err error
				if cleanup {
					closed, err = database.DeleteExpiredEphemeralPublicURLs(ctx, now.Add(2*time.Second))
				} else {
					_, closed, err = database.ApplyHostedPolicyRevocation(ctx, "https://authority.example.test", fixtures[0].setup.TeamID, 2, true, nil, nil, now)
				}
				if err == nil && closed != 2 {
					err = fmt.Errorf("closed %d sessions, want 2", closed)
				}
				bulk <- err
			})
			bulkPID := waitForPostgresBlock(t, ctx, database, int32(gate.Conn().PgConn().PID()), bulk)
			workers.Go(func() {
				f := fixtures[2]
				single <- database.ClosePublishRun(ctx, f.setup.PublishRunID, f.setup.PublishRunToken, now)
			})
			waitForPostgresBlock(t, ctx, database, bulkPID, single)
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			for _, done := range []<-chan error{bulk, single} {
				if err := awaitIntegrationResult(t, ctx, done); err != nil {
					t.Fatal(err)
				}
			}
			assertAssignmentTotals(t, database.pool, 4)
		})
	}
}
