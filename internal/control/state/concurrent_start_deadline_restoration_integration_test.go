package state

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationConcurrentStartsRestoredTenSecondAuthorityBudget(t *testing.T) {
	for _, mutation := range []string{"role", "remove", "release"} {
		t.Run(mutation, func(t *testing.T) {
			owner, member, domain, fixtures := sessionLockAuthorityFixtures(t)
			f, sibling := fixtures[0], fixtures[1]
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			firstGate, err := f.database.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, firstGate)
			secondGate, err := f.database.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, secondGate)
			if _, err := controlstatedb.New(firstGate).LockService(ctx, f.service.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := controlstatedb.New(secondGate).LockService(ctx, sibling.service.ID); err != nil {
				t.Fatal(err)
			}
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			started := []chan error{make(chan error, 1), make(chan error, 1)}
			for index := range fixtures {
				workers.Go(func() {
					fixture := &fixtures[index]
					run, err := fixture.database.StartServiceRun(ctx, fixture.service.ID,
						fixture.prepared.RunID, fixture.prepared.RunNumber, fixture.publisher, fixture.now)
					fixture.run = run
					started[index] <- err
				})
			}
			firstPID := waitForPostgresBlock(t, ctx, f.database, int32(firstGate.Conn().PgConn().PID()), started[0])
			secondPID := waitForPostgresBlock(t, ctx, f.database, int32(secondGate.Conn().PgConn().PID()), started[1])
			mutated := make(chan error, 1)
			workers.Go(func() {
				var err error
				switch mutation {
				case "role":
					_, err = f.database.SetMembershipRole(ctx, owner, member.TeamID, member.ID, TeamRoleMember, f.now)
				case "remove":
					err = f.database.RemoveMembership(ctx, owner, member.TeamID, member.ID, f.now)
				case "release":
					err = f.database.ReleaseTeamDomain(ctx, owner, member.TeamID, domain.ID, f.now)
				}
				mutated <- err
			})
			waitForPostgresBlock(t, ctx, f.database, firstPID, mutated, secondPID)
			if err := firstGate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := awaitIntegrationResult(t, ctx, started[0]); err != nil {
				t.Fatal(err)
			}
			// one completed reader must not let the writer miss the other.
			waitForPostgresBlock(t, ctx, f.database, secondPID, mutated)
			if err := secondGate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := awaitIntegrationResult(t, ctx, started[1]); err != nil {
				t.Fatal(err)
			}
			if err := awaitIntegrationResult(t, ctx, mutated); err != nil {
				t.Fatal(err)
			}
			ids := []string{fixtures[0].run.RunID, fixtures[1].run.RunID}
			var closed, slots int
			if err := f.database.pool.QueryRow(ctx, `SELECT
				(SELECT count(*) FROM control.service_runs WHERE id=ANY($1::text[]) AND state='closed' AND closed_at IS NOT NULL AND NOT assignments_open),
				(SELECT count(*) FROM control.service_connection_slots WHERE service_run_id=ANY($1::text[]) AND NOT session_open)`,
				ids).Scan(&closed, &slots); err != nil || closed != 2 || slots != 4 {
				t.Fatalf("ten-second authority closure runs/slots=%d/%d, want 2/4: %v", closed, slots, err)
			}
			for _, fixture := range fixtures {
				if fixture.run.Token == "" || len(fixture.run.Connections) != 2 {
					t.Fatal("concurrent start did not first issue actual run authority")
				}
				if _, err := fixture.database.StartServiceRun(ctx, fixture.service.ID, fixture.run.RunID,
					fixture.run.RunNumber, fixture.publisher, f.now); !errors.Is(err, ErrServiceAccess) {
					t.Fatal("authority mutation allowed old start replay", err)
				}
				if _, err := fixture.database.HeartbeatServiceRun(ctx, fixture.service.ID, fixture.run.RunID,
					fixture.run.Token, f.now, ServiceRunHealth{StreamCapacity: 64}); !errors.Is(err, ErrServiceAccess) {
					t.Fatal("authority mutation allowed old heartbeat", err)
				}
				want := ErrServiceAccess
				if mutation == "role" {
					want = ErrServiceConflict
				}
				if _, err := fixture.database.PrepareServiceRun(ctx, fixture.service.ID, fixture.publisher,
					fixture.prepared.IdempotencyKey, f.now, ServiceRunRequest{Metadata: fixture.service.ServiceMetadata}); !errors.Is(err, want) {
					t.Fatalf("authority mutation old-key replay = %v, want %v", err, want)
				}
			}
		})
	}
}
