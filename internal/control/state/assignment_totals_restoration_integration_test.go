package state

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestIntegrationAssignmentTotalsRestoredParentChildTransitionRace(t *testing.T) {
	for _, reopen := range []bool{false, true} {
		for _, mutation := range []string{"expire", "delete", "transfer"} {
			t.Run(fmt.Sprintf("reopen=%t/%s", reopen, mutation), func(t *testing.T) {
				f := newServicePublicationFixture(t)
				d := f.database
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				if _, err := d.RegisterRelay(ctx, relayLifecycleRegistration("restored-spare"), f.now, time.Hour); err != nil {
					t.Fatal(err)
				}
				closeParent := `UPDATE control.service_runs SET state='closed',closed_at=publisher_expires_at WHERE id=$1`
				if reopen {
					if _, err := d.pool.Exec(ctx, closeParent, f.run.RunID); err != nil {
						t.Fatal(err)
					}
					assertAssignmentTotals(t, d.pool, 0)
				} else {
					assertAssignmentTotals(t, d.pool, 2)
				}
				child, err := d.pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer rollbackTestTransaction(t, child)
				if _, err := child.Exec(ctx, `SELECT publisher_connection_id FROM control.service_connection_slots
					WHERE service_run_id=$1 AND connection_slot=0 FOR UPDATE`, f.run.RunID); err != nil {
					t.Fatal(err)
				}
				parentQuery := closeParent
				if reopen {
					parentQuery = `UPDATE control.service_runs SET state='starting',closed_at=NULL WHERE id=$1`
				}
				workers := newIntegrationWorkers(t, cancel)
				defer workers.stop()
				done := make(chan error, 1)
				workers.Go(func() {
					_, err := d.pool.Exec(ctx, parentQuery, f.run.RunID)
					done <- err
				})
				// the parent row is held while its eligibility cascade waits on
				// this child. the child mutation must not lock the parent back.
				waitForPostgresBlock(t, ctx, d, int32(child.Conn().PgConn().PID()), done)
				// expired slots use the unified closed state, not a second
				// service lifecycle or a caller-selected lease.
				query := `UPDATE control.service_connection_slots SET state='closed' WHERE service_run_id=$1 AND connection_slot=0`
				switch mutation {
				case "delete":
					query = `DELETE FROM control.service_connection_slots WHERE service_run_id=$1 AND connection_slot=0`
				case "transfer":
					query = `UPDATE control.service_connection_slots SET relay_service_id='restored-spare' WHERE service_run_id=$1 AND connection_slot=0`
				}
				if _, err := child.Exec(ctx, query, f.run.RunID); err != nil {
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
				assertAssignmentTotals(t, d.pool, want)
			})
		}
	}
}
