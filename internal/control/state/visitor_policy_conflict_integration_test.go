package state

import (
	"context"
	"errors"
	"testing"
	"time"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationPublisherVisitorPolicyRetriesAllocationConflicts(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		t.Run(map[bool]string{false: "current grant", true: "revoked grant"}[revoke], func(t *testing.T) {
			f, run, owners := capacityFixture(t, 4)
			d := f.database
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			workers := newIntegrationWorkers(t, cancel)
			if err := d.PrepareVisitorSigningKeys(ctx, testVisitorIssuer, f.now); err != nil {
				t.Fatal(err)
			}
			request := capacityRequest(run, owners[0], "policy-conflict", 2)
			allocation, err := d.AllocateStreamCapacity(ctx, request, f.now)
			if err != nil {
				t.Fatal(err)
			}
			gate, err := d.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			// a same-value update still creates a conflicting row version after
			// the real reader's snapshot and initial authority checks.
			if _, err := gate.Exec(ctx, `UPDATE control.stream_capacity_allocations SET valid_until=valid_until WHERE id=$1`, allocation.ID); err != nil {
				t.Fatal(err)
			}
			var result controlv1.VisitorPolicyUpdate
			done := make(chan error, 1)
			workers.Go(func() {
				var err error
				result, err = d.ReadPublisherVisitorPolicy(ctx, request.Scope, run.RunID, run.RunNumber, run.Token, 0, []string{allocation.ID}, f.now)
				done <- err
			})
			waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), done)
			if revoke {
				if _, err := gate.Exec(ctx, `UPDATE control.publisher_grants SET revoked_at=$2
					WHERE id=(SELECT publisher_grant_id FROM control.service_runs WHERE id=$1)`, run.RunID, f.now); err != nil {
					t.Fatal(err)
				}
			}
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			err = awaitIntegrationResult(t, ctx, done)
			if revoke {
				if !errors.Is(err, ErrServiceAccess) {
					t.Fatal("retried policy did not recheck current publisher authority", err)
				}
			} else if err != nil || !result.Policy.Enabled || result.Policy.Resource.Id != run.ServiceID || len(result.Policy.StreamAllocations) != 1 || !result.Policy.ObservedAt.After(f.now) {
				t.Fatal("rolled-back observation did not recover with a complete policy", err)
			}
			var observed bool
			if err := d.pool.QueryRow(ctx, `SELECT publisher_observed_at IS NOT NULL FROM control.stream_capacity_allocations WHERE id=$1`, allocation.ID).Scan(&observed); err != nil {
				t.Fatal(err)
			}
			if observed == revoke {
				t.Fatal("publisher observation did not match the committed authorization decision", observed)
			}
		})
	}
}
