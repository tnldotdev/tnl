package state

import (
	"context"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

// ClosedServiceRuns proves only terminal state for exact requested tuples.
// a missing row, expired lease, or newer sibling is not closure evidence.
func (d *Database) ClosedServiceRuns(ctx context.Context, lease IngressLeaseIdentity, runs []ServiceRunReference, now time.Time) (closed []ServiceRunReference, retErr error) {
	if validateIngressLeaseIdentity(lease) != nil || len(runs) == 0 || len(runs) > 128 {
		return nil, ErrServiceAccess
	}
	ids := make([]string, 0, len(runs))
	seen := make(map[ServiceRunReference]bool, len(runs))
	for _, run := range runs {
		if _, err := checkedServiceRunBinding(run.ServiceID, run.RunID, run.RunNumber); err != nil || seen[run] {
			return nil, ErrServiceAccess
		}
		seen[run] = true
		ids = append(ids, run.RunID)
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(ctx, tx, "look up closed service runs", &retErr)()
	q := controlstatedb.New(tx)
	if _, err := lockCurrentIngressLease(ctx, q, lease, now); err != nil {
		return nil, err
	}
	rows, err := q.ClosedServiceRuns(ctx, ids)
	if err != nil {
		return nil, err
	}
	closed = make([]ServiceRunReference, 0, len(runs))
	for _, run := range rows {
		ref := ServiceRunReference{ServiceID: run.ServiceID, RunID: run.ID, RunNumber: run.RunNumber}
		if seen[ref] {
			closed = append(closed, ref)
		}
	}
	return closed, tx.Commit(ctx)
}
