package state

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

// callers hold owner -> service -> run. settlement retains every issued offline
// serving tail and is a no-op after the exact active run has been settled once.
func closeServiceRun(ctx context.Context, q *controlstatedb.Queries, run controlstatedb.ControlServiceRun, now time.Time) (int64, error) {
	count, err := settleServiceRun(ctx, q, run, now)
	if err == nil && count != 0 {
		err = retireUnusedServiceCertificateOrders(ctx, q, run.ID, now)
	}
	return count, err
}

// atomic replacement settles the old run before inserting its successor, then
// retires unused certificates against both changes before committing.
func settleServiceRun(ctx context.Context, q *controlstatedb.Queries, run controlstatedb.ControlServiceRun, now time.Time) (int64, error) {
	count, err := q.CloseServiceRun(ctx, controlstatedb.CloseServiceRunParams{
		ID: run.ID, ServiceID: run.ServiceID, RunNumber: run.RunNumber, Now: timestamptz(now),
	})
	if err != nil || count == 0 {
		return count, err
	}
	if err = q.CancelOpenServiceRecoveryEpisode(ctx, controlstatedb.CancelOpenServiceRecoveryEpisodeParams{
		ServiceRunID: run.ID, CanceledAt: timestamptz(now),
	}); err != nil {
		return count, err
	}
	if run.GuestID.Valid {
		_, err = q.FinishGuestServiceRun(ctx, controlstatedb.FinishGuestServiceRunParams{
			ServiceRunID: text(run.ID), ClosedAt: timestamptz(now), CloseReason: "closed",
		})
	}
	return count, err
}

// callers hold the service owner and service locks. closure and suspension use
// the same ordered run settlement and slot-release path.
func closeServiceRuns(ctx context.Context, tx pgx.Tx, serviceID string, now time.Time) error {
	q := controlstatedb.New(tx)
	runs, err := q.LockServiceRunsForClose(ctx, serviceID)
	if err != nil {
		return err
	}
	for _, run := range runs {
		if _, err = closeServiceRun(ctx, q, run, now); err != nil {
			return err
		}
	}
	return nil
}

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
