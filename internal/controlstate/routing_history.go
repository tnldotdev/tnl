package controlstate

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

// AdvanceIngressRoutingRetention advertises the oldest supported incremental
// cursor. snapshot and entry-revision anchors survive subsequent pruning.
// the cutoff is chosen by control, never supplied by an ingress request.
func (d *Database) AdvanceIngressRoutingRetention(ctx context.Context, cutoff time.Time) (revision uint64, retErr error) {
	defer d.observeOperation("AdvanceIngressRoutingRetention", &retErr)()
	if err := d.requireOpen(); err != nil {
		return 0, err
	}
	if cutoff.IsZero() {
		return 0, errors.New("controlstate: routing retention cutoff is required")
	}
	queries := controlstatedb.New(d.pool)
	candidate, err := queries.SelectIngressRoutingRetentionFloor(ctx, timestamptz(cutoff))
	if err != nil {
		return 0, fmt.Errorf("controlstate: select routing retention floor: %w", err)
	}
	// autocommit releases the clock before cleanup. another control may advance
	// the floor meanwhile; the update remains monotonic and idempotent.
	floor, err := queries.AdvanceIngressRoutingRetentionFloor(ctx, candidate)
	if err != nil {
		return 0, fmt.Errorf("controlstate: advance routing retention floor: %w", err)
	}
	if d.activity != nil {
		d.activity.metrics.Load().ObserveRoutingHistoryFloor(uint64(floor))
	}
	return uint64(floor), nil
}

type RoutingHistoryPruneResult struct {
	NextRevision uint64
	Scanned      int64
	Deleted      int64
	More         bool
	Busy         bool
}

// PruneIngressRoutingHistory scans at most 1,000 committed events below the
// published floor. callers yield between batches, retain NextRevision within a
// sweep, and restart at zero after More is false. A canceled/failed batch must
// retry its previous cursor. Busy means another control owns the current batch.
func (d *Database) PruneIngressRoutingHistory(ctx context.Context, afterRevision uint64) (result RoutingHistoryPruneResult, retErr error) {
	defer d.observeOperation("PruneIngressRoutingHistory", &retErr)()
	if err := d.requireOpen(); err != nil {
		return result, err
	}
	after, ok := nonnegativeInt64(afterRevision)
	if !ok {
		return result, errors.New("controlstate: routing cleanup cursor is invalid")
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, fmt.Errorf("controlstate: prune routing history: begin: %w", err)
	}
	defer rollback(ctx, tx, "prune routing history", &retErr)()
	queries := controlstatedb.New(tx)
	locked, err := queries.TryLockIngressRoutingHistoryCleanup(ctx)
	if err != nil {
		return result, fmt.Errorf("controlstate: prune routing history: guard: %w", err)
	}
	if !locked {
		if d.activity != nil {
			d.activity.metrics.Load().ObserveRoutingHistoryBatch(0, 0, true)
		}
		return RoutingHistoryPruneResult{NextRevision: afterRevision, Busy: true}, nil
	}
	batch, err := queries.PruneIngressRoutingHistoryBatch(ctx, after)
	if err != nil {
		return result, fmt.Errorf("controlstate: prune routing history: delete: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return result, fmt.Errorf("controlstate: prune routing history: commit: %w", err)
	}
	if d.activity != nil {
		d.activity.metrics.Load().ObserveRoutingHistoryBatch(batch.Scanned, batch.Deleted, false)
	}
	return RoutingHistoryPruneResult{NextRevision: uint64(batch.NextRevision), Scanned: batch.Scanned, Deleted: batch.Deleted, More: batch.Scanned == 1000}, nil
}
