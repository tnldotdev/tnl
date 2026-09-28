package controlstate

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

// ExpireSavedPublishRuns closes at most one batch of expired runs, including
// runs on saved public URLs that no publisher will touch again. Each closure
// also releases its relay reservations and publishes routing tombstones.
func (d *Database) ExpireSavedPublishRuns(ctx context.Context, now time.Time) (count int, retErr error) {
	if err := d.requireOpen(); err != nil {
		return 0, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return 0, fmt.Errorf("controlstate: expire saved publish runs: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "expire saved publish runs", &retErr)()
	queries := controlstatedb.New(tx)
	pendingEvents := pendingIngressRoutingTableEvents{}
	routes, err := queries.LockExpiredPublishRunPublicURLs(ctx, controlstatedb.LockExpiredPublishRunPublicURLsParams{
		Now: timestamptz(now), BatchSize: maximumExpiredPublishRunBatch,
	})
	if err != nil {
		return 0, fmt.Errorf("controlstate: expire saved publish runs: lock public URLs: %w", err)
	}
	for _, route := range routes {
		// The candidate may have been renewed after the query's snapshot.
		// Recheck the run under its public URL lock before closing it.
		_, closed, err := expireStaleOpenPublishRun(ctx, queries, &pendingEvents, route, now)
		if err != nil {
			return 0, err
		}
		if closed {
			count++
		}
	}
	if err := pendingEvents.publish(ctx, queries); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("controlstate: expire saved publish runs: commit: %w", err)
	}
	return count, nil
}
