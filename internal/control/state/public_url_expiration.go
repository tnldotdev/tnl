package state

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

// DeleteExpiredEphemeralPublicURLs removes a bounded batch of expired public
// URLs. it uses the same publish-run, routing-table, and DNS cleanup as explicit
// deletion.
func (d *Database) DeleteExpiredEphemeralPublicURLs(ctx context.Context, now time.Time) (count int, retErr error) {
	if err := d.requireOpen(); err != nil {
		return 0, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return 0, fmt.Errorf("controlstate: delete expired ephemeral public_urls: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "delete expired ephemeral routes", &retErr)()
	queries := controlstatedb.New(tx)
	pendingEvents := pendingIngressRoutingTableEvents{}
	routes, err := queries.LockExpiredEphemeralPublicURLs(ctx, controlstatedb.LockExpiredEphemeralPublicURLsParams{
		Now: timestamptz(now), BatchSize: maximumExpiredEphemeralPublicURLBatch,
	})
	if err != nil {
		return 0, fmt.Errorf("controlstate: delete expired ephemeral public_urls: lock public_urls: %w", err)
	}
	for _, route := range routes {
		hasOpenSession, _, err := expireStaleOpenPublishRun(ctx, queries, &pendingEvents, route, now)
		if err != nil {
			return 0, err
		}
		if hasOpenSession {
			continue
		}
		updated, err := queries.DeletePublicURL(ctx, controlstatedb.DeletePublicURLParams{
			DeletedAt: timestamptz(now), PublicURLID: route.ID, ExpectedMutationRevision: route.MutationRevision,
		})
		if err != nil {
			return 0, fmt.Errorf("controlstate: delete expired ephemeral public_urls: update public_url: %w", err)
		}
		if updated != 1 {
			return 0, ErrPublicURLNotFound
		}
		if err := queries.InsertExpiredEphemeralPublicURLDeleteAuditEvent(
			ctx,
			controlstatedb.InsertExpiredEphemeralPublicURLDeleteAuditEventParams{
				RequestID: "ephemeral_expiry/" + route.ID, PublicURLID: route.ID, OccurredAt: timestamptz(now),
			},
		); err != nil {
			return 0, fmt.Errorf("controlstate: delete expired ephemeral public_urls: insert audit event: %w", err)
		}
		count++
	}
	if err := pendingEvents.publish(ctx, queries); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("controlstate: delete expired ephemeral public_urls: commit: %w", err)
	}
	return count, nil
}
