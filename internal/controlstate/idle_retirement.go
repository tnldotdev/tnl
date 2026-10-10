package controlstate

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

const (
	savedURLIdlePeriod     = 180 * 24 * time.Hour
	savedURLRecoveryPeriod = 30 * 24 * time.Hour
	savedURLRetireBatch    = 128
)

// RetireIdlePublicURLs starts recovery for idle saved URLs and deletes those
// whose recovery period ended. an active or unclosed publish run is never
// retired. publishing again starts a new idle period when that run closes.
func (d *Database) RetireIdlePublicURLs(ctx context.Context, now time.Time) (deleted int, retErr error) {
	if now.IsZero() {
		return 0, ErrPublicURLInvalid
	}
	if err := d.requireOpen(); err != nil {
		return 0, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return 0, fmt.Errorf("begin saved URL retirement: %w", err)
	}
	defer rollback(ctx, tx, "retire saved public URLs", &retErr)()
	queries := controlstatedb.New(tx)
	routes, err := queries.LockDueSavedPublicURLRetirements(ctx, controlstatedb.LockDueSavedPublicURLRetirementsParams{
		IdleBefore:    timestamptz(now.Add(-savedURLIdlePeriod)),
		RecoverBefore: timestamptz(now.Add(-savedURLRecoveryPeriod)), BatchSize: savedURLRetireBatch,
	})
	if err != nil {
		return 0, fmt.Errorf("lock idle saved public URLs: %w", err)
	}
	for _, route := range routes {
		latest, err := queries.LatestClosedPublicURLPublishRun(ctx, route.ID)
		if err != nil && err != pgx.ErrNoRows {
			return 0, fmt.Errorf("read last publish run for idle URL: %w", err)
		}
		idleSince := route.CreatedAt.Time
		if err == nil && latest.Time.After(idleSince) {
			idleSince = latest.Time
		}
		if route.IdleRecoveryStartedAt.Valid {
			if idleSince.After(route.IdleRecoveryStartedAt.Time) {
				if _, err := queries.SetSavedPublicURLRecovery(ctx, controlstatedb.SetSavedPublicURLRecoveryParams{PublicURLID: route.ID}); err != nil {
					return 0, fmt.Errorf("end recovered public URL idle window: %w", err)
				}
				continue
			}
			if now.Before(route.IdleRecoveryStartedAt.Time.Add(savedURLRecoveryPeriod)) {
				continue
			}
			if err := quarantineTCPPortClaim(ctx, queries, route.ID, now); err != nil {
				return 0, fmt.Errorf("quarantine retired public URL port: %w", err)
			}
			updated, err := queries.DeletePublicURL(ctx, controlstatedb.DeletePublicURLParams{
				DeletedAt: timestamptz(now), PublicURLID: route.ID, ExpectedMutationRevision: route.MutationRevision,
			})
			if err != nil {
				return 0, fmt.Errorf("delete retired public URL: %w", err)
			}
			if updated != 1 {
				return 0, ErrPublicURLMutationStale
			}
			if err := queries.InsertIdlePublicURLDeleteAuditEvent(ctx, controlstatedb.InsertIdlePublicURLDeleteAuditEventParams{
				RequestID: "idle_retirement/" + route.ID, PublicURLID: route.ID, OccurredAt: timestamptz(now),
			}); err != nil {
				return 0, fmt.Errorf("audit retired public URL: %w", err)
			}
			deleted++
			continue
		}
		started := now
		if _, err := queries.SetSavedPublicURLRecovery(ctx, controlstatedb.SetSavedPublicURLRecoveryParams{
			StartedAt: timestamptz(started), PublicURLID: route.ID,
		}); err != nil {
			return 0, fmt.Errorf("start saved public URL recovery: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit saved URL retirement: %w", err)
	}
	return deleted, nil
}
