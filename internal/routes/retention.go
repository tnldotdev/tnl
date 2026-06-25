package routes

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/tnldotdev/tnl/internal/state/statedb"
)

const (
	routeStateRetention     = 365 * 24 * time.Hour
	routeStatePruneInterval = time.Hour
	retentionBatchSize      = 5000
)

// RunStateRetention prunes obsolete route state immediately and at a bounded interval until ctx is canceled.
func RunStateRetention(ctx context.Context, db *sql.DB, report func(error)) {
	store := &Store{db: db, queries: statedb.New(db)}
	for {
		if err := store.pruneRouteState(ctx, time.Now()); err != nil {
			if ctx.Err() != nil {
				return
			}
			if report != nil {
				report(err)
			}
		}
		timer := time.NewTimer(routeStatePruneInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (s *Store) pruneRouteState(ctx context.Context, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("routes: begin state retention: %w", err)
	}
	defer tx.Rollback()
	queries := s.queries.WithTx(tx)
	batchSize := int64(retentionBatchSize)
	cutoff := now.UTC().Add(-routeStateRetention).UnixNano()
	attemptCutoff := now.UTC().Add(-time.Hour).UnixNano()

	if _, err := queries.DeleteObsoleteRouteSessions(ctx, batchSize); err != nil {
		return fmt.Errorf("routes: prune sessions: %w", err)
	}
	if _, err := queries.DeleteObsoleteRouteAllowedIPPrefixes(ctx, batchSize); err != nil {
		return fmt.Errorf("routes: prune IP policies: %w", err)
	}
	if _, err := queries.DeleteExpiredRouteAuthorizationUses(ctx, statedb.DeleteExpiredRouteAuthorizationUsesParams{
		Now: now.UTC().UnixNano(), BatchSize: batchSize,
	}); err != nil {
		return fmt.Errorf("routes: prune authorization uses: %w", err)
	}
	if _, err := queries.DeleteObsoleteCertificateIssuances(ctx, statedb.DeleteObsoleteCertificateIssuancesParams{
		AttemptCutoff: attemptCutoff, Now: now.UTC().UnixNano(), RetentionCutoff: cutoff, BatchSize: batchSize,
	}); err != nil {
		return fmt.Errorf("routes: prune certificate issuances: %w", err)
	}
	if _, err := queries.DeleteObsoleteDeletedRouteUsageSnapshots(ctx, statedb.DeleteObsoleteDeletedRouteUsageSnapshotsParams{
		Cutoff: cutoff, BatchSize: batchSize,
	}); err != nil {
		return fmt.Errorf("routes: prune deleted route usage: %w", err)
	}
	if err := queries.DeleteExpiredRouteLifecycleEvents(ctx, statedb.DeleteExpiredRouteLifecycleEventsParams{
		Cutoff: cutoff, BatchSize: batchSize,
	}); err != nil {
		return fmt.Errorf("routes: prune lifecycle events: %w", err)
	}
	if _, err := queries.DeleteObsoleteRouteRegistrations(ctx, statedb.DeleteObsoleteRouteRegistrationsParams{
		Cutoff: cutoff, BatchSize: batchSize,
	}); err != nil {
		return fmt.Errorf("routes: prune registrations: %w", err)
	}
	if _, err := queries.DeleteObsoleteDeletedRoutes(ctx, statedb.DeleteObsoleteDeletedRoutesParams{
		Cutoff: cutoff, BatchSize: batchSize,
	}); err != nil {
		return fmt.Errorf("routes: prune deleted routes: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("routes: commit state retention: %w", err)
	}
	return nil
}
