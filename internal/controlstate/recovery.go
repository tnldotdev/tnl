package controlstate

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

var ErrRouteRecoveryEpisodeStale = errors.New("controlstate: route recovery episode is stale")

// RouteRecoveryObservation is one stored route recovery measurement.
type RouteRecoveryObservation struct {
	EpisodeID       uint64
	RouteID         string
	RouteVersion    uint64
	OpenedAt        time.Time
	ObservedAt      time.Time
	ObservedSeconds float64
}

// ObserveRouteRecovery closes one open episode and updates its cumulative
// histogram in a transaction. Repeating an observed episode is safe.
func (d *Database) ObserveRouteRecovery(
	ctx context.Context,
	ingressIdentity IngressLeaseIdentity,
	routeID string,
	routeVersion uint64,
	episodeID uint64,
	observedAt time.Time,
) (result RouteRecoveryObservation, retErr error) {
	if err := validateIngressLeaseIdentity(ingressIdentity); err != nil {
		return RouteRecoveryObservation{}, err
	}
	if !validStateText(routeID) {
		return RouteRecoveryObservation{}, errors.New("controlstate: recovery route ID is invalid")
	}
	if _, ok := positiveInt64(routeVersion); !ok {
		return RouteRecoveryObservation{}, errors.New("controlstate: recovery route version is invalid")
	}
	if _, ok := positiveInt64(episodeID); !ok {
		return RouteRecoveryObservation{}, errors.New("controlstate: recovery episode ID is invalid")
	}
	if err := d.requireOpen(); err != nil {
		return RouteRecoveryObservation{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return RouteRecoveryObservation{}, fmt.Errorf("controlstate: observe route recovery: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "observe route recovery", &retErr)()
	queries := controlstatedb.New(tx)
	if _, err := lockCurrentIngressLease(ctx, queries, ingressIdentity, observedAt); err != nil {
		return RouteRecoveryObservation{}, err
	}
	episode, err := queries.LockRouteRecoveryEpisode(ctx, positive(episodeID))
	if errors.Is(err, pgx.ErrNoRows) {
		return RouteRecoveryObservation{}, ErrRouteRecoveryEpisodeStale
	}
	if err != nil {
		return RouteRecoveryObservation{}, fmt.Errorf("controlstate: observe route recovery: lock episode: %w", err)
	}
	if episode.RouteID != routeID || !matchesPositiveInt64(episode.RouteVersion, routeVersion) || !episode.OpenedAt.Valid {
		return RouteRecoveryObservation{}, ErrRouteRecoveryEpisodeStale
	}
	if episode.State == "observed" && episode.ObservedAt.Valid && episode.ObservedSeconds.Valid {
		if err := tx.Commit(ctx); err != nil {
			return RouteRecoveryObservation{}, fmt.Errorf("controlstate: observe route recovery: commit retry: %w", err)
		}
		return recoveryObservation(episode), nil
	}
	if episode.State != "open" || observedAt.Before(episode.OpenedAt.Time) {
		return RouteRecoveryObservation{}, ErrRouteRecoveryEpisodeStale
	}
	seconds := observedAt.Sub(episode.OpenedAt.Time).Seconds()
	episode, err = queries.ObserveRouteRecoveryEpisode(ctx, controlstatedb.ObserveRouteRecoveryEpisodeParams{
		ObservedAt: timestamptz(observedAt), ObservedSeconds: float8(seconds),
		EpisodeID: positive(episodeID), RouteID: routeID, RouteVersion: positive(routeVersion),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return RouteRecoveryObservation{}, ErrRouteRecoveryEpisodeStale
	}
	if err != nil {
		return RouteRecoveryObservation{}, fmt.Errorf("controlstate: observe route recovery: close episode: %w", err)
	}
	if _, err := queries.UpdateRouteRecoveryHistogram(ctx, controlstatedb.UpdateRouteRecoveryHistogramParams{
		ObservedSeconds: seconds, UpdatedAt: timestamptz(observedAt),
	}); err != nil {
		return RouteRecoveryObservation{}, fmt.Errorf("controlstate: observe route recovery: update histogram: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return RouteRecoveryObservation{}, fmt.Errorf("controlstate: observe route recovery: commit: %w", err)
	}
	return recoveryObservation(episode), nil
}

func recoveryObservation(episode controlstatedb.ControlRouteRecoveryEpisode) RouteRecoveryObservation {
	return RouteRecoveryObservation{
		EpisodeID: uint64(episode.EpisodeID), RouteID: episode.RouteID,
		RouteVersion: uint64(episode.RouteVersion), OpenedAt: episode.OpenedAt.Time,
		ObservedAt: episode.ObservedAt.Time, ObservedSeconds: episode.ObservedSeconds.Float64,
	}
}

func float8(value float64) pgtype.Float8 {
	return pgtype.Float8{Float64: value, Valid: true}
}
