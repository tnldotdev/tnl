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

var ErrPublicURLRecoveryEpisodeStale = errors.New("controlstate: route recovery episode is stale")

// PublicURLRecoveryObservation is one stored route recovery measurement.
type PublicURLRecoveryObservation struct {
	RecoveryEpisodeID uint64
	PublicURLID       string
	PublishRunNumber  uint64
	OpenedAt          time.Time
	ObservedAt        time.Time
	ObservedSeconds   float64
}

// ObservePublicURLRecovery closes one open episode and updates its cumulative
// histogram in a transaction. Repeating an observed episode is safe.
func (d *Database) ObservePublicURLRecovery(
	ctx context.Context,
	ingressIdentity IngressLeaseIdentity,
	publicURLID string,
	publishRunNumber uint64,
	recoveryEpisodeID uint64,
	observedAt time.Time,
) (result PublicURLRecoveryObservation, retErr error) {
	if err := validateIngressLeaseIdentity(ingressIdentity); err != nil {
		return PublicURLRecoveryObservation{}, err
	}
	if !validStateText(publicURLID) {
		return PublicURLRecoveryObservation{}, errors.New("controlstate: recovery route ID is invalid")
	}
	if _, ok := positiveInt64(publishRunNumber); !ok {
		return PublicURLRecoveryObservation{}, errors.New("controlstate: recovery publish run number is invalid")
	}
	if _, ok := positiveInt64(recoveryEpisodeID); !ok {
		return PublicURLRecoveryObservation{}, errors.New("controlstate: recovery episode ID is invalid")
	}
	if err := d.requireOpen(); err != nil {
		return PublicURLRecoveryObservation{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return PublicURLRecoveryObservation{}, fmt.Errorf("controlstate: observe route recovery: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "observe route recovery", &retErr)()
	queries := controlstatedb.New(tx)
	if _, err := lockCurrentIngressLease(ctx, queries, ingressIdentity, observedAt); err != nil {
		return PublicURLRecoveryObservation{}, err
	}
	episode, err := queries.LockPublicURLRecoveryEpisode(ctx, positive(recoveryEpisodeID))
	if errors.Is(err, pgx.ErrNoRows) {
		return PublicURLRecoveryObservation{}, ErrPublicURLRecoveryEpisodeStale
	}
	if err != nil {
		return PublicURLRecoveryObservation{}, fmt.Errorf("controlstate: observe route recovery: lock episode: %w", err)
	}
	if episode.PublicURLID != publicURLID || !matchesPositiveInt64(episode.PublishRunNumber, publishRunNumber) || !episode.OpenedAt.Valid {
		return PublicURLRecoveryObservation{}, ErrPublicURLRecoveryEpisodeStale
	}
	if episode.State == "observed" && episode.ObservedAt.Valid && episode.ObservedSeconds.Valid {
		if err := tx.Commit(ctx); err != nil {
			return PublicURLRecoveryObservation{}, fmt.Errorf("controlstate: observe route recovery: commit retry: %w", err)
		}
		return recoveryObservation(episode), nil
	}
	if episode.State != "open" || observedAt.Before(episode.OpenedAt.Time) {
		return PublicURLRecoveryObservation{}, ErrPublicURLRecoveryEpisodeStale
	}
	seconds := observedAt.Sub(episode.OpenedAt.Time).Seconds()
	episode, err = queries.ObservePublicURLRecoveryEpisode(ctx, controlstatedb.ObservePublicURLRecoveryEpisodeParams{
		ObservedAt: timestamptz(observedAt), ObservedSeconds: float8(seconds),
		RecoveryEpisodeID: positive(recoveryEpisodeID), PublicURLID: publicURLID, PublishRunNumber: positive(publishRunNumber),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return PublicURLRecoveryObservation{}, ErrPublicURLRecoveryEpisodeStale
	}
	if err != nil {
		return PublicURLRecoveryObservation{}, fmt.Errorf("controlstate: observe route recovery: close episode: %w", err)
	}
	if _, err := queries.UpdatePublicURLRecoveryHistogram(ctx, controlstatedb.UpdatePublicURLRecoveryHistogramParams{
		ObservedSeconds: seconds, UpdatedAt: timestamptz(observedAt),
	}); err != nil {
		return PublicURLRecoveryObservation{}, fmt.Errorf("controlstate: observe route recovery: update histogram: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return PublicURLRecoveryObservation{}, fmt.Errorf("controlstate: observe route recovery: commit: %w", err)
	}
	return recoveryObservation(episode), nil
}

func recoveryObservation(episode controlstatedb.ControlPublicUrlRecoveryEpisode) PublicURLRecoveryObservation {
	return PublicURLRecoveryObservation{
		RecoveryEpisodeID: uint64(episode.RecoveryEpisodeID), PublicURLID: episode.PublicURLID,
		PublishRunNumber: uint64(episode.PublishRunNumber), OpenedAt: episode.OpenedAt.Time,
		ObservedAt: episode.ObservedAt.Time, ObservedSeconds: episode.ObservedSeconds.Float64,
	}
}

func float8(value float64) pgtype.Float8 {
	return pgtype.Float8{Float64: value, Valid: true}
}
