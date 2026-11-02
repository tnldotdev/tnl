package state

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/observability"
)

// HeartbeatPublishRun extends one publish run and returns current or
// replacement publisher connection assignments.
func (d *Database) HeartbeatPublishRun(
	ctx context.Context,
	authentication PublishRunAuthentication,
	now time.Time,
	leaseDuration time.Duration,
	connectionCredentialDuration time.Duration,
) (result PublishRunSetup, retErr error) {
	ctx, finish := d.observeOperation(ctx, "HeartbeatPublishRun")
	defer func() { finish(retErr) }()
	if err := validatePublishRunAuthentication(authentication); err != nil {
		return PublishRunSetup{}, err
	}
	if leaseDuration <= 0 || connectionCredentialDuration <= 0 {
		return PublishRunSetup{}, errors.New("controlstate: publish-run heartbeat durations must be positive")
	}
	if err := d.requireOpen(); err != nil {
		return PublishRunSetup{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return PublishRunSetup{}, fmt.Errorf("controlstate: heartbeat publish run: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "heartbeat publish run", &retErr)()
	queries := controlstatedb.New(tx)
	pendingEvents := pendingIngressRoutingTableEvents{}
	route, session, err := lockAuthenticatedPublishRun(ctx, queries, authentication, now)
	if err != nil {
		return PublishRunSetup{}, err
	}
	live, err := d.publisherRunLive(ctx, queries, route, session, now)
	if err != nil {
		return PublishRunSetup{}, err
	}
	if !live {
		if err := closePublishRun(ctx, queries, &pendingEvents, route, session, PublishRunClosed, now, "publisher_grant_revoked"); err != nil {
			return PublishRunSetup{}, err
		}
		if err := pendingEvents.publish(ctx, queries); err != nil {
			return PublishRunSetup{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return PublishRunSetup{}, err
		}
		return PublishRunSetup{}, ErrPublisherIdentity
	}
	spentReason, err := queries.GuestRunAllowanceSpent(ctx, controlstatedb.GuestRunAllowanceSpentParams{
		PublishRunID: text(session.ID), Now: timestamptz(now),
	})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return PublishRunSetup{}, fmt.Errorf("controlstate: read guest trial allowance: %w", err)
	}
	if spentReason != "" {
		if err := closePublishRun(ctx, queries, &pendingEvents, route, session, PublishRunClosed, now, spentReason); err != nil {
			return PublishRunSetup{}, err
		}
		if err := pendingEvents.publish(ctx, queries); err != nil {
			return PublishRunSetup{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return PublishRunSetup{}, err
		}
		return PublishRunSetup{}, ErrGuestTrialSpent
	}
	if route.Ephemeral {
		if _, err := queries.RenewEphemeralPublicURLExpiry(ctx, controlstatedb.RenewEphemeralPublicURLExpiryParams{
			ExpiresAt: timestamptz(now.Add(ephemeralPublicURLGracePeriod)), PublicURLID: route.ID,
		}); err != nil {
			return PublishRunSetup{}, fmt.Errorf("controlstate: heartbeat publish run: renew ephemeral public_url: %w", err)
		}
	}
	previousExpiresAt := session.PublisherExpiresAt.Time
	session, err = queries.HeartbeatPublishRun(ctx, controlstatedb.HeartbeatPublishRunParams{
		HeartbeatAt: timestamptz(now), ExpiresAt: timestamptz(now.Add(leaseDuration)),
		PublishRunID: session.ID, PublicURLID: route.ID, PublishRunNumber: session.PublishRunNumber,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return PublishRunSetup{}, ErrPublishRunStale
	}
	if err != nil {
		return PublishRunSetup{}, fmt.Errorf("controlstate: heartbeat publish run: update lease: %w", err)
	}
	leaseExtended := session.PublisherExpiresAt.Time.After(previousExpiresAt)
	connections, err := validReadyPublisherConnections(ctx, queries, session.ID, now)
	if err != nil {
		return PublishRunSetup{}, err
	}
	removedReadyConnection := false
	var replenishment replenishmentResult
	if len(connections) != publishRunConnectionCount {
		replenishment, err = replenishPublishRunConnections(
			ctx, queries, session, authentication.PublishRunToken, connections, now, connectionCredentialDuration,
		)
		if err != nil {
			return PublishRunSetup{}, err
		}
		removedReadyConnection = replenishment.removedReady
		connections, err = validReadyPublisherConnections(ctx, queries, session.ID, now)
		if err != nil {
			return PublishRunSetup{}, err
		}
	}
	if session.PolicyDenials < 0 {
		return PublishRunSetup{}, errors.New("controlstate: heartbeat publish run: invalid policy denial count")
	}
	if session.ReadyAt.Valid && removedReadyConnection {
		if err := openPublicURLRecoveryEpisode(ctx, queries, route.ID, session.PublishRunNumber, now); err != nil {
			return PublishRunSetup{}, err
		}
	}
	published, err := publishRunRoutingPublished(ctx, queries, session)
	if err != nil {
		return PublishRunSetup{}, err
	}
	if published && (leaseExtended && len(connections) > 0 || removedReadyConnection) {
		eventKind := publicURLRoutingTableEventKind(len(connections) > 0)
		if _, err := pendingEvents.addRouteEvent(ctx, queries, route, session, connections, eventKind, now); err != nil {
			return PublishRunSetup{}, err
		}
	}
	setup, err := loadPublishRunSetupWithToken(ctx, queries, authentication.PublishRunToken, session)
	if err != nil {
		return PublishRunSetup{}, err
	}
	setup.PolicyDenials = uint64(session.PolicyDenials)
	if err := pendingEvents.publish(ctx, queries); err != nil {
		return PublishRunSetup{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return PublishRunSetup{}, fmt.Errorf("controlstate: heartbeat publish run: commit: %w", err)
	}
	metrics := d.activity.metrics.Load()
	for reason, count := range replenishment.replacements {
		metrics.AddAssignmentReplacements(reason, count)
	}
	if replenishment.attempted {
		outcome := observability.PlacementPlaced
		if replenishment.unavailable {
			outcome = observability.PlacementUnavailable
		}
		metrics.ObservePlacement("replenish", outcome)
	}
	return setup, nil
}
