package state

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/security/credentials"
)

func (d *Database) markPublisherConnectionReady(
	ctx context.Context,
	request PublisherConnectionClaimRequest,
	now time.Time,
) (result ClaimedPublisherConnection, retErr error) {
	if err := validatePublisherConnectionClaim(request); err != nil {
		return ClaimedPublisherConnection{}, err
	}
	if err := d.requireOpen(); err != nil {
		return ClaimedPublisherConnection{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return ClaimedPublisherConnection{}, fmt.Errorf("controlstate: mark publisher connection ready: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "mark publisher connection ready", &retErr)()
	queries := controlstatedb.New(tx)
	pendingEvents := pendingIngressRoutingTableEvents{}
	route, session, err := lockPublishRunForPublisherConnection(ctx, queries, request, now)
	if err != nil {
		return ClaimedPublisherConnection{}, err
	}
	before, err := queries.GetPublisherConnectionForClaim(ctx, request.PublisherConnectionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ClaimedPublisherConnection{}, ErrPublisherConnectionUnavailable
	}
	if err != nil {
		return ClaimedPublisherConnection{}, fmt.Errorf("controlstate: mark publisher connection ready: lock assignment: %w", err)
	}
	beforeState := PublisherConnectionState(before.State)
	if !storedConnectionAssignmentMatches(before, request.ConnectionAssignmentIdentity) ||
		!publisherConnectionClaimMatches(before, request) ||
		beforeState != PublisherConnectionConnected && beforeState != PublisherConnectionReady {
		return ClaimedPublisherConnection{}, ErrConnectionAssignmentStale
	}
	lease, err := queries.GetRelayLeaseForReady(ctx, request.RelayID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ClaimedPublisherConnection{}, ErrRelayLeaseStale
	}
	if err != nil {
		return ClaimedPublisherConnection{}, fmt.Errorf("controlstate: mark publisher connection ready: lock relay lease: %w", err)
	}
	if err := validateClaimRelayLease(controlstatedb.GetRelayLeaseForClaimRow(lease), request.RelayLeaseIdentity, before.RelayServiceID, now); err != nil {
		return ClaimedPublisherConnection{}, err
	}
	row, err := queries.MarkPublisherConnectionReady(ctx, publisherConnectionClaimParams(request, now))
	if errors.Is(err, pgx.ErrNoRows) {
		return ClaimedPublisherConnection{}, ErrConnectionAssignmentStale
	}
	if err != nil {
		return ClaimedPublisherConnection{}, fmt.Errorf("controlstate: mark publisher connection ready: update assignment: %w", err)
	}
	connections, err := validReadyPublisherConnections(ctx, queries, session.ID, now)
	if err != nil {
		return ClaimedPublisherConnection{}, err
	}
	if beforeState != PublisherConnectionReady {
		if err := pendingEvents.addPublisherConnectionChanges(ctx, queries, route, session, connections, now); err != nil {
			return ClaimedPublisherConnection{}, err
		}
	}
	if err := pendingEvents.publish(ctx, queries); err != nil {
		return ClaimedPublisherConnection{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ClaimedPublisherConnection{}, fmt.Errorf("controlstate: mark publisher connection ready: commit: %w", err)
	}
	return claimedPublisherConnection(row)
}

func (d *Database) disconnectPublisherConnection(
	ctx context.Context,
	request PublisherConnectionClaimRequest,
	now time.Time,
	unexpected bool,
) (result ClaimedPublisherConnection, retErr error) {
	if err := validatePublisherConnectionClaim(request); err != nil {
		return ClaimedPublisherConnection{}, err
	}
	if err := d.requireOpen(); err != nil {
		return ClaimedPublisherConnection{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return ClaimedPublisherConnection{}, fmt.Errorf("controlstate: disconnect publisher connection: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "disconnect publisher connection", &retErr)()
	queries := controlstatedb.New(tx)
	pendingEvents := pendingIngressRoutingTableEvents{}
	route, session, err := lockPublishRunForPublisherConnection(ctx, queries, request, now)
	if err != nil {
		return ClaimedPublisherConnection{}, err
	}
	before, err := queries.GetPublisherConnectionForClaim(ctx, request.PublisherConnectionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ClaimedPublisherConnection{}, ErrPublisherConnectionUnavailable
	}
	if err != nil {
		return ClaimedPublisherConnection{}, fmt.Errorf("controlstate: disconnect publisher connection: lock assignment: %w", err)
	}
	beforeState := PublisherConnectionState(before.State)
	if !storedConnectionAssignmentMatches(before, request.ConnectionAssignmentIdentity) ||
		!publisherConnectionClaimMatches(before, request) ||
		beforeState != PublisherConnectionConnected && beforeState != PublisherConnectionReady && beforeState != PublisherConnectionDraining {
		return ClaimedPublisherConnection{}, ErrConnectionAssignmentStale
	}
	row, err := queries.DisconnectPublisherConnection(ctx, disconnectPublisherConnectionParams(request, now))
	if errors.Is(err, pgx.ErrNoRows) {
		return ClaimedPublisherConnection{}, ErrConnectionAssignmentStale
	}
	if err != nil {
		return ClaimedPublisherConnection{}, fmt.Errorf("controlstate: disconnect publisher connection: update assignment: %w", err)
	}
	connections, err := validReadyPublisherConnections(ctx, queries, session.ID, now)
	if err != nil {
		return ClaimedPublisherConnection{}, err
	}
	if session.ReadyAt.Valid && beforeState == PublisherConnectionReady && unexpected {
		if err := openPublicURLRecoveryEpisode(ctx, queries, route.ID, session.PublishRunNumber, now); err != nil {
			return ClaimedPublisherConnection{}, err
		}
	}
	if beforeState == PublisherConnectionReady {
		if err := pendingEvents.addPublisherConnectionChanges(ctx, queries, route, session, connections, now); err != nil {
			return ClaimedPublisherConnection{}, err
		}
	}
	if err := pendingEvents.publish(ctx, queries); err != nil {
		return ClaimedPublisherConnection{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ClaimedPublisherConnection{}, fmt.Errorf("controlstate: disconnect publisher connection: commit: %w", err)
	}
	return claimedPublisherConnection(row)
}

func lockPublishRunForPublisherConnection(
	ctx context.Context,
	queries *controlstatedb.Queries,
	request PublisherConnectionClaimRequest,
	now time.Time,
) (controlstatedb.ControlPublicUrl, controlstatedb.ControlPublishRun, error) {
	route, err := queries.LockPublicURLForRun(ctx, request.PublicURLID)
	if errors.Is(err, pgx.ErrNoRows) {
		return controlstatedb.ControlPublicUrl{}, controlstatedb.ControlPublishRun{}, ErrConnectionAssignmentStale
	}
	if err != nil {
		return controlstatedb.ControlPublicUrl{}, controlstatedb.ControlPublishRun{}, fmt.Errorf("controlstate: lock publisher connection public_url: %w", err)
	}
	session, err := queries.LockPublishRun(ctx, request.PublishRunID)
	if errors.Is(err, pgx.ErrNoRows) {
		return controlstatedb.ControlPublicUrl{}, controlstatedb.ControlPublishRun{}, ErrConnectionAssignmentStale
	}
	if err != nil {
		return controlstatedb.ControlPublicUrl{}, controlstatedb.ControlPublishRun{}, fmt.Errorf("controlstate: lock publisher connection publish run: %w", err)
	}
	if PublicURLLifecycleState(route.LifecycleState) != PublicURLLifecycleEnabled || session.PublicURLID != request.PublicURLID ||
		!matchesPositiveInt64(session.PublishRunNumber, request.PublishRunNumber) || session.ClosedAt.Valid ||
		!session.PublisherExpiresAt.Valid || !session.PublisherExpiresAt.Time.After(now) {
		return controlstatedb.ControlPublicUrl{}, controlstatedb.ControlPublishRun{}, ErrConnectionAssignmentStale
	}
	return route, session, nil
}

func lockAuthenticatedPublishRun(
	ctx context.Context,
	queries *controlstatedb.Queries,
	authentication PublishRunAuthentication,
	now time.Time,
) (controlstatedb.ControlPublicUrl, controlstatedb.ControlPublishRun, error) {
	route, err := queries.LockPublicURLForRun(ctx, authentication.PublicURLID)
	if errors.Is(err, pgx.ErrNoRows) {
		return controlstatedb.ControlPublicUrl{}, controlstatedb.ControlPublishRun{}, ErrPublishRunStale
	}
	if err != nil {
		return controlstatedb.ControlPublicUrl{}, controlstatedb.ControlPublishRun{}, fmt.Errorf("controlstate: lock authenticated public_url: %w", err)
	}
	session, err := queries.LockPublishRun(ctx, authentication.PublishRunID)
	if errors.Is(err, pgx.ErrNoRows) {
		return controlstatedb.ControlPublicUrl{}, controlstatedb.ControlPublishRun{}, ErrPublishRunStale
	}
	if err != nil {
		return controlstatedb.ControlPublicUrl{}, controlstatedb.ControlPublishRun{}, fmt.Errorf("controlstate: lock authenticated publish run: %w", err)
	}
	if session.CloseReason.String == "publisher_revoked" && session.PublicURLID == authentication.PublicURLID && matchesPositiveInt64(session.PublishRunNumber, authentication.PublishRunNumber) {
		tokenID, digest, err := credentials.ParsePublishRunToken(authentication.PublishRunToken)
		if err != nil || tokenID.String() != session.PublishRunTokenID || !credentials.SecretHashMatches(session.PublishRunTokenDigest, digest) {
			return route, session, ErrPublishRunCredential
		}
		return route, session, ErrPublisherIdentity
	}
	if PublicURLLifecycleState(route.LifecycleState) != PublicURLLifecycleEnabled || session.PublicURLID != authentication.PublicURLID ||
		!matchesPositiveInt64(session.PublishRunNumber, authentication.PublishRunNumber) || session.ClosedAt.Valid ||
		!session.PublisherExpiresAt.Valid || !session.PublisherExpiresAt.Time.After(now) {
		return controlstatedb.ControlPublicUrl{}, controlstatedb.ControlPublishRun{}, ErrPublishRunStale
	}
	tokenID, tokenHash, err := credentials.ParsePublishRunToken(authentication.PublishRunToken)
	if err != nil || tokenID.String() != session.PublishRunTokenID ||
		!credentials.SecretHashMatches(session.PublishRunTokenDigest, tokenHash) {
		return controlstatedb.ControlPublicUrl{}, controlstatedb.ControlPublishRun{}, ErrPublishRunCredential
	}
	return route, session, nil
}
