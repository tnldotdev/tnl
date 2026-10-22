package controlstate

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/security/credentials"
)

func (d *Database) ClosePublishRun(ctx context.Context, publishRunID string, token credentials.PublishRunToken, now time.Time) (retErr error) {
	ctx, finish := d.observeOperation(ctx, "ClosePublishRun")
	defer func() { finish(retErr) }()
	if !validStateText(publishRunID) {
		return ErrPublishRunCredential
	}
	tokenID, tokenHash, err := credentials.ParsePublishRunToken(token)
	if err != nil {
		return ErrPublishRunCredential
	}
	if err := d.requireOpen(); err != nil {
		return err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("controlstate: close publish run: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "close publish run", &retErr)()
	queries := controlstatedb.New(tx)
	pendingEvents := pendingIngressRoutingTableEvents{}
	before, err := queries.GetPublishRun(ctx, publishRunID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrPublishRunCredential
	}
	if err != nil {
		return fmt.Errorf("controlstate: close publish run: read session: %w", err)
	}
	route, err := queries.LockPublicURLForRun(ctx, before.PublicURLID)
	if err != nil {
		return fmt.Errorf("controlstate: close publish run: lock public_url: %w", err)
	}
	session, err := queries.LockPublishRun(ctx, publishRunID)
	if err != nil {
		return fmt.Errorf("controlstate: close publish run: lock session: %w", err)
	}
	if tokenID.String() != session.PublishRunTokenID || !credentials.SecretHashMatches(session.PublishRunTokenDigest, tokenHash) {
		return ErrPublishRunCredential
	}
	if session.ClosedAt.Valid {
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("controlstate: close publish run: commit retry: %w", err)
		}
		return nil
	}
	if err := closePublishRun(ctx, queries, &pendingEvents, route, session, PublishRunClosed, now, "publisher_closed"); err != nil {
		return err
	}
	if err := pendingEvents.publish(ctx, queries); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("controlstate: close publish run: commit: %w", err)
	}
	return nil
}

func closeOpenPublishRun(
	ctx context.Context,
	queries *controlstatedb.Queries,
	pendingEvents *pendingIngressRoutingTableEvents,
	route controlstatedb.ControlPublicUrl,
	now time.Time,
	reason string,
) error {
	sessions, err := queries.ListOpenPublishRuns(ctx, route.ID)
	if err != nil {
		return fmt.Errorf("controlstate: close publish run: read open session: %w", err)
	}
	for _, session := range sessions {
		if err := closePublishRun(ctx, queries, pendingEvents, route, session, PublishRunClosed, now, reason); err != nil {
			return err
		}
	}
	return nil
}

// the caller holds the public URL row through commit, keeping the live/expired
// result valid. Closed is false if another control closed the publish run first.
func expireStaleOpenPublishRun(
	ctx context.Context,
	queries *controlstatedb.Queries,
	pendingEvents *pendingIngressRoutingTableEvents,
	route controlstatedb.ControlPublicUrl,
	now time.Time,
) (live, closed bool, retErr error) {
	live, count, err := expireStaleOpenPublishRuns(ctx, queries, pendingEvents, route, now)
	return live, count > 0, err
}

func expireStaleOpenPublishRuns(ctx context.Context, queries *controlstatedb.Queries, pendingEvents *pendingIngressRoutingTableEvents,
	route controlstatedb.ControlPublicUrl, now time.Time) (live bool, closed int, retErr error) {
	sessions, err := queries.ListOpenPublishRuns(ctx, route.ID)
	if err != nil {
		return false, 0, fmt.Errorf("controlstate: expire publish run: read open session: %w", err)
	}
	for _, session := range sessions {
		oneLive, oneClosed, err := expireOpenPublishRun(ctx, queries, pendingEvents, route, session, now)
		if err != nil {
			return false, 0, err
		}
		live = live || oneLive
		if oneClosed {
			closed++
		}
	}
	return live, closed, nil
}

func expireOpenPublishRun(ctx context.Context, queries *controlstatedb.Queries, pendingEvents *pendingIngressRoutingTableEvents,
	route controlstatedb.ControlPublicUrl, session controlstatedb.ControlPublishRun, now time.Time) (bool, bool, error) {
	closedAt := now
	reason := "publisher_expired"
	if session.PublisherExpiresAt.Valid {
		closedAt = session.PublisherExpiresAt.Time
	}
	guestID, err := queries.GuestForPublicURL(ctx, route.ID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return false, false, fmt.Errorf("controlstate: expire publish run: read guest owner: %w", err)
	}
	if err == nil {
		guest, err := queries.GetGuestTrialByID(ctx, guestID)
		if err != nil {
			return false, false, fmt.Errorf("controlstate: expire publish run: read guest trial: %w", err)
		}
		if guest.ExpiresAt.Valid && guest.ExpiresAt.Time.Before(closedAt) {
			closedAt, reason = guest.ExpiresAt.Time, "guest_expired"
		}
		if guest.ActiveReadyAt.Valid {
			remaining := GuestReadyAllowance - time.Duration(guest.UsedReadyNs)
			if remaining < 0 {
				remaining = 0
			}
			deadline := guest.ActiveReadyAt.Time.Add(remaining)
			if deadline.Before(closedAt) {
				closedAt, reason = deadline, "guest_ready_limit"
			}
		}
		if guest.UsedBytes >= GuestByteAllowance && now.Before(closedAt) {
			closedAt, reason = now, "guest_transfer_limit"
		}
	}
	if closedAt.After(now) {
		return true, false, nil
	}
	if err := closePublishRun(ctx, queries, pendingEvents, route, session, PublishRunExpired, closedAt, reason); err != nil {
		return false, false, err
	}
	return false, true, nil
}

func closePublishRun(
	ctx context.Context,
	queries *controlstatedb.Queries,
	pendingEvents *pendingIngressRoutingTableEvents,
	route controlstatedb.ControlPublicUrl,
	session controlstatedb.ControlPublishRun,
	state PublishRunState,
	now time.Time,
	reason string,
) error {
	if session.ReadyAt.Valid {
		// the event and closure commit together. only this terminal path may
		// authorize ingress to retire lifetime totals for the exact run.
		session.ClosedAt = timestamptz(now)
		if _, err := pendingEvents.addRouteEvent(ctx, queries, route, session, nil, "public_url_tombstone", now); err != nil {
			return err
		}
	}
	if err := queries.CancelPublishRunACMEOrders(ctx, controlstatedb.CancelPublishRunACMEOrdersParams{
		CanceledAt: timestamptz(now), PublishRunID: session.ID,
	}); err != nil {
		return fmt.Errorf("controlstate: close publish run: cancel certificate orders: %w", err)
	}
	if err := queries.CancelPublishRunACMEAuthorizations(ctx, controlstatedb.CancelPublishRunACMEAuthorizationsParams{
		CanceledAt: timestamptz(now), PublishRunID: session.ID,
	}); err != nil {
		return fmt.Errorf("controlstate: close publish run: cancel certificate authorizations: %w", err)
	}
	if _, err := queries.CancelOpenPublicURLRecoveryEpisode(ctx, controlstatedb.CancelOpenPublicURLRecoveryEpisodeParams{
		CanceledAt: timestamptz(now), PublicURLID: route.ID, PublishRunNumber: session.PublishRunNumber,
	}); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("controlstate: close publish run: cancel recovery episode: %w", err)
	}
	if err := queries.ClosePublishRunConnections(ctx, controlstatedb.ClosePublishRunConnectionsParams{
		ClosedAt: timestamptz(now), PublishRunID: session.ID,
	}); err != nil {
		return fmt.Errorf("controlstate: close publish run: close publisher connections: %w", err)
	}
	if _, err := queries.ClosePublishRun(ctx, controlstatedb.ClosePublishRunParams{
		State: string(state), ClosedAt: timestamptz(now), CloseReason: text(reason), PublishRunID: session.ID,
	}); err != nil {
		return fmt.Errorf("controlstate: close publish run: update session: %w", err)
	}
	if _, err := queries.FinishGuestPublishRun(ctx, controlstatedb.FinishGuestPublishRunParams{
		PublishRunID: text(session.ID), ClosedAt: timestamptz(now), CloseReason: reason,
	}); err != nil {
		return fmt.Errorf("controlstate: finish guest publish run: %w", err)
	}
	return nil
}
