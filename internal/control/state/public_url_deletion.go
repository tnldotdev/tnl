package controlstate

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func (d *Database) DeletePublicURL(ctx context.Context, identityID, publicURLID string, now time.Time) (retErr error) {
	return d.deletePublicURL(ctx, AuthorizedPublicURLDeleteRequest{PublicURLID: publicURLID, ActingIdentityID: identityID}, now)
}

func (d *Database) DeleteAuthorizedPublicURL(
	ctx context.Context,
	request AuthorizedPublicURLDeleteRequest,
	now time.Time,
) error {
	return d.deletePublicURL(ctx, request, now)
}

func (d *Database) deletePublicURL(ctx context.Context, request AuthorizedPublicURLDeleteRequest, now time.Time) (retErr error) {
	identityID := request.ActingIdentityID
	publicURLID := request.PublicURLID
	if !validStateText(identityID) || !validStateText(publicURLID) {
		return ErrPublicURLInvalid
	}
	if request.GuestID != "" && (!validStateText(request.GuestID) || !validStateText(request.TeamID) ||
		request.PolicyRevision == 0 || request.ExpectedMutationRevision == 0) {
		return ErrPublicURLInvalid
	}
	if err := d.requireOpen(); err != nil {
		return err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("controlstate: delete public_url: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "delete route", &retErr)()
	queries := controlstatedb.New(tx)
	pendingEvents := pendingIngressRoutingTableEvents{}
	var route controlstatedb.ControlPublicUrl
	if request.GuestID == "" && request.PublisherIdentityID != "" {
		if _, err := queries.LockLocalPublicURLTeamForMutation(ctx, publicURLID); errors.Is(err, pgx.ErrNoRows) {
			return ErrPublicURLNotFound
		} else if err != nil {
			return fmt.Errorf("controlstate: delete ad-hoc public_url: lock team: %w", err)
		}
		route, err = queries.LockPublicURLForRun(ctx, publicURLID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrPublicURLNotFound
		}
		if err != nil {
			return fmt.Errorf("controlstate: delete ad-hoc public_url: lock URL: %w", err)
		}
		if err := d.validatePublisherDeletion(ctx, queries, request, route, now); err != nil {
			return err
		}
	} else if request.GuestID == "" {
		if _, err := queries.LockLocalPublicURLTeamForMutation(ctx, publicURLID); errors.Is(err, pgx.ErrNoRows) {
			return ErrPublicURLNotFound
		} else if err != nil {
			return fmt.Errorf("controlstate: delete public_url: lock team: %w", err)
		}
		row, err := queries.LockIdentityPublicURLForDelete(ctx, controlstatedb.LockIdentityPublicURLForDeleteParams{
			IdentityID: identityID, PublicURLID: publicURLID,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrPublicURLNotFound
		}
		if err != nil {
			return fmt.Errorf("controlstate: delete public_url: lock public_url: %w", err)
		}
		if row.ActorRole == "member" && (!row.MembershipID.Valid || row.MembershipID.String != row.ActorMembershipID) {
			return ErrPublicURLAccess
		}
		route = publicURLModelFromDeleteRow(row)
	} else {
		owned, err := queries.GuestOwnsPublicURL(ctx, controlstatedb.GuestOwnsPublicURLParams{GuestID: request.GuestID, PublicURLID: publicURLID})
		if err != nil || !owned || request.ActingIdentityID != request.GuestID {
			return ErrPublicURLAccess
		}
		route, err = queries.LockPublicURLForRun(ctx, publicURLID)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && route.TeamID != request.TeamID {
			return ErrPublicURLNotFound
		}
		if err != nil {
			return fmt.Errorf("controlstate: delete public_url: lock public_url: %w", err)
		}
		if !matchesPositiveInt64(route.MutationRevision, request.ExpectedMutationRevision) {
			return ErrPublicURLMutationStale
		}
	}
	if err = rejectProjectManagedDefinition(ctx, tx, publicURLID); err != nil {
		return err
	}
	expectedMutationRevision := route.MutationRevision
	if request.ExpectedMutationRevision != 0 {
		if !matchesPositiveInt64(route.MutationRevision, request.ExpectedMutationRevision) {
			return ErrPublicURLMutationStale
		}
		expectedMutationRevision = positive(request.ExpectedMutationRevision)
	}
	if err := closeOpenPublishRun(ctx, queries, &pendingEvents, route, now, "public_url_deleted"); err != nil {
		return err
	}
	updated, err := queries.DeletePublicURL(ctx, controlstatedb.DeletePublicURLParams{
		DeletedAt: timestamptz(now), PublicURLID: publicURLID, ExpectedMutationRevision: expectedMutationRevision,
	})
	if err != nil {
		return fmt.Errorf("controlstate: delete public_url: update public_url: %w", err)
	}
	if updated != 1 {
		return ErrPublicURLNotFound
	}
	requestID, err := opaqueid.New(opaqueid.RequestPrefix)
	if err != nil {
		return fmt.Errorf("controlstate: delete public_url: generate request ID: %w", err)
	}
	if err := queries.InsertPublicURLDeleteAuditEvent(ctx, controlstatedb.InsertPublicURLDeleteAuditEventParams{
		ActorIdentityID: text(identityID), RequestID: requestID, PublicURLID: publicURLID, OccurredAt: timestamptz(now),
	}); err != nil {
		return fmt.Errorf("controlstate: delete public_url: insert audit event: %w", err)
	}
	if err := pendingEvents.publish(ctx, queries); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("controlstate: delete public_url: commit: %w", err)
	}
	return nil
}
