package controlstate

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

var ErrInvitationNotFound = errors.New("controlstate: invitation not found")

type Invitation struct {
	ID                         string
	TeamID                     string
	MemberSlug                 string
	InitialRole                TeamRole
	NormalizedEmailRestriction string
	State                      InvitationState
	CreatedAt                  time.Time
	ExpiresAt                  time.Time
}

type InvitationSecret struct {
	Invitation Invitation
	Secret     string
}

type CreateInvitationRequest struct {
	IdentityID       string
	TeamID           string
	IdempotencyKey   string
	RequestDigest    [32]byte
	MemberSlug       string
	InitialRole      TeamRole
	ExpiresAt        time.Time
	EmailRestriction string
	RetrySecret      []byte
}

func (d *Database) ListTeamInvitations(
	ctx context.Context,
	identityID, teamID string,
	now time.Time,
) (result []Invitation, retErr error) {
	if !validStateText(identityID) || !validStateText(teamID) || now.IsZero() {
		return nil, ErrAuthorityInvalid
	}
	if err := d.requireOpen(); err != nil {
		return nil, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("controlstate: list team invitations: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "list team invitations", &retErr)()
	queries := controlstatedb.New(tx)
	actor, err := lockTeamActor(ctx, queries, identityID, teamID)
	if err != nil {
		return nil, err
	}
	actorRole := TeamRole(actor.ActorRole)
	if TeamKind(actor.Kind) != TeamKindOrganization || actorRole != TeamRoleAdmin && actorRole != TeamRoleOwner {
		return nil, ErrAuthorityAccess
	}
	if err := expireTeamInvitations(ctx, queries, teamID, now); err != nil {
		return nil, err
	}
	rows, err := queries.ListTeamInvitations(ctx, teamID)
	if err != nil {
		return nil, fmt.Errorf("controlstate: list team invitations: %w", err)
	}
	result = make([]Invitation, len(rows))
	for index, row := range rows {
		result[index] = invitationFromRow(
			row.ID, row.TeamID, row.MemberSlug, row.InitialRole, row.NormalizedEmailRestriction,
			row.State, row.CreatedAt, row.ExpiresAt,
		)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("controlstate: list team invitations: commit: %w", err)
	}
	return result, nil
}

func (d *Database) CreateTeamInvitation(
	ctx context.Context,
	request CreateInvitationRequest,
	now time.Time,
) (result InvitationSecret, retErr error) {
	normalizedEmail, err := normalizeEmailRestriction(request.EmailRestriction)
	if err != nil || !validStateText(request.IdentityID) || !validStateText(request.TeamID) ||
		!validIdempotencyKey(request.IdempotencyKey) || !validAuthorityLabel(request.MemberSlug) ||
		!request.InitialRole.valid() || now.IsZero() || !request.ExpiresAt.After(now) || len(request.RetrySecret) < 32 {
		return InvitationSecret{}, ErrAuthorityInvalid
	}
	token, tokenDigest, err := credentials.DeriveInvitationToken(request.RetrySecret, invitationRetryContext(request))
	if err != nil {
		return InvitationSecret{}, ErrAuthorityInvalid
	}
	if err := d.requireOpen(); err != nil {
		return InvitationSecret{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return InvitationSecret{}, fmt.Errorf("controlstate: create team invitation: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "create team invitation", &retErr)()
	queries := controlstatedb.New(tx)
	actor, err := lockTeamActor(ctx, queries, request.IdentityID, request.TeamID)
	if err != nil {
		return InvitationSecret{}, err
	}
	actorRole := TeamRole(actor.ActorRole)
	if TeamKind(actor.Kind) != TeamKindOrganization || actorRole != TeamRoleAdmin && actorRole != TeamRoleOwner ||
		request.InitialRole != TeamRoleMember && actorRole != TeamRoleOwner {
		return InvitationSecret{}, ErrAuthorityAccess
	}
	if err := expireTeamInvitations(ctx, queries, request.TeamID, now); err != nil {
		return InvitationSecret{}, err
	}
	existing, err := queries.GetInvitationByIdempotency(ctx, controlstatedb.GetInvitationByIdempotencyParams{
		IdentityID: request.IdentityID, TeamID: request.TeamID, IdempotencyKey: request.IdempotencyKey,
	})
	if err == nil {
		if existing.TeamID != request.TeamID || subtle.ConstantTimeCompare(existing.RequestDigest, request.RequestDigest[:]) != 1 {
			return InvitationSecret{}, ErrAuthorityIdempotency
		}
		state := InvitationState(existing.State)
		if state != InvitationPending || !existing.ExpiresAt.Time.After(now) {
			if state == InvitationExpired {
				if err := tx.Commit(ctx); err != nil {
					return InvitationSecret{}, fmt.Errorf("controlstate: create team invitation: commit expiration: %w", err)
				}
			}
			return InvitationSecret{}, ErrAuthorityConflict
		}
		if subtle.ConstantTimeCompare(existing.TokenDigest, tokenDigest[:]) != 1 {
			return InvitationSecret{}, ErrAuthorityConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return InvitationSecret{}, fmt.Errorf("controlstate: create team invitation: commit retry: %w", err)
		}
		return InvitationSecret{Invitation: invitationFromRow(
			existing.ID, existing.TeamID, existing.MemberSlug, existing.InitialRole,
			existing.NormalizedEmailRestriction, existing.State, existing.CreatedAt, existing.ExpiresAt,
		), Secret: token.String()}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return InvitationSecret{}, fmt.Errorf("controlstate: create team invitation: read idempotent invitation: %w", err)
	}
	reservationID, err := opaqueid.New(opaqueid.SlugReservationPrefix)
	if err != nil {
		return InvitationSecret{}, err
	}
	reservationID, err = queries.ReserveInvitedMemberSlug(ctx, controlstatedb.ReserveInvitedMemberSlugParams{
		ID: reservationID, TeamID: request.TeamID, MemberSlug: request.MemberSlug,
		ReservedByIdentityID: text(request.IdentityID), CreatedAt: timestamp(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return InvitationSecret{}, ErrAuthorityConflict
	}
	if err != nil {
		return InvitationSecret{}, fmt.Errorf("controlstate: create team invitation: reserve member slug: %w", err)
	}
	invitationID, err := opaqueid.New(opaqueid.InvitationPrefix)
	if err != nil {
		return InvitationSecret{}, err
	}
	row, err := queries.CreateTeamInvitation(ctx, controlstatedb.CreateTeamInvitationParams{
		ID: invitationID, TeamID: request.TeamID, SlugReservationID: reservationID,
		InitialRole: string(request.InitialRole), InvitedByIdentityID: request.IdentityID,
		IdempotencyKey: request.IdempotencyKey, RequestDigest: request.RequestDigest[:], TokenDigest: tokenDigest[:],
		NormalizedEmailRestriction: nullableText(normalizedEmail),
		CreatedAt:                  timestamp(now), ExpiresAt: timestamp(request.ExpiresAt),
	})
	if err != nil {
		return InvitationSecret{}, fmt.Errorf("controlstate: create team invitation: insert invitation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return InvitationSecret{}, fmt.Errorf("controlstate: create team invitation: commit: %w", err)
	}
	return InvitationSecret{Invitation: invitationFromRow(
		row.ID, row.TeamID, request.MemberSlug, row.InitialRole, row.NormalizedEmailRestriction,
		row.State, row.CreatedAt, row.ExpiresAt,
	), Secret: token.String()}, nil
}

func (d *Database) RevokeTeamInvitation(
	ctx context.Context,
	identityID, teamID, invitationID string,
	now time.Time,
) (retErr error) {
	if !validStateText(identityID) || !validStateText(teamID) || !validStateText(invitationID) || now.IsZero() {
		return ErrAuthorityInvalid
	}
	if err := d.requireOpen(); err != nil {
		return err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("controlstate: revoke team invitation: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "revoke team invitation", &retErr)()
	queries := controlstatedb.New(tx)
	actor, err := lockTeamActor(ctx, queries, identityID, teamID)
	if err != nil {
		return err
	}
	actorRole := TeamRole(actor.ActorRole)
	if TeamKind(actor.Kind) != TeamKindOrganization || actorRole != TeamRoleAdmin && actorRole != TeamRoleOwner {
		return ErrAuthorityAccess
	}
	invitation, err := queries.LockTeamInvitation(ctx, controlstatedb.LockTeamInvitationParams{
		InvitationID: invitationID, TeamID: teamID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrInvitationNotFound
	}
	if err != nil {
		return fmt.Errorf("controlstate: revoke team invitation: lock invitation: %w", err)
	}
	if TeamRole(invitation.InitialRole) != TeamRoleMember && actorRole != TeamRoleOwner {
		return ErrAuthorityAccess
	}
	state := InvitationState(invitation.State)
	if state == InvitationRevoked {
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("controlstate: revoke team invitation: commit replay: %w", err)
		}
		return nil
	}
	if state == InvitationPending && !invitation.ExpiresAt.Time.After(now) {
		if _, err := queries.MarkInvitationExpired(ctx, invitation.ID); err != nil {
			return fmt.Errorf("controlstate: revoke team invitation: expire invitation: %w", err)
		}
		if _, err := queries.ReleaseInvitedMemberSlug(ctx, controlstatedb.ReleaseInvitedMemberSlugParams{
			ReleasedAt: timestamp(now), SlugReservationID: invitation.SlugReservationID,
		}); err != nil {
			return fmt.Errorf("controlstate: revoke team invitation: release expired slug: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("controlstate: revoke team invitation: commit expiration: %w", err)
		}
		return ErrAuthorityConflict
	}
	if state != InvitationPending {
		return ErrAuthorityConflict
	}
	updated, err := queries.RevokeTeamInvitation(ctx, controlstatedb.RevokeTeamInvitationParams{
		RevokedAt: timestamp(now), IdentityID: text(identityID), InvitationID: invitationID,
	})
	if err != nil {
		return fmt.Errorf("controlstate: revoke team invitation: update invitation: %w", err)
	}
	if updated != 1 {
		return ErrAuthorityConflict
	}
	updated, err = queries.ReleaseInvitedMemberSlug(ctx, controlstatedb.ReleaseInvitedMemberSlugParams{
		ReleasedAt: timestamp(now), SlugReservationID: invitation.SlugReservationID,
	})
	if err != nil {
		return fmt.Errorf("controlstate: revoke team invitation: release member slug: %w", err)
	}
	if updated != 1 {
		return ErrAuthorityConflict
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("controlstate: revoke team invitation: commit: %w", err)
	}
	return nil
}

func (d *Database) AcceptInvitation(
	ctx context.Context,
	identityID string,
	token credentials.InvitationToken,
	now time.Time,
) (result Membership, retErr error) {
	if !validStateText(identityID) || now.IsZero() {
		return Membership{}, ErrAuthorityInvalid
	}
	tokenDigest, err := credentials.ParseInvitationToken(token)
	if err != nil {
		return Membership{}, ErrInvitationNotFound
	}
	if err := d.requireOpen(); err != nil {
		return Membership{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return Membership{}, fmt.Errorf("controlstate: accept invitation: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "accept invitation", &retErr)()
	queries := controlstatedb.New(tx)
	teamID, err := queries.FindInvitationTeamByTokenDigest(ctx, tokenDigest[:])
	if errors.Is(err, pgx.ErrNoRows) {
		return Membership{}, ErrInvitationNotFound
	}
	if err != nil {
		return Membership{}, fmt.Errorf("controlstate: accept invitation: find invitation team: %w", err)
	}
	if _, err := queries.LockTeamForInvitationAcceptance(ctx, teamID); errors.Is(err, pgx.ErrNoRows) {
		return Membership{}, ErrInvitationNotFound
	} else if err != nil {
		return Membership{}, fmt.Errorf("controlstate: accept invitation: lock team: %w", err)
	}
	invitation, err := queries.LockInvitationByTokenDigest(ctx, controlstatedb.LockInvitationByTokenDigestParams{
		IdentityID: identityID, TokenDigest: tokenDigest[:],
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Membership{}, ErrInvitationNotFound
	}
	if err != nil {
		return Membership{}, fmt.Errorf("controlstate: accept invitation: lock invitation: %w", err)
	}
	if TeamKind(invitation.TeamKind) != TeamKindOrganization || InvitationState(invitation.State) != InvitationPending {
		return Membership{}, ErrAuthorityConflict
	}
	if !invitation.ExpiresAt.Time.After(now) {
		if _, err := queries.MarkInvitationExpired(ctx, invitation.ID); err != nil {
			return Membership{}, fmt.Errorf("controlstate: accept invitation: expire invitation: %w", err)
		}
		if _, err := queries.ReleaseInvitedMemberSlug(ctx, controlstatedb.ReleaseInvitedMemberSlugParams{
			ReleasedAt: timestamp(now), SlugReservationID: invitation.SlugReservationID,
		}); err != nil {
			return Membership{}, fmt.Errorf("controlstate: accept invitation: release expired slug: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return Membership{}, fmt.Errorf("controlstate: accept invitation: commit expiration: %w", err)
		}
		return Membership{}, ErrAuthorityConflict
	}
	if invitation.NormalizedEmailRestriction.Valid &&
		(!invitation.AcceptingEmailVerified || invitation.AcceptingNormalizedEmail.String != invitation.NormalizedEmailRestriction.String) {
		return Membership{}, ErrAuthorityAccess
	}
	exists, err := queries.TeamMembershipIdentityExists(ctx, controlstatedb.TeamMembershipIdentityExistsParams{
		TeamID: invitation.TeamID, IdentityID: identityID,
	})
	if err != nil {
		return Membership{}, fmt.Errorf("controlstate: accept invitation: check current membership: %w", err)
	}
	if exists {
		return Membership{}, ErrAuthorityConflict
	}
	managedLabel, err := availableManagedLabel(ctx, queries, now)
	if err != nil {
		return Membership{}, err
	}
	membershipID, err := opaqueid.New(opaqueid.MembershipPrefix)
	if err != nil {
		return Membership{}, err
	}
	revision, err := queries.AdvanceTeamPolicyRevision(ctx, controlstatedb.AdvanceTeamPolicyRevisionParams{
		UpdatedAt: timestamp(now), TeamID: invitation.TeamID,
	})
	if err != nil {
		return Membership{}, fmt.Errorf("controlstate: accept invitation: advance policy revision: %w", err)
	}
	if updated, err := queries.ActivateMemberSlug(ctx, controlstatedb.ActivateMemberSlugParams{
		IdentityID: text(identityID), ActivatedAt: timestamp(now), SlugReservationID: invitation.SlugReservationID,
	}); err != nil || updated != 1 {
		return Membership{}, authorityRowsError("accept invitation: activate member slug", updated, err)
	}
	if err := queries.CreateTeamMembership(ctx, controlstatedb.CreateTeamMembershipParams{
		ID: membershipID, TeamID: invitation.TeamID, IdentityID: identityID,
		SlugReservationID: invitation.SlugReservationID, ManagedLabel: managedLabel,
		Role: invitation.InitialRole, AuthorityRevision: revision, CreatedAt: timestamp(now),
	}); err != nil {
		return Membership{}, fmt.Errorf("controlstate: accept invitation: create membership: %w", err)
	}
	if updated, err := queries.AcceptTeamInvitation(ctx, controlstatedb.AcceptTeamInvitationParams{
		AcceptedAt: timestamp(now), IdentityID: text(identityID), MembershipID: text(membershipID), InvitationID: invitation.ID,
	}); err != nil || updated != 1 {
		return Membership{}, authorityRowsError("accept invitation: update invitation", updated, err)
	}
	row, err := queries.GetTeamMembershipContext(ctx, controlstatedb.GetTeamMembershipContextParams{
		MembershipID: membershipID, TeamID: invitation.TeamID,
	})
	if err != nil {
		return Membership{}, fmt.Errorf("controlstate: accept invitation: read membership: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Membership{}, fmt.Errorf("controlstate: accept invitation: commit: %w", err)
	}
	return membershipFromRow(
		row.ID, row.TeamID, row.IdentityID, row.TeamDisplayName, row.TeamKind, row.Role,
		row.MemberSlug, row.ManagedLabel, row.PolicyRevision, row.CreatedAt, row.UpdatedAt,
	), nil
}

func expireTeamInvitations(ctx context.Context, queries *controlstatedb.Queries, teamID string, now time.Time) error {
	reservationIDs, err := queries.ExpireTeamInvitations(ctx, controlstatedb.ExpireTeamInvitationsParams{
		TeamID: teamID, Now: timestamp(now),
	})
	if err != nil {
		return fmt.Errorf("controlstate: expire team invitations: %w", err)
	}
	for _, reservationID := range reservationIDs {
		updated, err := queries.ReleaseInvitedMemberSlug(ctx, controlstatedb.ReleaseInvitedMemberSlugParams{
			ReleasedAt: timestamp(now), SlugReservationID: reservationID,
		})
		if err != nil || updated != 1 {
			return authorityRowsError("expire team invitations: release member slug", updated, err)
		}
	}
	return nil
}

func invitationFromRow(
	id, teamID, memberSlug, initialRole string,
	normalizedEmail pgtype.Text,
	state string,
	createdAt, expiresAt pgtype.Timestamptz,
) Invitation {
	return Invitation{
		ID: id, TeamID: teamID, MemberSlug: memberSlug, InitialRole: TeamRole(initialRole),
		NormalizedEmailRestriction: normalizedEmail.String, State: InvitationState(state),
		CreatedAt: createdAt.Time, ExpiresAt: expiresAt.Time,
	}
}

func normalizeEmailRestriction(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	normalized := strings.ToLower(strings.TrimSpace(value))
	parsed, err := mail.ParseAddress(normalized)
	if err != nil || parsed.Address != normalized || len(normalized) > 320 {
		return "", ErrAuthorityInvalid
	}
	return normalized, nil
}

func invitationRetryContext(request CreateInvitationRequest) string {
	return request.IdentityID + "\x00" + request.TeamID + "\x00" + request.IdempotencyKey + "\x00" +
		base64.RawURLEncoding.EncodeToString(request.RequestDigest[:])
}

func authorityRowsError(operation string, rows int64, err error) error {
	if err != nil {
		return fmt.Errorf("controlstate: %s: %w", operation, err)
	}
	return fmt.Errorf("controlstate: %s: changed %d rows", operation, rows)
}
