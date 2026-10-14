package controlstate

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

type VisitorShareInvitation struct {
	ID, TeamID, PublicURLID, Email, CreatedByIdentityID, AcceptedIdentityID string
	CreatedAt, ExpiresAt                                                    time.Time
	AcceptedAt, RevokedAt                                                   *time.Time
}

type VisitorShareInvitationPage struct {
	Invitations []VisitorShareInvitation
	NextCursor  string
}

type CreateVisitorShareInvitationRequest struct {
	TeamID, PublicURLID, ActingIdentityID, IdempotencyKey, Email string
	TokenDigest                                                  [32]byte
	PolicyRevision, ExpectedMutationRevision                     uint64
	ExpiresAt                                                    time.Time
}

func visitorInvitationDigest(request CreateVisitorShareInvitationRequest, normalizedEmail string) [32]byte {
	return sha256.Sum256([]byte(request.TeamID + "\x00" + request.PublicURLID + "\x00" + normalizedEmail + "\x00" +
		base64.RawURLEncoding.EncodeToString(request.TokenDigest[:]) + "\x00" + request.ExpiresAt.UTC().Format(time.RFC3339Nano)))
}

func (d *Database) CreateVisitorShareInvitation(ctx context.Context, request CreateVisitorShareInvitationRequest, now time.Time) (result VisitorShareInvitation, retErr error) {
	email, err := normalizeEmailRestriction(request.Email)
	if err != nil || email == "" || !validStateText(request.TeamID) || !validStateText(request.PublicURLID) ||
		!validStateText(request.ActingIdentityID) || !validIdempotencyKey(request.IdempotencyKey) ||
		request.PolicyRevision == 0 || request.ExpectedMutationRevision == 0 || request.ExpectedMutationRevision > 1<<63-1 ||
		!request.ExpiresAt.After(now) || request.ExpiresAt.After(now.Add(maximumShareLifetime)) {
		return VisitorShareInvitation{}, ErrShareInvalid
	}
	if err := d.requireOpen(); err != nil {
		return VisitorShareInvitation{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return VisitorShareInvitation{}, fmt.Errorf("begin named share invitation: %w", err)
	}
	defer rollback(ctx, tx, "create named share invitation", &retErr)()
	queries := controlstatedb.New(tx)
	if _, err := queries.LockLocalTeamForMutation(ctx, request.TeamID); errors.Is(err, pgx.ErrNoRows) {
		return VisitorShareInvitation{}, ErrPreviewAccess
	} else if err != nil {
		return VisitorShareInvitation{}, fmt.Errorf("lock invitation team: %w", err)
	}
	membership, err := queries.GetActivePublishRunMembership(ctx, controlstatedb.GetActivePublishRunMembershipParams{
		TeamID: request.TeamID, IdentityID: request.ActingIdentityID,
	})
	if errors.Is(err, pgx.ErrNoRows) || err == nil && membership.PolicyRevision != positive(request.PolicyRevision) {
		return VisitorShareInvitation{}, ErrShareStale
	}
	if err != nil {
		return VisitorShareInvitation{}, fmt.Errorf("read invitation issuer: %w", err)
	}
	url, err := queries.LockPublicURLForRun(ctx, request.PublicURLID)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !validTeamURLShare(url, request.TeamID, membership.ID, membership.Role, request.PolicyRevision, request.ExpectedMutationRevision) {
		return VisitorShareInvitation{}, ErrShareStale
	}
	if err != nil {
		return VisitorShareInvitation{}, fmt.Errorf("lock invited public URL: %w", err)
	}
	id, err := opaqueid.New(opaqueid.SharePrefix)
	if err != nil {
		return VisitorShareInvitation{}, fmt.Errorf("create invitation ID: %w", err)
	}
	digest := visitorInvitationDigest(request, email)
	stored, err := queries.CreateVisitorShareInvitation(ctx, controlstatedb.CreateVisitorShareInvitationParams{
		ID: id, TeamID: request.TeamID, PublicURLID: url.ID, NormalizedEmail: email,
		TokenDigest: request.TokenDigest[:], CreatedByIdentityID: request.ActingIdentityID,
		IdempotencyKey: request.IdempotencyKey, RequestDigest: digest[:], CreatedAt: timestamptz(now), ExpiresAt: timestamptz(request.ExpiresAt),
	})
	if err != nil {
		return VisitorShareInvitation{}, fmt.Errorf("save named share invitation: %w", err)
	}
	if stored.TeamID != request.TeamID || stored.PublicURLID != request.PublicURLID || stored.RevokedAt.Valid || stored.AcceptedAt.Valid ||
		!stored.ExpiresAt.Time.After(now) ||
		subtle.ConstantTimeCompare(stored.RequestDigest, digest[:]) != 1 || subtle.ConstantTimeCompare(stored.TokenDigest, request.TokenDigest[:]) != 1 {
		return VisitorShareInvitation{}, ErrShareIdempotency
	}
	if err := tx.Commit(ctx); err != nil {
		return VisitorShareInvitation{}, fmt.Errorf("commit named share invitation: %w", err)
	}
	return visitorInvitationFromRow(stored), nil
}

func parseVisitorInviteSecret(secret string) (string, [32]byte, error) {
	id, encoded, found := strings.Cut(secret, ".")
	if !found || !opaqueid.Valid(id, opaqueid.SharePrefix) {
		return "", [32]byte{}, ErrShareInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != encoded {
		return "", [32]byte{}, ErrShareInvalid
	}
	return id, sha256.Sum256(raw), nil
}

func (d *Database) AcceptVisitorShareInvitation(ctx context.Context, secret, identityID string, now time.Time) (result VisitorShareInvitation, retErr error) {
	id, digest, err := parseVisitorInviteSecret(secret)
	if err != nil || !validStateText(identityID) {
		return VisitorShareInvitation{}, ErrShareInvalid
	}
	if err := d.requireOpen(); err != nil {
		return VisitorShareInvitation{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return VisitorShareInvitation{}, fmt.Errorf("begin share acceptance: %w", err)
	}
	defer rollback(ctx, tx, "accept named share invitation", &retErr)()
	queries := controlstatedb.New(tx)
	preliminary, err := queries.GetVisitorShareInvitation(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return VisitorShareInvitation{}, ErrShareNotFound
	}
	if err != nil {
		return VisitorShareInvitation{}, fmt.Errorf("read invited URL: %w", err)
	}
	if _, err := queries.LockLocalTeamForMutation(ctx, preliminary.TeamID); errors.Is(err, pgx.ErrNoRows) {
		return VisitorShareInvitation{}, ErrShareNotFound
	} else if err != nil {
		return VisitorShareInvitation{}, fmt.Errorf("lock invitation team: %w", err)
	}
	url, err := queries.LockPublicURLForRun(ctx, preliminary.PublicURLID)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (url.TeamID != preliminary.TeamID || url.LifecycleState != string(PublicURLLifecycleEnabled) ||
		url.Purpose != string(PublicURLPurposeApp) ||
		url.ServiceProtocol != string(PublicURLServiceHTTP) && url.ServiceProtocol != string(PublicURLServicePostgres) &&
			url.ServiceProtocol != string(PublicURLServiceMySQL) && url.ServiceProtocol != string(PublicURLServiceRedis)) {
		return VisitorShareInvitation{}, ErrShareNotFound
	}
	if err != nil {
		return VisitorShareInvitation{}, fmt.Errorf("lock invited public URL: %w", err)
	}
	stored, err := queries.LockVisitorShareInvitation(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (stored.TeamID != url.TeamID || stored.PublicURLID != url.ID ||
		stored.RevokedAt.Valid || stored.AcceptedAt.Valid || !stored.ExpiresAt.Time.After(now) ||
		subtle.ConstantTimeCompare(stored.TokenDigest, digest[:]) != 1) {
		return VisitorShareInvitation{}, ErrShareNotFound
	}
	if err != nil {
		return VisitorShareInvitation{}, fmt.Errorf("lock named invitation: %w", err)
	}
	recipient, err := queries.LockVisitorInvitationRecipient(ctx, identityID)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (recipient.DisabledAt.Valid || !recipient.EmailVerified ||
		!recipient.NormalizedEmail.Valid || recipient.NormalizedEmail.String != stored.NormalizedEmail) {
		return VisitorShareInvitation{}, ErrShareNotFound
	}
	if err != nil {
		return VisitorShareInvitation{}, fmt.Errorf("verify invitation recipient: %w", err)
	}
	if _, err := queries.AcceptVisitorShareInvitation(ctx, controlstatedb.AcceptVisitorShareInvitationParams{
		ID: stored.ID, IdentityID: nullableText(identityID), Now: timestamptz(now),
	}); errors.Is(err, pgx.ErrNoRows) {
		return VisitorShareInvitation{}, ErrShareNotFound
	} else if err != nil {
		return VisitorShareInvitation{}, fmt.Errorf("accept named invitation: %w", err)
	}
	if err := queries.InsertAcceptedVisitorGrant(ctx, controlstatedb.InsertAcceptedVisitorGrantParams{
		ID: stored.ID, TeamID: stored.TeamID, PublicURLID: nullableText(stored.PublicURLID),
		IdentityID: nullableText(identityID), CreatedByIdentityID: stored.CreatedByIdentityID,
		IdempotencyKey: "invited/" + stored.ID, RequestDigest: stored.RequestDigest,
		CreatedAt: timestamptz(now), ExpiresAt: stored.ExpiresAt,
	}); err != nil {
		return VisitorShareInvitation{}, fmt.Errorf("save accepted visitor grant: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return VisitorShareInvitation{}, fmt.Errorf("commit invitation acceptance: %w", err)
	}
	stored.AcceptedIdentityID = nullableText(identityID)
	stored.AcceptedAt = timestamptz(now)
	return visitorInvitationFromRow(stored), nil
}

func (d *Database) ListVisitorShareInvitations(ctx context.Context, teamID, actorID, cursor string) (VisitorShareInvitationPage, error) {
	if !validStateText(teamID) || !validStateText(actorID) || cursor != "" && !opaqueid.Valid(cursor, opaqueid.SharePrefix) {
		return VisitorShareInvitationPage{}, ErrShareInvalid
	}
	if err := d.requireOpen(); err != nil {
		return VisitorShareInvitationPage{}, err
	}
	rows, err := controlstatedb.New(d.pool).ListVisitorShareInvitations(ctx, controlstatedb.ListVisitorShareInvitationsParams{
		TeamID: teamID, IdentityID: actorID, Cursor: nullableText(cursor),
	})
	if err != nil {
		return VisitorShareInvitationPage{}, fmt.Errorf("list named share invitations: %w", err)
	}
	page := VisitorShareInvitationPage{Invitations: make([]VisitorShareInvitation, min(len(rows), publicURLPageSize))}
	for index, row := range rows[:len(page.Invitations)] {
		page.Invitations[index] = visitorInvitationFromRow(row)
	}
	if len(rows) > publicURLPageSize {
		page.NextCursor = rows[publicURLPageSize-1].ID
	}
	return page, nil
}

func (d *Database) GetVisitorShareInvitation(ctx context.Context, id string) (VisitorShareInvitation, error) {
	if !opaqueid.Valid(id, opaqueid.SharePrefix) {
		return VisitorShareInvitation{}, ErrShareNotFound
	}
	if err := d.requireOpen(); err != nil {
		return VisitorShareInvitation{}, err
	}
	row, err := controlstatedb.New(d.pool).GetVisitorShareInvitation(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return VisitorShareInvitation{}, ErrShareNotFound
	}
	if err != nil {
		return VisitorShareInvitation{}, fmt.Errorf("read named share invitation: %w", err)
	}
	return visitorInvitationFromRow(row), nil
}

func (d *Database) RevokeVisitorShareInvitation(ctx context.Context, id, teamID, actorID string, now time.Time) (result VisitorShareInvitation, retErr error) {
	if !opaqueid.Valid(id, opaqueid.SharePrefix) || !validStateText(teamID) || !validStateText(actorID) {
		return VisitorShareInvitation{}, ErrShareInvalid
	}
	if err := d.requireOpen(); err != nil {
		return VisitorShareInvitation{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return VisitorShareInvitation{}, fmt.Errorf("begin invitation revocation: %w", err)
	}
	defer rollback(ctx, tx, "revoke named share invitation", &retErr)()
	queries := controlstatedb.New(tx)
	if _, err := queries.LockLocalTeamForMutation(ctx, teamID); errors.Is(err, pgx.ErrNoRows) {
		return VisitorShareInvitation{}, ErrShareNotFound
	} else if err != nil {
		return VisitorShareInvitation{}, fmt.Errorf("lock invitation team: %w", err)
	}
	member, err := queries.GetActivePublishRunMembership(ctx, controlstatedb.GetActivePublishRunMembershipParams{
		TeamID: teamID, IdentityID: actorID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return VisitorShareInvitation{}, ErrShareNotFound
	}
	if err != nil {
		return VisitorShareInvitation{}, fmt.Errorf("read invitation manager: %w", err)
	}
	unlocked, err := queries.GetVisitorShareInvitation(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && unlocked.TeamID != teamID {
		return VisitorShareInvitation{}, ErrShareNotFound
	}
	if err != nil {
		return VisitorShareInvitation{}, fmt.Errorf("read named invitation: %w", err)
	}
	url, err := queries.LockPublicURLForRun(ctx, unlocked.PublicURLID)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (url.TeamID != teamID ||
		!(url.PublicURLScope == string(PublicURLScopeMember) && url.MembershipID.Valid && url.MembershipID.String == member.ID ||
			url.PublicURLScope == string(PublicURLScopeShared) && (member.Role == string(TeamRoleAdmin) || member.Role == string(TeamRoleOwner)))) {
		return VisitorShareInvitation{}, ErrShareNotFound
	}
	if err != nil {
		return VisitorShareInvitation{}, fmt.Errorf("lock invitation public URL: %w", err)
	}
	stored, err := queries.LockVisitorShareInvitation(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (stored.TeamID != teamID || stored.PublicURLID != url.ID) {
		return VisitorShareInvitation{}, ErrShareNotFound
	}
	if err != nil {
		return VisitorShareInvitation{}, fmt.Errorf("lock named invitation: %w", err)
	}
	if !stored.RevokedAt.Valid {
		if err := queries.RevokeVisitorShareInvitation(ctx, controlstatedb.RevokeVisitorShareInvitationParams{
			ID: id, IdentityID: nullableText(actorID), Now: timestamptz(now),
		}); err != nil {
			return VisitorShareInvitation{}, fmt.Errorf("save invitation revocation: %w", err)
		}
		if stored.AcceptedAt.Valid {
			if err := queries.RevokeAcceptedVisitorGrant(ctx, controlstatedb.RevokeAcceptedVisitorGrantParams{
				ID: id, IdentityID: nullableText(actorID), Now: timestamptz(now),
			}); err != nil {
				return VisitorShareInvitation{}, fmt.Errorf("revoke accepted visitor grant: %w", err)
			}
		}
		stored.RevokedAt = timestamptz(now)
	}
	if err := tx.Commit(ctx); err != nil {
		return VisitorShareInvitation{}, fmt.Errorf("commit invitation revocation: %w", err)
	}
	return visitorInvitationFromRow(stored), nil
}

func visitorInvitationFromRow(row controlstatedb.ControlVisitorShareInvitation) VisitorShareInvitation {
	return VisitorShareInvitation{
		ID: row.ID, TeamID: row.TeamID, PublicURLID: row.PublicURLID,
		Email: row.NormalizedEmail, CreatedByIdentityID: row.CreatedByIdentityID,
		AcceptedIdentityID: row.AcceptedIdentityID.String,
		CreatedAt:          row.CreatedAt.Time, ExpiresAt: row.ExpiresAt.Time,
		AcceptedAt: optionalTime(row.AcceptedAt), RevokedAt: optionalTime(row.RevokedAt),
	}
}
