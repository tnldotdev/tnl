package controlstate

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

type VisitorShareGrant struct {
	ID, TeamID, PublicURLID, CreatedByIdentityID string
	Kind                                         string
	CreatedAt                                    time.Time
	ExpiresAt, RevokedAt                         *time.Time
}

type VisitorShareGrantPage struct {
	Shares     []VisitorShareGrant
	NextCursor string
}

type CreateTeamURLShareGrantRequest struct {
	TeamID, PublicURLID, ActingIdentityID, IdempotencyKey string
	PolicyRevision, ExpectedMutationRevision              uint64
	ExpiresAt                                             *time.Time
}

func teamURLShareDigest(request CreateTeamURLShareGrantRequest) [32]byte {
	expires := ""
	if request.ExpiresAt != nil {
		expires = request.ExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	return sha256.Sum256([]byte(request.TeamID + "\x00" + request.PublicURLID + "\x00" + expires))
}

func (d *Database) CreateTeamURLShareGrant(ctx context.Context, request CreateTeamURLShareGrantRequest, now time.Time) (result VisitorShareGrant, retErr error) {
	if !validStateText(request.PublicURLID) || !validStateText(request.TeamID) ||
		!validStateText(request.ActingIdentityID) || !validStateText(request.IdempotencyKey) || len(request.IdempotencyKey) > 128 ||
		request.PolicyRevision == 0 || request.ExpectedMutationRevision == 0 || request.ExpectedMutationRevision > 1<<63-1 ||
		request.ExpiresAt != nil && (!request.ExpiresAt.After(now) || request.ExpiresAt.After(now.Add(30*24*time.Hour))) {
		return VisitorShareGrant{}, ErrShareInvalid
	}
	if err := d.requireOpen(); err != nil {
		return VisitorShareGrant{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return VisitorShareGrant{}, fmt.Errorf("begin team share grant: %w", err)
	}
	defer rollback(ctx, tx, "create team share grant", &retErr)()
	queries := controlstatedb.New(tx)
	if _, err := queries.LockLocalTeamForMutation(ctx, request.TeamID); errors.Is(err, pgx.ErrNoRows) {
		return VisitorShareGrant{}, ErrPreviewAccess
	} else if err != nil {
		return VisitorShareGrant{}, fmt.Errorf("lock team for share: %w", err)
	}
	membership, err := queries.GetActivePublishRunMembership(ctx, controlstatedb.GetActivePublishRunMembershipParams{
		TeamID: request.TeamID, IdentityID: request.ActingIdentityID,
	})
	if errors.Is(err, pgx.ErrNoRows) || err == nil && membership.PolicyRevision != positive(request.PolicyRevision) {
		return VisitorShareGrant{}, ErrShareStale
	}
	if err != nil {
		return VisitorShareGrant{}, fmt.Errorf("read share membership: %w", err)
	}
	url, err := queries.LockPublicURLForRun(ctx, request.PublicURLID)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !validTeamURLShare(url, request.TeamID, membership.ID, membership.Role, request.PolicyRevision, request.ExpectedMutationRevision) {
		return VisitorShareGrant{}, ErrShareStale
	}
	if err != nil {
		return VisitorShareGrant{}, fmt.Errorf("lock shared public URL: %w", err)
	}
	id, err := opaqueid.New(opaqueid.SharePrefix)
	if err != nil {
		return VisitorShareGrant{}, fmt.Errorf("create share ID: %w", err)
	}
	digest := teamURLShareDigest(request)
	stored, err := queries.CreateTeamURLVisitorGrant(ctx, controlstatedb.CreateTeamURLVisitorGrantParams{
		ID: id, TeamID: request.TeamID, PublicURLID: nullableText(request.PublicURLID),
		CreatedByIdentityID: request.ActingIdentityID, IdempotencyKey: request.IdempotencyKey,
		RequestDigest: digest[:], CreatedAt: timestamptz(now), ExpiresAt: nullableTime(request.ExpiresAt),
	})
	if err != nil {
		return VisitorShareGrant{}, fmt.Errorf("save team share grant: %w", err)
	}
	if stored.Kind != "team_url" || stored.TeamID != request.TeamID || stored.PublicURLID.String != request.PublicURLID ||
		stored.RevokedAt.Valid || stored.ExpiresAt.Valid && !stored.ExpiresAt.Time.After(now) ||
		subtle.ConstantTimeCompare(stored.RequestDigest, digest[:]) != 1 {
		return VisitorShareGrant{}, ErrShareIdempotency
	}
	if err := tx.Commit(ctx); err != nil {
		return VisitorShareGrant{}, fmt.Errorf("commit team share grant: %w", err)
	}
	return visitorShareGrantFromRow(stored), nil
}

func validTeamURLShare(url controlstatedb.ControlPublicUrl, teamID, membershipID, role string, revision, mutation uint64) bool {
	if url.TeamID != teamID || url.LifecycleState != string(PublicURLLifecycleEnabled) || url.Purpose != string(PublicURLPurposeApp) ||
		url.ServiceProtocol != string(PublicURLServiceHTTP) && url.ServiceProtocol != string(PublicURLServicePostgres) &&
			url.ServiceProtocol != string(PublicURLServiceMySQL) && url.ServiceProtocol != string(PublicURLServiceRedis) ||
		url.PolicyRevision > positive(revision) || url.MutationRevision != int64(mutation) {
		return false
	}
	return url.PublicURLScope == string(PublicURLScopeMember) && url.MembershipID.Valid && url.MembershipID.String == membershipID ||
		url.PublicURLScope == string(PublicURLScopeShared) && (role == string(TeamRoleAdmin) || role == string(TeamRoleOwner))
}

func (d *Database) ListTeamURLShareGrants(ctx context.Context, teamID, identityID, cursor string) (VisitorShareGrantPage, error) {
	if !validStateText(teamID) || !validStateText(identityID) || cursor != "" && !opaqueid.Valid(cursor, opaqueid.SharePrefix) {
		return VisitorShareGrantPage{}, ErrShareInvalid
	}
	if err := d.requireOpen(); err != nil {
		return VisitorShareGrantPage{}, err
	}
	rows, err := controlstatedb.New(d.pool).ListTeamURLVisitorGrants(ctx, controlstatedb.ListTeamURLVisitorGrantsParams{
		TeamID: teamID, IdentityID: identityID, Cursor: nullableText(cursor),
	})
	if err != nil {
		return VisitorShareGrantPage{}, fmt.Errorf("list team share grants: %w", err)
	}
	page := VisitorShareGrantPage{Shares: make([]VisitorShareGrant, min(len(rows), publicURLPageSize))}
	for index, row := range rows[:len(page.Shares)] {
		page.Shares[index] = visitorShareGrantFromRow(row)
	}
	if len(rows) > publicURLPageSize {
		page.NextCursor = rows[publicURLPageSize-1].ID
	}
	return page, nil
}

func (d *Database) GetTeamURLShareGrant(ctx context.Context, id string) (VisitorShareGrant, error) {
	if !opaqueid.Valid(id, opaqueid.SharePrefix) {
		return VisitorShareGrant{}, ErrShareNotFound
	}
	if err := d.requireOpen(); err != nil {
		return VisitorShareGrant{}, err
	}
	row, err := controlstatedb.New(d.pool).GetTeamURLVisitorGrant(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return VisitorShareGrant{}, ErrShareNotFound
	}
	if err != nil {
		return VisitorShareGrant{}, fmt.Errorf("read team share grant: %w", err)
	}
	return visitorShareGrantFromRow(row), nil
}

func (d *Database) RevokeTeamURLShareGrant(ctx context.Context, id, teamID, identityID string, now time.Time) (result VisitorShareGrant, retErr error) {
	if !opaqueid.Valid(id, opaqueid.SharePrefix) || !validStateText(teamID) || !validStateText(identityID) {
		return VisitorShareGrant{}, ErrShareInvalid
	}
	if err := d.requireOpen(); err != nil {
		return VisitorShareGrant{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return VisitorShareGrant{}, fmt.Errorf("begin share revocation: %w", err)
	}
	defer rollback(ctx, tx, "revoke team share grant", &retErr)()
	queries := controlstatedb.New(tx)
	if _, err := queries.LockLocalTeamForMutation(ctx, teamID); errors.Is(err, pgx.ErrNoRows) {
		return VisitorShareGrant{}, ErrPreviewAccess
	} else if err != nil {
		return VisitorShareGrant{}, fmt.Errorf("lock team for share revocation: %w", err)
	}
	member, err := queries.GetActivePublishRunMembership(ctx, controlstatedb.GetActivePublishRunMembershipParams{
		TeamID: teamID, IdentityID: identityID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return VisitorShareGrant{}, ErrShareNotFound
	}
	if err != nil {
		return VisitorShareGrant{}, fmt.Errorf("read share revoker: %w", err)
	}
	unlocked, err := queries.GetTeamURLVisitorGrant(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (unlocked.TeamID != teamID || !unlocked.PublicURLID.Valid) {
		return VisitorShareGrant{}, ErrShareNotFound
	}
	if err != nil {
		return VisitorShareGrant{}, fmt.Errorf("read team share grant: %w", err)
	}
	url, err := queries.LockPublicURLForRun(ctx, unlocked.PublicURLID.String)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (url.TeamID != teamID ||
		!(url.PublicURLScope == string(PublicURLScopeMember) && url.MembershipID.Valid && url.MembershipID.String == member.ID ||
			url.PublicURLScope == string(PublicURLScopeShared) && (member.Role == string(TeamRoleAdmin) || member.Role == string(TeamRoleOwner)))) {
		return VisitorShareGrant{}, ErrShareNotFound
	}
	if err != nil {
		return VisitorShareGrant{}, fmt.Errorf("lock share public URL: %w", err)
	}
	stored, err := queries.LockTeamURLVisitorGrant(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (stored.TeamID != teamID || stored.PublicURLID.String != url.ID) {
		return VisitorShareGrant{}, ErrShareNotFound
	}
	if err != nil {
		return VisitorShareGrant{}, fmt.Errorf("lock team share grant: %w", err)
	}
	if !stored.RevokedAt.Valid {
		if err := queries.RevokeTeamURLVisitorGrant(ctx, controlstatedb.RevokeTeamURLVisitorGrantParams{
			ID: id, IdentityID: nullableText(identityID), Now: timestamptz(now),
		}); err != nil {
			return VisitorShareGrant{}, fmt.Errorf("save share revocation: %w", err)
		}
		stored.RevokedAt = timestamptz(now)
	}
	if err := tx.Commit(ctx); err != nil {
		return VisitorShareGrant{}, fmt.Errorf("commit share revocation: %w", err)
	}
	return visitorShareGrantFromRow(stored), nil
}

func visitorShareGrantFromRow(row controlstatedb.ControlVisitorAccessGrant) VisitorShareGrant {
	return VisitorShareGrant{
		ID: row.ID, TeamID: row.TeamID, Kind: row.Kind, PublicURLID: row.PublicURLID.String,
		CreatedByIdentityID: row.CreatedByIdentityID, CreatedAt: row.CreatedAt.Time,
		ExpiresAt: optionalTime(row.ExpiresAt), RevokedAt: optionalTime(row.RevokedAt),
	}
}
