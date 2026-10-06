package controlstate

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

var (
	ErrShareNotFound    = errors.New("controlstate: share not found")
	ErrShareInvalid     = errors.New("controlstate: share is invalid")
	ErrShareIdempotency = errors.New("controlstate: share idempotency conflict")
	ErrShareStale       = errors.New("controlstate: share public URL state changed")
	ErrShareLimit       = errors.New("controlstate: public URL has too many active shares or share cookies")
)

const maximumShareLifetime = 30 * 24 * time.Hour

type Share struct {
	SchemaVersion       int
	ID                  string
	PreviewID           string
	TeamID              string
	PublicURLIDs        []string
	CreatedByIdentityID string
	CreatedAt           time.Time
	ExpiresAt           time.Time
	RevokedAt           *time.Time
}

type SharePage struct {
	Shares     []Share
	NextCursor string
}

type AuthorizedSharePublicURL struct {
	PublicURLID              string
	ExpectedMutationRevision uint64
}

type CreateShareRequest struct {
	PreviewID         string
	TeamID            string
	ActingIdentityID  string
	IdempotencyKey    string
	SecretFingerprint [32]byte
	ExpiresAt         time.Time
	PolicyRevision    uint64
	PublicURLs        []AuthorizedSharePublicURL
}

func (d *Database) CreateShare(ctx context.Context, request CreateShareRequest, now time.Time) (result Share, retErr error) {
	now = now.UTC().Truncate(time.Microsecond)
	request.ExpiresAt = request.ExpiresAt.UTC().Truncate(time.Microsecond)
	if !opaqueid.Valid(request.PreviewID, opaqueid.PreviewPrefix) || request.TeamID == "" || request.ActingIdentityID == "" ||
		request.IdempotencyKey == "" || len(request.IdempotencyKey) > 128 || request.PolicyRevision == 0 ||
		!request.ExpiresAt.After(now) || request.ExpiresAt.After(now.Add(maximumShareLifetime)) ||
		len(request.PublicURLs) < 1 || len(request.PublicURLs) > 32 {
		return Share{}, ErrShareInvalid
	}
	urls := slices.Clone(request.PublicURLs)
	slices.SortFunc(urls, func(left, right AuthorizedSharePublicURL) int {
		return strings.Compare(left.PublicURLID, right.PublicURLID)
	})
	ids := make([]string, len(urls))
	for index, route := range urls {
		if route.PublicURLID == "" || route.ExpectedMutationRevision == 0 || route.ExpectedMutationRevision > 1<<63-1 ||
			index > 0 && route.PublicURLID == urls[index-1].PublicURLID {
			return Share{}, ErrShareInvalid
		}
		ids[index] = route.PublicURLID
	}
	digestInput, err := json.Marshal(struct {
		PreviewID    string   `json:"preview_id"`
		TeamID       string   `json:"team_id"`
		PublicURLIDs []string `json:"public_url_ids"`
		Fingerprint  string   `json:"secret_fingerprint"`
		ExpiresAt    string   `json:"expires_at"`
	}{request.PreviewID, request.TeamID, ids, hex.EncodeToString(request.SecretFingerprint[:]), request.ExpiresAt.UTC().Format(time.RFC3339Nano)})
	if err != nil {
		return Share{}, fmt.Errorf("controlstate: encode share request: %w", err)
	}
	digest := sha256.Sum256(digestInput)
	if err := d.requireOpen(); err != nil {
		return Share{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return Share{}, fmt.Errorf("controlstate: create share: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "create share", &retErr)()
	queries := controlstatedb.New(tx)
	preview, err := queries.GetPreview(ctx, request.PreviewID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Share{}, ErrPreviewNotFound
	}
	if err != nil {
		return Share{}, fmt.Errorf("controlstate: create share: read preview: %w", err)
	}
	if preview.TeamID != request.TeamID || preview.CreatedByIdentityID != request.ActingIdentityID {
		return Share{}, ErrPreviewAccess
	}
	previewURLs, err := queries.ListPreviewPublicURLs(ctx, preview.ID)
	if err != nil {
		return Share{}, fmt.Errorf("controlstate: create share: read preview public URLs: %w", err)
	}
	for _, id := range ids {
		if _, found := slices.BinarySearch(previewURLs, id); !found {
			return Share{}, ErrShareStale
		}
	}
	policyRevision := positive(request.PolicyRevision)
	{
		if _, err := queries.LockLocalTeamForMutation(ctx, request.TeamID); errors.Is(err, pgx.ErrNoRows) {
			return Share{}, ErrPreviewAccess
		} else if err != nil {
			return Share{}, fmt.Errorf("controlstate: create share: lock team: %w", err)
		}
	}
	var membership controlstatedb.GetActivePublishRunMembershipRow
	{
		membership, err = queries.GetActivePublishRunMembership(ctx, controlstatedb.GetActivePublishRunMembershipParams{
			TeamID: request.TeamID, IdentityID: request.ActingIdentityID,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return Share{}, ErrPreviewAccess
		}
		if err != nil {
			return Share{}, fmt.Errorf("controlstate: create share: read membership: %w", err)
		}
		if membership.PolicyRevision != policyRevision {
			return Share{}, ErrShareStale
		}
	}
	for _, authorized := range urls {
		route, err := queries.LockPublicURLForRun(ctx, authorized.PublicURLID)
		if errors.Is(err, pgx.ErrNoRows) {
			return Share{}, ErrShareStale
		}
		if err != nil {
			return Share{}, fmt.Errorf("controlstate: create share: lock public URL: %w", err)
		}
		if route.TeamID != request.TeamID || route.LifecycleState != string(PublicURLLifecycleEnabled) ||
			route.MutationRevision != int64(authorized.ExpectedMutationRevision) || route.PolicyRevision > policyRevision {
			return Share{}, ErrShareStale
		}
		if route.PublicURLScope == string(PublicURLScopeMember) &&
			(!route.MembershipID.Valid || route.MembershipID.String != membership.ID) ||
			route.PublicURLScope == string(PublicURLScopeShared) && membership.Role != "admin" && membership.Role != "owner" {
			return Share{}, ErrPreviewAccess
		}
		count, err := queries.CountActiveSharesForPublicURL(ctx, controlstatedb.CountActiveSharesForPublicURLParams{
			PublicURLID: route.ID, Now: timestamptz(now),
		})
		if err != nil {
			return Share{}, fmt.Errorf("controlstate: count active shares: %w", err)
		}
		if count >= 256 {
			return Share{}, ErrShareLimit
		}
	}
	id, err := opaqueid.New(opaqueid.SharePrefix)
	if err != nil {
		return Share{}, fmt.Errorf("controlstate: create share ID: %w", err)
	}
	stored, err := queries.CreateShare(ctx, controlstatedb.CreateShareParams{
		ID: id, PreviewID: preview.ID, TeamID: request.TeamID,
		CreatedByIdentityID: request.ActingIdentityID, IdempotencyKey: request.IdempotencyKey,
		RequestDigest: digest[:], SecretFingerprint: request.SecretFingerprint[:],
		CreatedAt: timestamptz(now), ExpiresAt: timestamptz(request.ExpiresAt),
	})
	if err != nil {
		return Share{}, fmt.Errorf("controlstate: create share: save share: %w", err)
	}
	if stored.PreviewID != preview.ID || stored.RevokedAt.Valid || subtle.ConstantTimeCompare(stored.RequestDigest, digest[:]) != 1 {
		return Share{}, ErrShareIdempotency
	}
	for _, publicURLID := range ids {
		if _, err := queries.AddSharePublicURL(ctx, controlstatedb.AddSharePublicURLParams{
			PublicURLID: publicURLID, ShareID: stored.ID, IdentityID: request.ActingIdentityID,
		}); errors.Is(err, pgx.ErrNoRows) {
			return Share{}, ErrShareStale
		} else if err != nil {
			return Share{}, fmt.Errorf("controlstate: create share: save public URL snapshot: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return Share{}, fmt.Errorf("controlstate: create share: commit: %w", err)
	}
	return shareFromModel(stored, ids), nil
}

func (d *Database) GetShare(ctx context.Context, id string) (Share, error) {
	if !opaqueid.Valid(id, opaqueid.SharePrefix) {
		return Share{}, ErrShareNotFound
	}
	if err := d.requireOpen(); err != nil {
		return Share{}, err
	}
	queries := controlstatedb.New(d.pool)
	row, err := queries.GetShare(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return Share{}, ErrShareNotFound
	}
	if err != nil {
		return Share{}, fmt.Errorf("controlstate: read share: %w", err)
	}
	return shareWithURLs(ctx, queries, row)
}

func (d *Database) ListShares(ctx context.Context, previewID, cursor string) (SharePage, error) {
	if !opaqueid.Valid(previewID, opaqueid.PreviewPrefix) || cursor != "" && !opaqueid.Valid(cursor, opaqueid.SharePrefix) {
		return SharePage{}, ErrShareInvalid
	}
	if err := d.requireOpen(); err != nil {
		return SharePage{}, err
	}
	queries := controlstatedb.New(d.pool)
	rows, err := queries.ListShares(ctx, controlstatedb.ListSharesParams{PreviewID: previewID, AfterID: cursor})
	if err != nil {
		return SharePage{}, fmt.Errorf("controlstate: list shares: %w", err)
	}
	return sharePageFromRows(ctx, queries, rows)
}

func (d *Database) ListTeamShares(ctx context.Context, teamID, identityID, cursor string) (SharePage, error) {
	if teamID == "" || identityID == "" || cursor != "" && !opaqueid.Valid(cursor, opaqueid.SharePrefix) {
		return SharePage{}, ErrShareInvalid
	}
	if err := d.requireOpen(); err != nil {
		return SharePage{}, err
	}
	queries := controlstatedb.New(d.pool)
	rows, err := queries.ListTeamShares(ctx, controlstatedb.ListTeamSharesParams{
		TeamID: teamID, IdentityID: identityID, AfterID: cursor,
	})
	if err != nil {
		return SharePage{}, fmt.Errorf("controlstate: list team shares: %w", err)
	}
	return sharePageFromRows(ctx, queries, rows)
}

func sharePageFromRows(ctx context.Context, queries *controlstatedb.Queries, rows []controlstatedb.ControlShare) (SharePage, error) {
	page := SharePage{Shares: make([]Share, 0, min(len(rows), 100))}
	for index, row := range rows {
		if index == 100 {
			page.NextCursor = rows[index-1].ID
			break
		}
		share, err := shareWithURLs(ctx, queries, row)
		if err != nil {
			return SharePage{}, err
		}
		page.Shares = append(page.Shares, share)
	}
	return page, nil
}

func (d *Database) RevokeShare(ctx context.Context, id, identityID string, now time.Time) (Share, error) {
	if !opaqueid.Valid(id, opaqueid.SharePrefix) || identityID == "" {
		return Share{}, ErrShareInvalid
	}
	if err := d.requireOpen(); err != nil {
		return Share{}, err
	}
	queries := controlstatedb.New(d.pool)
	row, err := queries.RevokeShare(ctx, controlstatedb.RevokeShareParams{
		ShareID: id, IdentityID: identityID,
		RevokedAt: timestamptz(now), RevokedByIdentityID: identityID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Share{}, ErrShareNotFound
	}
	if err != nil {
		return Share{}, fmt.Errorf("controlstate: revoke share: %w", err)
	}
	return shareWithURLs(ctx, queries, row)
}

func shareWithURLs(ctx context.Context, queries *controlstatedb.Queries, row controlstatedb.ControlShare) (Share, error) {
	ids, err := queries.ListSharePublicURLs(ctx, row.ID)
	if err != nil {
		return Share{}, fmt.Errorf("controlstate: read share public URLs: %w", err)
	}
	return shareFromModel(row, ids), nil
}

func shareFromModel(row controlstatedb.ControlShare, ids []string) Share {
	if ids == nil {
		ids = []string{}
	}
	return Share{
		SchemaVersion: int(row.SchemaVersion),
		ID:            row.ID, PreviewID: row.PreviewID, TeamID: row.TeamID,
		CreatedByIdentityID: row.CreatedByIdentityID, PublicURLIDs: ids,
		CreatedAt: row.CreatedAt.Time, ExpiresAt: row.ExpiresAt.Time, RevokedAt: optionalTime(row.RevokedAt),
	}
}
