package state

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
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
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
	Scope               string
	Label               string
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
	Label             string
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
	if request.PreviewID != "" && !opaqueid.Valid(request.PreviewID, opaqueid.PreviewPrefix) || request.TeamID == "" || request.ActingIdentityID == "" ||
		len(request.Label) > 128 ||
		request.IdempotencyKey == "" || len(request.IdempotencyKey) > 128 || request.PolicyRevision == 0 ||
		!request.ExpiresAt.After(now) || request.ExpiresAt.After(now.Add(maximumShareLifetime)) ||
		len(request.PublicURLs) < 1 || len(request.PublicURLs) > 32 || request.PreviewID == "" && len(request.PublicURLs) != 1 {
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
		Label        string   `json:"label"`
		PublicURLIDs []string `json:"public_url_ids"`
		Fingerprint  string   `json:"secret_fingerprint"`
		ExpiresAt    string   `json:"expires_at"`
	}{request.PreviewID, request.TeamID, request.Label, ids, hex.EncodeToString(request.SecretFingerprint[:]), request.ExpiresAt.UTC().Format(time.RFC3339Nano)})
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
	if request.PreviewID != "" {
		preview, err := queries.GetPreview(ctx, request.PreviewID)
		if errors.Is(err, pgx.ErrNoRows) {
			return Share{}, ErrPreviewNotFound
		}
		if err != nil {
			return Share{}, fmt.Errorf("controlstate: create share: read preview: %w", err)
		}
		if preview.TeamID != request.TeamID || preview.CreatedByIdentityID != request.ActingIdentityID || preview.DemoPublishRunID.Valid {
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
			(route.Purpose != "app" && (request.PreviewID != "" || route.Purpose != "alias" && route.Purpose != "demo")) || route.ServiceProtocol != "http" ||
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
	scope := "url"
	if request.PreviewID != "" {
		scope = "preview"
	}
	stored, err := queries.CreateShare(ctx, controlstatedb.CreateShareParams{
		ID: id, PreviewID: nullableText(request.PreviewID), TeamID: request.TeamID, Scope: scope, Label: request.Label,
		CreatedByIdentityID: request.ActingIdentityID, IdempotencyKey: request.IdempotencyKey,
		RequestDigest: digest[:], SecretDigest: request.SecretFingerprint[:],
		CreatedAt: timestamptz(now), ExpiresAt: timestamptz(request.ExpiresAt),
	})
	if err != nil {
		return Share{}, fmt.Errorf("controlstate: create share: save share: %w", err)
	}
	if stored.PreviewID.String != request.PreviewID || stored.Scope != scope || stored.RevokedAt.Valid || subtle.ConstantTimeCompare(stored.RequestDigest, digest[:]) != 1 {
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
		if err = auditPublicMutation(ctx, tx, publicURLID, request.ActingIdentityID, "grant.create", stored.ID, stored.CreatedAt.Time); err != nil {
			return Share{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return Share{}, fmt.Errorf("controlstate: create share: commit: %w", err)
	}
	return shareFromModel(stored, ids), nil
}

// CreateGuestShare saves the same share capability used by regular URLs, but
// ties it to the live guest trial and its single demo URL.
func (d *Database) CreateGuestShare(ctx context.Context, guestID, publicURLID, key, label string, fingerprint [32]byte, expiresAt, now time.Time) (result Share, retErr error) {
	now = now.UTC().Truncate(time.Microsecond)
	expiresAt = expiresAt.UTC().Truncate(time.Microsecond)
	if guestID == "" || !opaqueid.Valid(publicURLID, opaqueid.PublicURLPrefix) || key == "" || len(key) > 128 || len(label) > 128 ||
		!expiresAt.After(now) || expiresAt.After(now.Add(maximumShareLifetime)) {
		return Share{}, ErrShareInvalid
	}
	if err := d.requireOpen(); err != nil {
		return Share{}, err
	}
	digest := sha256.Sum256([]byte(guestID + ":" + publicURLID + ":" + hex.EncodeToString(fingerprint[:]) + ":" + expiresAt.Format(time.RFC3339Nano) + ":" + label))
	id, err := opaqueid.New(opaqueid.SharePrefix)
	if err != nil {
		return Share{}, err
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return Share{}, fmt.Errorf("controlstate: create guest share: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "create guest share", &retErr)()
	q := controlstatedb.New(tx)
	route, err := q.LockPublicURLForRun(ctx, publicURLID)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (route.Purpose != "demo" || route.LifecycleState != "enabled") {
		return Share{}, ErrShareStale
	}
	if err != nil {
		return Share{}, fmt.Errorf("controlstate: create guest share: lock public URL: %w", err)
	}
	count, err := q.CountActiveSharesForPublicURL(ctx, controlstatedb.CountActiveSharesForPublicURLParams{PublicURLID: publicURLID, Now: timestamptz(now)})
	if err != nil {
		return Share{}, fmt.Errorf("controlstate: create guest share: count active shares: %w", err)
	}
	if count >= 256 {
		return Share{}, ErrShareLimit
	}
	stored, err := q.CreateGuestShare(ctx, controlstatedb.CreateGuestShareParams{
		ID: id, GuestID: guestID, PublicURLID: publicURLID, IdempotencyKey: key, Label: label,
		RequestDigest: digest[:], SecretDigest: fingerprint[:], ExpiresAt: timestamptz(expiresAt), Now: timestamptz(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Share{}, ErrShareStale
	}
	if err != nil {
		return Share{}, fmt.Errorf("controlstate: create guest share: save share: %w", err)
	}
	if stored.GuestID.String != guestID || stored.Scope != "guest" || stored.RevokedAt.Valid || subtle.ConstantTimeCompare(stored.RequestDigest, digest[:]) != 1 {
		return Share{}, ErrShareIdempotency
	}
	if _, err = q.AddGuestSharePublicURL(ctx, controlstatedb.AddGuestSharePublicURLParams{ShareID: stored.ID, PublicURLID: publicURLID}); errors.Is(err, pgx.ErrNoRows) {
		return Share{}, ErrShareStale
	} else if err != nil {
		return Share{}, fmt.Errorf("controlstate: create guest share: save public URL snapshot: %w", err)
	}
	if err = auditPublicMutation(ctx, tx, publicURLID, "", "grant.create", stored.ID, stored.CreatedAt.Time); err != nil {
		return Share{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Share{}, fmt.Errorf("controlstate: create guest share: commit: %w", err)
	}
	return shareFromModel(stored, []string{publicURLID}), nil
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
	rows, err := queries.ListShares(ctx, controlstatedb.ListSharesParams{PreviewID: text(previewID), AfterID: cursor})
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

func (d *Database) RevokeShare(ctx context.Context, id, identityID string, now time.Time) (result Share, retErr error) {
	if !opaqueid.Valid(id, opaqueid.SharePrefix) || identityID == "" {
		return Share{}, ErrShareInvalid
	}
	if err := d.requireOpen(); err != nil {
		return Share{}, err
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return Share{}, err
	}
	defer rollback(ctx, tx, "revoke anonymous share", &retErr)()
	queries := controlstatedb.New(tx)
	candidate, err := queries.GetShare(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return Share{}, ErrShareNotFound
	}
	if err != nil {
		return Share{}, err
	}
	if candidate.CreatedByIdentityID != identityID {
		return Share{}, ErrShareNotFound
	}
	if _, err = queries.LockLocalTeamForMutation(ctx, candidate.TeamID); err != nil {
		return Share{}, err
	}
	if _, err = queries.GetActivePublishRunMembership(ctx, controlstatedb.GetActivePublishRunMembershipParams{TeamID: candidate.TeamID, IdentityID: identityID}); errors.Is(err, pgx.ErrNoRows) {
		return Share{}, ErrPreviewAccess
	} else if err != nil {
		return Share{}, err
	}
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
	result, err = shareWithURLs(ctx, queries, row)
	if err != nil {
		return Share{}, err
	}
	for _, service := range result.PublicURLIDs {
		if err = auditPublicMutation(ctx, tx, service, identityID, "grant.revoke", id, now); err != nil {
			return Share{}, err
		}
	}
	return result, tx.Commit(ctx)
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
		ID:            row.ID, PreviewID: row.PreviewID.String, TeamID: row.TeamID, Scope: row.Scope, Label: row.Label,
		CreatedByIdentityID: row.CreatedByIdentityID, PublicURLIDs: ids,
		CreatedAt: row.CreatedAt.Time, ExpiresAt: row.ExpiresAt.Time, RevokedAt: optionalTime(row.RevokedAt),
	}
}
