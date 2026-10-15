package controlstate

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

type VisitorGrant struct {
	ID          string     `json:"id"`
	PublicURLID string     `json:"public_url_id"`
	Kind        string     `json:"kind"`
	Label       string     `json:"label,omitempty"`
	IdentityID  string     `json:"identity_id,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
}

// visitorManager is independent of visitor permission: a grant permits visits,
// never grant management or publishing.
func visitorManager(ctx context.Context, q *controlstatedb.Queries, url controlstatedb.ControlPublicUrl, actorID string) error {
	member, err := q.GetActivePublishRunMembership(ctx, controlstatedb.GetActivePublishRunMembershipParams{TeamID: url.TeamID, IdentityID: actorID})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrPreviewAccess
	}
	if err != nil {
		return err
	}
	if url.PublicURLScope == "member" && member.ID == url.MembershipID.String || url.PublicURLScope == "shared" && (member.Role == "owner" || member.Role == "admin") {
		return nil
	}
	return ErrPreviewAccess
}

func visitorGrantFromRow(row controlstatedb.ControlVisitorGrant) VisitorGrant {
	return VisitorGrant{ID: row.ID, PublicURLID: row.PublicURLID, Kind: row.Kind, Label: row.Label, IdentityID: row.IdentityID.String,
		CreatedAt: row.CreatedAt.Time, ExpiresAt: optionalTime(row.ExpiresAt), RevokedAt: optionalTime(row.RevokedAt)}
}

// CreateVisitorToken stores only a digest. the caller presents the one-time
// secret to the visitor; its URL and expiration are checked on every request.
func (d *Database) CreateVisitorToken(ctx context.Context, urlID, actorID, key, label string, digest [32]byte, expires, now time.Time) (result VisitorGrant, retErr error) {
	if !validFeedbackKey(key) || label == "" || len(label) > 64 || digest == ([32]byte{}) || !expires.After(now) || expires.After(now.Add(maximumShareLifetime)) {
		return result, ErrShareInvalid
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "create visitor token", &retErr)()
	q := controlstatedb.New(tx)
	url, err := lockVisitorURL(ctx, q, urlID)
	if err != nil {
		return result, err
	}
	if url.Purpose != "app" && url.Purpose != "alias" || url.ServiceProtocol != "http" {
		return result, ErrShareInvalid
	}
	if err = visitorManager(ctx, q, url, actorID); err != nil {
		return result, err
	}
	id, err := opaqueid.New(opaqueid.VisitorTokenPrefix)
	if err != nil {
		return result, err
	}
	encoded, _ := json.Marshal(struct {
		URL, Label string
		Digest     [32]byte
		Expiry     time.Time
	}{urlID, label, digest, expires})
	requestDigest := sha256.Sum256(encoded)
	row, err := q.CreateVisitorGrant(ctx, controlstatedb.CreateVisitorGrantParams{
		ID: id, PublicURLID: urlID, TeamID: url.TeamID, Kind: "token", Label: label,
		TokenDigest: digest[:], CreatedByIdentityID: actorID, IdempotencyKey: key,
		RequestDigest: requestDigest[:], CreatedAt: timestamptz(now), ExpiresAt: timestamptz(expires),
	})
	if err != nil {
		return result, err
	}
	if row.RevokedAt.Valid || subtle.ConstantTimeCompare(row.RequestDigest, requestDigest[:]) != 1 {
		return result, ErrShareIdempotency
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return visitorGrantFromRow(row), nil
}

func (d *Database) CreateTeamVisitorGrant(ctx context.Context, urlID, actorID, key string, expires *time.Time, now time.Time) (result VisitorGrant, retErr error) {
	if !validFeedbackKey(key) || expires != nil && !expires.After(now) {
		return result, ErrShareInvalid
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "create visitor grant", &retErr)()
	q := controlstatedb.New(tx)
	url, err := lockVisitorURL(ctx, q, urlID)
	if err != nil {
		return result, err
	}
	if url.Purpose != "app" || url.ServiceProtocol != "http" && !databaseProtocol(url.ServiceProtocol) {
		return result, ErrShareInvalid
	}
	if err = visitorManager(ctx, q, url, actorID); err != nil {
		return result, err
	}
	id, err := opaqueid.New(opaqueid.SharePrefix)
	if err != nil {
		return result, err
	}
	encoded, _ := json.Marshal(struct {
		URL     string
		Expires *time.Time
	}{urlID, expires})
	digest := sha256.Sum256(encoded)
	row, err := q.CreateVisitorGrant(ctx, controlstatedb.CreateVisitorGrantParams{ID: id, PublicURLID: urlID, TeamID: url.TeamID,
		Kind: "team", CreatedByIdentityID: actorID, IdempotencyKey: key, RequestDigest: digest[:], CreatedAt: timestamptz(now), ExpiresAt: nullableTime(expires)})
	if err != nil {
		return result, err
	}
	if row.RevokedAt.Valid || subtle.ConstantTimeCompare(row.RequestDigest, digest[:]) != 1 {
		return result, ErrShareIdempotency
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return visitorGrantFromRow(row), nil
}

func (d *Database) ListVisitorGrants(ctx context.Context, urlID, actorID string) (result []VisitorGrant, retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(ctx, tx, "list visitor grants", &retErr)()
	q := controlstatedb.New(tx)
	url, err := lockVisitorURL(ctx, q, urlID)
	if err != nil {
		return nil, err
	}
	if err = visitorManager(ctx, q, url, actorID); err != nil {
		return nil, err
	}
	rows, err := q.ListVisitorGrants(ctx, urlID)
	if err != nil {
		return nil, err
	}
	result = make([]VisitorGrant, len(rows))
	for index, row := range rows {
		result[index] = visitorGrantFromRow(row)
	}
	return result, tx.Commit(ctx)
}

func (d *Database) RevokeVisitorGrant(ctx context.Context, urlID, actorID, grantID string, now time.Time) (retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "revoke visitor grant", &retErr)()
	q := controlstatedb.New(tx)
	url, err := lockVisitorURL(ctx, q, urlID)
	if err != nil {
		return err
	}
	if err = visitorManager(ctx, q, url, actorID); err != nil {
		return err
	}
	grant, err := q.GetVisitorGrant(ctx, grantID)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && grant.PublicURLID != urlID {
		return ErrShareNotFound
	}
	if err != nil {
		return err
	}
	if err = q.RevokeVisitorGrant(ctx, controlstatedb.RevokeVisitorGrantParams{ID: grantID, RevokedAt: timestamptz(now)}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type VisitorInvitation struct {
	ID                 string     `json:"id"`
	PublicURLID        string     `json:"public_url_id"`
	Email              string     `json:"email"`
	ExpiresAt          time.Time  `json:"expires_at"`
	AcceptedIdentityID string     `json:"accepted_identity_id,omitempty"`
	RevokedAt          *time.Time `json:"revoked_at,omitempty"`
}

func visitorInvitationFromRow(row controlstatedb.ControlVisitorInvitation) VisitorInvitation {
	return VisitorInvitation{ID: row.ID, PublicURLID: row.PublicURLID, Email: row.NormalizedEmail, ExpiresAt: row.ExpiresAt.Time,
		AcceptedIdentityID: row.AcceptedIdentityID.String, RevokedAt: optionalTime(row.RevokedAt)}
}

// the client generates the secret; control stores only its digest.
func (d *Database) CreateVisitorInvitation(ctx context.Context, urlID, actorID, key, email string, tokenDigest [32]byte, expires, now time.Time) (result VisitorInvitation, retErr error) {
	email, err := normalizeEmailRestriction(email)
	if err != nil || email == "" || tokenDigest == ([32]byte{}) || !validFeedbackKey(key) || !expires.After(now) || expires.After(now.Add(maximumShareLifetime)) {
		return result, ErrShareInvalid
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "create visitor invitation", &retErr)()
	q := controlstatedb.New(tx)
	url, err := lockVisitorURL(ctx, q, urlID)
	if err != nil {
		return result, err
	}
	if url.Purpose != "app" || url.ServiceProtocol != "http" && !databaseProtocol(url.ServiceProtocol) {
		return result, ErrShareInvalid
	}
	if err = visitorManager(ctx, q, url, actorID); err != nil {
		return result, err
	}
	id, err := opaqueid.New(opaqueid.SharePrefix)
	if err != nil {
		return result, err
	}
	encoded, _ := json.Marshal(struct {
		URL, Email string
		Digest     [32]byte
		Expires    time.Time
	}{urlID, email, tokenDigest, expires})
	digest := sha256.Sum256(encoded)
	row, err := q.CreateVisitorInvitation(ctx, controlstatedb.CreateVisitorInvitationParams{ID: id, PublicURLID: urlID, TeamID: url.TeamID,
		NormalizedEmail: email, TokenDigest: tokenDigest[:], CreatedByIdentityID: actorID, IdempotencyKey: key, RequestDigest: digest[:], CreatedAt: timestamptz(now), ExpiresAt: timestamptz(expires)})
	if err != nil {
		return result, err
	}
	if row.RevokedAt.Valid || row.AcceptedAt.Valid || subtle.ConstantTimeCompare(row.RequestDigest, digest[:]) != 1 {
		return result, ErrShareIdempotency
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return visitorInvitationFromRow(row), nil
}

func (d *Database) AcceptVisitorInvitation(ctx context.Context, identityID, secret string, now time.Time) (result VisitorGrant, retErr error) {
	id, encoded, found := strings.Cut(secret, ".")
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if !found || !opaqueid.Valid(id, opaqueid.SharePrefix) || err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != encoded {
		return result, ErrShareNotFound
	}
	digest := sha256.Sum256(raw)
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "accept visitor invitation", &retErr)()
	q := controlstatedb.New(tx)
	candidate, err := q.GetVisitorInvitation(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrShareNotFound
	}
	if err != nil {
		return result, err
	}
	url, err := lockVisitorURL(ctx, q, candidate.PublicURLID)
	if err != nil {
		return result, err
	}
	if url.Purpose != "app" || url.ServiceProtocol != "http" && !databaseProtocol(url.ServiceProtocol) {
		return result, ErrShareNotFound
	}
	row, err := q.LockVisitorInvitation(ctx, id)
	if err != nil {
		return result, err
	}
	if row.RevokedAt.Valid || row.AcceptedAt.Valid || !row.ExpiresAt.Time.After(now) || subtle.ConstantTimeCompare(row.TokenDigest, digest[:]) != 1 {
		return result, ErrShareNotFound
	}
	identity, err := q.LockVisitorIdentity(ctx, identityID)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrVisitorSignIn
	}
	if err != nil {
		return result, err
	}
	if !identity.EmailVerified || identity.NormalizedEmail.String != row.NormalizedEmail {
		return result, ErrPreviewAccess
	}
	if err = q.AcceptVisitorInvitation(ctx, controlstatedb.AcceptVisitorInvitationParams{ID: id, AcceptedAt: timestamptz(now), AcceptedIdentityID: nullableText(identityID)}); err != nil {
		return result, err
	}
	grant, err := q.CreateVisitorGrant(ctx, controlstatedb.CreateVisitorGrantParams{ID: id, PublicURLID: url.ID, TeamID: url.TeamID, Kind: "identity", IdentityID: nullableText(identityID),
		CreatedByIdentityID: row.CreatedByIdentityID, IdempotencyKey: "invitation/" + id, RequestDigest: row.RequestDigest, CreatedAt: timestamptz(now), ExpiresAt: row.ExpiresAt})
	if err != nil {
		return result, err
	}
	if grant.ID != id || grant.Kind != "identity" || grant.IdentityID.String != identityID || grant.PublicURLID != url.ID || subtle.ConstantTimeCompare(grant.RequestDigest, row.RequestDigest) != 1 {
		return result, ErrShareIdempotency
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return visitorGrantFromRow(grant), nil
}

func (d *Database) ListVisitorInvitations(ctx context.Context, urlID, actorID string) (result []VisitorInvitation, retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(ctx, tx, "list visitor invitations", &retErr)()
	q := controlstatedb.New(tx)
	url, err := lockVisitorURL(ctx, q, urlID)
	if err != nil {
		return nil, err
	}
	if err = visitorManager(ctx, q, url, actorID); err != nil {
		return nil, err
	}
	rows, err := q.ListVisitorInvitations(ctx, urlID)
	if err != nil {
		return nil, err
	}
	result = make([]VisitorInvitation, len(rows))
	for i, row := range rows {
		result[i] = visitorInvitationFromRow(row)
	}
	return result, tx.Commit(ctx)
}

func (d *Database) RevokeVisitorInvitation(ctx context.Context, urlID, actorID, id string, now time.Time) (retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "revoke visitor invitation", &retErr)()
	q := controlstatedb.New(tx)
	url, err := lockVisitorURL(ctx, q, urlID)
	if err != nil {
		return err
	}
	if err = visitorManager(ctx, q, url, actorID); err != nil {
		return err
	}
	row, err := q.LockVisitorInvitation(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && row.PublicURLID != urlID {
		return ErrShareNotFound
	}
	if err != nil {
		return err
	}
	if err = q.RevokeVisitorInvitation(ctx, controlstatedb.RevokeVisitorInvitationParams{ID: id, RevokedAt: timestamptz(now)}); err != nil {
		return err
	}
	if row.AcceptedAt.Valid {
		if err = q.RevokeVisitorGrant(ctx, controlstatedb.RevokeVisitorGrantParams{ID: id, RevokedAt: timestamptz(now)}); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

type AvailablePublicURL struct {
	ID                string `json:"id"`
	TeamID            string `json:"team_id"`
	TeamName          string `json:"team_name"`
	CanonicalHostname string `json:"canonical_hostname"`
	ServiceProtocol   string `json:"service_protocol"`
	PublicPort        *int32 `json:"public_port,omitempty"`
	VisitorAccess     string `json:"visitor_access"`
}
type AvailablePublicURLPage struct {
	PublicURLs []AvailablePublicURL `json:"public_urls"`
	NextCursor string               `json:"next_cursor,omitempty"`
}

func (d *Database) ListAvailablePublicURLs(ctx context.Context, identityID, teamID, cursor string, now time.Time) (AvailablePublicURLPage, error) {
	rows, err := controlstatedb.New(d.pool).ListVisitorInventory(ctx, controlstatedb.ListVisitorInventoryParams{IdentityID: identityID, TeamID: teamID, Cursor: cursor, Now: timestamptz(now)})
	if err != nil {
		return AvailablePublicURLPage{}, err
	}
	page := AvailablePublicURLPage{PublicURLs: make([]AvailablePublicURL, min(len(rows), 100))}
	for i, row := range rows[:len(page.PublicURLs)] {
		item := AvailablePublicURL{ID: row.ID, TeamID: row.TeamID, TeamName: row.TeamName, CanonicalHostname: row.CanonicalHostname, ServiceProtocol: row.ServiceProtocol, VisitorAccess: row.VisitorAccess}
		if row.PublicPort.Valid {
			item.PublicPort = &row.PublicPort.Int32
		}
		page.PublicURLs[i] = item
	}
	if len(rows) > 100 {
		page.NextCursor = rows[99].ID
	}
	return page, nil
}
