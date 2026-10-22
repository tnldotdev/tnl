package controlstate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func (d *Database) IssuePublisherEnrollment(ctx context.Context, r CreatePublisherEnrollmentRequest) (result PublisherEnrollment, retErr error) {
	if !naming.ValidServiceName(r.Name) || r.Kind != "installed" && r.Kind != "automation" && r.Kind != "run" {
		return result, ErrPublisherEnrollment
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "issue publisher enrollment", &retErr)()
	q := controlstatedb.New(tx)
	resolved, err := d.authorizePublisherScope(ctx, q, r.Scope, r.EditorID, r.EditorMembershipID, r.PolicyRevision)
	if err != nil {
		return result, err
	}
	s := resolved.publisherScope()
	ownership, owner := "member", r.EditorMembershipID
	if s.Kind == "private_service" || s.PublicURLScope == PublicURLScopeShared {
		ownership, owner = "team", ""
	} else if s.Kind == "saved_url" {
		u, e := q.LockPublicURLForRun(ctx, s.PublicURLID)
		if e != nil {
			return result, e
		}
		if u.PublicURLScope == "shared" {
			ownership, owner = "team", ""
		}
	}
	if r.Ownership != "" {
		if r.Ownership != "member" && r.Ownership != "team" {
			return result, ErrPublisherEnrollment
		}
		if r.Ownership == "team" && ownership != "team" {
			return result, ErrPublisherIdentity
		}
		if r.Ownership == "member" {
			ownership, owner = "member", r.EditorMembershipID
		}
	}
	id, err := opaqueid.New(opaqueid.PublisherEnrollmentPrefix)
	if err != nil {
		return result, err
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return result, err
	}
	key := id + "." + base64.RawURLEncoding.EncodeToString(secret[:])
	digest := sha256.Sum256([]byte(key))
	until := r.Now.Add(PublisherEnrollmentLifetime)
	_, err = q.InsertPublisherEnrollment(ctx, controlstatedb.InsertPublisherEnrollmentParams{ID: id, EnrollmentKeyDigest: digest[:], TeamID: s.TeamID, Name: r.Name, IdentityKind: r.Kind, GrantKind: s.Kind, PublicURLID: nullableText(s.PublicURLID), PrivateServiceID: nullableText(s.PrivateServiceID), DomainID: nullableText(s.DomainID), Namespace: nullableText(s.Namespace), MembershipID: nullableText(s.MembershipID), PublicURLScope: nullableText(string(s.PublicURLScope)), CreatedByIdentityID: r.EditorID, CreatedAt: timestamptz(r.Now), ExpiresAt: timestamptz(until), Ownership: ownership, OwnerMembershipID: nullableText(owner)})
	if err != nil {
		return result, err
	}
	if err := tx.Commit(ctx); err != nil {
		return result, err
	}
	return PublisherEnrollment{id, key, s, until}, nil
}

func insertPublisherGrant(ctx context.Context, q *controlstatedb.Queries, publisher, issuer string, resolved resolvedPublisherScope, expires *time.Time, now time.Time) (controlstatedb.ControlPublisherGrant, error) {
	if resolved == nil {
		return controlstatedb.ControlPublisherGrant{}, ErrPublisherIdentity
	}
	s := resolved.publisherScope()
	id, err := opaqueid.New(opaqueid.PublisherGrantPrefix)
	if err != nil {
		return controlstatedb.ControlPublisherGrant{}, err
	}
	grant, err := q.InsertPublisherGrant(ctx, controlstatedb.InsertPublisherGrantParams{ID: id, PublisherIdentityID: publisher, CreatedByIdentityID: issuer, Kind: s.Kind, PublicURLID: nullableText(s.PublicURLID), PrivateServiceID: nullableText(s.PrivateServiceID), DomainID: nullableText(s.DomainID), Namespace: nullableText(s.Namespace), MembershipID: nullableText(s.MembershipID), PublicURLScope: nullableText(string(s.PublicURLScope)), CreatedAt: timestamptz(now), ExpiresAt: nullableTime(expires)})
	var constraint *pgconn.PgError
	if errors.As(err, &constraint) && constraint.Code == "23505" && (constraint.ConstraintName == "publisher_grants_active_url" || constraint.ConstraintName == "publisher_grants_active_namespace" || constraint.ConstraintName == "publisher_grants_active_private_service") {
		return grant, ErrAuthorityConflict
	}
	return grant, err
}

func insertPublisher(ctx context.Context, q *controlstatedb.Queries, resolved resolvedPublisherScope, name, kind, creator, guest, ownership, owner string, public ed25519.PublicKey, expires *time.Time, now time.Time) (PublisherIdentity, error) {
	if resolved == nil {
		return PublisherIdentity{}, ErrPublisherIdentity
	}
	s := resolved.publisherScope()
	id, err := opaqueid.New(opaqueid.PublisherIdentityPrefix)
	if err != nil {
		return PublisherIdentity{}, err
	}
	kid, err := opaqueid.New(opaqueid.PublisherIdentityKeyPrefix)
	if err != nil {
		return PublisherIdentity{}, err
	}
	if _, err := q.InsertPublisherIdentity(ctx, controlstatedb.InsertPublisherIdentityParams{ID: id, TeamID: s.TeamID, Name: name, Kind: kind, CreatedByIdentityID: creator, GuestID: nullableText(guest), CreatedAt: timestamptz(now), Ownership: ownership, OwnerMembershipID: nullableText(owner)}); err != nil {
		return PublisherIdentity{}, err
	}
	if err := q.InsertPublisherKey(ctx, controlstatedb.InsertPublisherKeyParams{ID: kid, PublisherIdentityID: id, PublicKey: public, Revision: 1, CreatedAt: timestamptz(now)}); err != nil {
		return PublisherIdentity{}, err
	}
	g, err := insertPublisherGrant(ctx, q, id, creator, resolved, expires, now)
	if err != nil {
		return PublisherIdentity{}, err
	}
	return PublisherIdentity{ID: id, KeyID: kid, GrantID: g.ID, CreatorID: creator, Kind: kind, GuestID: guest, Scope: s, Ownership: ownership, OwnerMembershipID: owner}, nil
}

func (d *Database) RedeemPublisherEnrollment(ctx context.Context, secret string, public ed25519.PublicKey, now time.Time) (result PublisherIdentity, retErr error) {
	p := strings.Split(secret, ".")
	if len(secret) > 256 || len(p) != 2 || !opaqueid.Valid(p[0], opaqueid.PublisherEnrollmentPrefix) || len(public) != 32 {
		return result, ErrPublisherEnrollment
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(p[1])
	if err != nil || len(b) != 32 {
		return result, ErrPublisherEnrollment
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "redeem publisher enrollment", &retErr)()
	q := controlstatedb.New(tx)
	e, err := q.LockPublisherEnrollment(ctx, p[0])
	if err != nil {
		return result, publisherLookupError(err, ErrPublisherEnrollment)
	}
	digest := sha256.Sum256([]byte(secret))
	if subtle.ConstantTimeCompare(digest[:], e.EnrollmentKeyDigest) != 1 || !e.ExpiresAt.Time.After(now) {
		return result, ErrPublisherEnrollment
	}
	s := PublisherScope{TeamID: e.TeamID, Kind: e.GrantKind, PublicURLID: e.PublicURLID.String, PrivateServiceID: e.PrivateServiceID.String, DomainID: e.DomainID.String, Namespace: e.Namespace.String, MembershipID: e.MembershipID.String, PublicURLScope: PublicURLScope(e.PublicURLScope.String)}
	if e.RedeemedAt.Valid {
		if subtle.ConstantTimeCompare(e.RedeemedPublicKey, public) != 1 {
			return result, ErrPublisherEnrollment
		}
		result, _, err = d.livePublisher(ctx, q, e.RedeemedIdentityID.String, e.RedeemedGrantID.String, "", now)
		if err != nil {
			return PublisherIdentity{}, publisherLookupError(err, ErrPublisherEnrollment)
		}
		result.KeyID = e.RedeemedKeyID.String
		return result, nil
	}
	resolved, err := resolvePublisherScope(ctx, q, s, "")
	if err != nil {
		return result, publisherLookupError(err, ErrPublisherEnrollment)
	}
	if e.Ownership == "member" {
		active, err := q.ActiveCompanyMembership(ctx, controlstatedb.ActiveCompanyMembershipParams{MembershipID: e.OwnerMembershipID.String, Now: timestamptz(now)})
		if err != nil {
			return result, err
		}
		if !active {
			return result, ErrPublisherEnrollment
		}
	}
	var expires *time.Time
	if e.IdentityKind == "automation" || e.IdentityKind == "run" {
		until := now.Add(time.Hour)
		expires = &until
	}
	result, err = insertPublisher(ctx, q, resolved, e.Name, e.IdentityKind, e.CreatedByIdentityID, "", e.Ownership, e.OwnerMembershipID.String, public, expires, now)
	if err != nil {
		return result, err
	}
	if err := q.RedeemPublisherEnrollment(ctx, controlstatedb.RedeemPublisherEnrollmentParams{ID: e.ID, IdentityID: text(result.ID), KeyID: text(result.KeyID), GrantID: text(result.GrantID), PublicKey: public, Now: timestamptz(now)}); err != nil {
		return PublisherIdentity{}, err
	}
	return result, tx.Commit(ctx)
}

// enroll a guest only after its demo URL exists. the trial credential is a
// bootstrap credential, never a publisher namespace or run credential.
func (d *Database) EnrollGuestPublisher(ctx context.Context, guestID, urlID, sourceIP string, public ed25519.PublicKey, now time.Time) (result PublisherIdentity, retErr error) {
	if len(public) != 32 || sourceIP == "" {
		return result, ErrPublisherIdentity
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "enroll guest publisher", &retErr)()
	q := controlstatedb.New(tx)
	u, err := q.LockPublicURLForRun(ctx, urlID)
	if err != nil {
		return result, err
	}
	trial, err := q.LockGuestTrialByID(ctx, guestID)
	if err != nil {
		return result, err
	}
	match, err := d.GuestSourceMatches(GuestTrial{ID: trial.ID, SourceIPDigest: trial.SourceIpDigest.String, SourceIPKeyID: trial.SourceIpKeyID.String}, sourceIP)
	if err != nil || !match || !trial.ExpiresAt.Time.After(now) || trial.EndedAt.Valid || trial.UsedReadyNs >= int64(GuestReadyAllowance) || trial.UsedBytes >= GuestByteAllowance {
		return result, ErrPublisherIdentity
	}
	s := PublisherScope{TeamID: trial.TeamID, Kind: "saved_url", PublicURLID: urlID}
	resolved, err := resolvePublisherScope(ctx, q, s, guestID)
	if err != nil {
		return result, err
	}
	// one identity per URL/key; competing keys cannot take over a trial URL.
	var existing, existingGrant, existingKey string
	var existingPublic []byte
	var revoked bool
	err = tx.QueryRow(ctx, `SELECT p.id, g.id, k.id, k.public_key, p.revoked_at IS NOT NULL OR g.revoked_at IS NOT NULL FROM control.publisher_identities p JOIN control.publisher_grants g ON g.publisher_identity_id=p.id JOIN control.publisher_identity_keys k ON k.publisher_identity_id=p.id AND k.retired_at IS NULL WHERE p.guest_id=$1 AND g.public_url_id=$2`, guestID, urlID).Scan(&existing, &existingGrant, &existingKey, &existingPublic, &revoked)
	if err == nil {
		if revoked || subtle.ConstantTimeCompare(existingPublic, public) != 1 {
			return result, ErrPublisherIdentity
		}
		return PublisherIdentity{ID: existing, KeyID: existingKey, GrantID: existingGrant, CreatorID: u.CreatedByIdentityID, Kind: "guest", GuestID: guestID, Scope: s}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}
	until := trial.ExpiresAt.Time
	result, err = insertPublisher(ctx, q, resolved, "guest", "guest", u.CreatedByIdentityID, guestID, "guest", "", public, &until, now)
	if err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}
