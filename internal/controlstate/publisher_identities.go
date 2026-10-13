package controlstate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisheridentity"
)

const (
	publisherEnrollmentLifetime = 10 * time.Minute
	publisherAccessLifetime     = 5 * time.Minute
)

var ErrPublisherIdentity = errors.New("publisher identity or grant is unavailable")
var ErrPublisherEnrollment = errors.New("publisher enrollment key is invalid or already used")

type PublisherScope struct {
	TeamID, PublicURLID, DomainID, Namespace string
	Kind                                     string
}

func (s PublisherScope) valid() bool {
	return validStateText(s.TeamID) && (s.Kind == "saved_url" && validStateText(s.PublicURLID) && s.DomainID == "" && s.Namespace == "" ||
		s.Kind == "namespace" && s.PublicURLID == "" && validStateText(s.DomainID) && validStateText(s.Namespace))
}

type PublisherEnrollment struct {
	ID, Key string
	Scope   PublisherScope
	Until   time.Time
}

type CreatePublisherEnrollmentRequest struct {
	Scope              PublisherScope
	Name, Kind         string
	EditorID           string
	EditorMembershipID string
	PolicyRevision     uint64
	Now                time.Time
}

type PublisherIdentity struct {
	ID, KeyID, GrantID string
	Scope              PublisherScope
}

type PublisherManagementGrant struct {
	ID, Kind, PublicURLMembershipID string
}

func (d *Database) PublisherManagementGrants(ctx context.Context, teamID, publisherID string) ([]PublisherManagementGrant, error) {
	rows, err := controlstatedb.New(d.pool).ListPublisherIdentityManagementGrants(ctx, controlstatedb.ListPublisherIdentityManagementGrantsParams{
		PublisherIdentityID: publisherID, TeamID: teamID,
	})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, ErrPublisherIdentity
	}
	result := make([]PublisherManagementGrant, 0, len(rows))
	for _, row := range rows {
		result = append(result, PublisherManagementGrant{ID: row.GrantID, Kind: row.Kind, PublicURLMembershipID: row.PublicUrlMembershipID.String})
	}
	return result, nil
}

// IssuePublisherEnrollment saves a short-lived one-use invitation after the
// caller's current editor authorization is checked again at the http boundary.
func (d *Database) IssuePublisherEnrollment(ctx context.Context, request CreatePublisherEnrollmentRequest) (PublisherEnrollment, error) {
	scope, now := request.Scope, request.Now
	if !scope.valid() || !naming.ValidServiceName(request.Name) || !validStateText(request.EditorID) ||
		!validStateText(request.EditorMembershipID) || request.PolicyRevision == 0 ||
		request.Kind != "installed" && request.Kind != "automation" {
		return PublisherEnrollment{}, ErrPublisherEnrollment
	}
	if err := d.requireOpen(); err != nil {
		return PublisherEnrollment{}, err
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return PublisherEnrollment{}, err
	}
	defer tx.Rollback(ctx)
	queries := controlstatedb.New(tx)
	if err := authorizePublisherGrantScope(ctx, queries, scope, request.EditorID, request.EditorMembershipID, request.PolicyRevision); err != nil {
		return PublisherEnrollment{}, err
	}
	id, err := opaqueid.New(opaqueid.PublisherEnrollmentPrefix)
	if err != nil {
		return PublisherEnrollment{}, err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return PublisherEnrollment{}, err
	}
	key := id + "." + base64.RawURLEncoding.EncodeToString(secret)
	digest := sha256.Sum256([]byte(key))
	until := now.Add(publisherEnrollmentLifetime)
	_, err = queries.CreatePublisherEnrollment(ctx, controlstatedb.CreatePublisherEnrollmentParams{
		ID: id, TokenDigest: digest[:], TeamID: scope.TeamID, Name: request.Name, IdentityKind: request.Kind,
		GrantKind: scope.Kind, PublicURLID: nullableText(scope.PublicURLID),
		DomainID: nullableText(scope.DomainID), Namespace: nullableText(scope.Namespace),
		CreatedByIdentityID: request.EditorID, CreatedAt: timestamptz(now), ExpiresAt: timestamptz(until),
	})
	if err != nil {
		return PublisherEnrollment{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return PublisherEnrollment{}, err
	}
	return PublisherEnrollment{ID: id, Key: key, Scope: scope, Until: until}, nil
}

func authorizePublisherGrantScope(ctx context.Context, queries *controlstatedb.Queries, scope PublisherScope, editorID, membershipID string, policyRevision uint64) error {
	if !scope.valid() || !validStateText(editorID) || !validStateText(membershipID) || policyRevision == 0 {
		return ErrPublisherIdentity
	}
	membership, err := queries.GetActivePublishRunMembership(ctx, controlstatedb.GetActivePublishRunMembershipParams{
		TeamID: scope.TeamID, IdentityID: editorID,
	})
	if err != nil || membership.ID != membershipID || membership.PolicyRevision != int64(policyRevision) {
		return ErrPublisherIdentity
	}
	if err := validatePublisherScope(ctx, queries, scope); err != nil {
		return err
	}
	if scope.Kind == "saved_url" {
		route, err := queries.GetPublisherGrantURL(ctx, scope.PublicURLID)
		if err != nil || route.PublicURLScope == "member" && route.MembershipID.String != membership.ID ||
			route.PublicURLScope == "shared" && membership.Role != "admin" && membership.Role != "owner" {
			return ErrPublisherIdentity
		}
	}
	return nil
}

// RedeemPublisherEnrollment serializes consumption under the enrollment row
// lock. a retry using the same key and registered public key recovers its IDs.
func (d *Database) RedeemPublisherEnrollment(ctx context.Context, key string, public ed25519.PublicKey, now time.Time) (result PublisherIdentity, retErr error) {
	parts := strings.Split(key, ".")
	if len(parts) != 2 || !opaqueid.Valid(parts[0], opaqueid.PublisherEnrollmentPrefix) || len(public) != ed25519.PublicKeySize || len(key) > 256 {
		return PublisherIdentity{}, ErrPublisherEnrollment
	}
	if secret, err := base64.RawURLEncoding.DecodeString(parts[1]); err != nil || len(secret) != 32 {
		return PublisherIdentity{}, ErrPublisherEnrollment
	}
	if err := d.requireOpen(); err != nil {
		return PublisherIdentity{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return PublisherIdentity{}, err
	}
	defer rollback(ctx, tx, "redeem publisher enrollment", &retErr)()
	queries := controlstatedb.New(tx)
	enrollment, err := queries.LockPublisherEnrollment(ctx, parts[0])
	if errors.Is(err, pgx.ErrNoRows) {
		return PublisherIdentity{}, ErrPublisherEnrollment
	}
	if err != nil {
		return PublisherIdentity{}, err
	}
	digest := sha256.Sum256([]byte(key))
	if subtle.ConstantTimeCompare(enrollment.TokenDigest, digest[:]) != 1 {
		return PublisherIdentity{}, ErrPublisherEnrollment
	}
	scope := PublisherScope{TeamID: enrollment.TeamID, Kind: enrollment.GrantKind,
		PublicURLID: enrollment.PublicURLID.String, DomainID: enrollment.DomainID.String, Namespace: enrollment.Namespace.String}
	if enrollment.RedeemedAt.Valid {
		if subtle.ConstantTimeCompare(enrollment.RedeemedPublicKey, public) != 1 {
			return PublisherIdentity{}, ErrPublisherEnrollment
		}
		return PublisherIdentity{ID: enrollment.RedeemedIdentityID.String,
			KeyID: enrollment.RedeemedKeyID.String, GrantID: enrollment.RedeemedGrantID.String, Scope: scope}, nil
	}
	if !enrollment.ExpiresAt.Time.After(now) || validatePublisherScope(ctx, queries, scope) != nil {
		return PublisherIdentity{}, ErrPublisherEnrollment
	}
	id, err := opaqueid.New(opaqueid.PublisherIdentityPrefix)
	if err != nil {
		return PublisherIdentity{}, err
	}
	keyID, err := opaqueid.New(opaqueid.PublisherIdentityKeyPrefix)
	if err != nil {
		return PublisherIdentity{}, err
	}
	grantID, err := opaqueid.New(opaqueid.PublisherGrantPrefix)
	if err != nil {
		return PublisherIdentity{}, err
	}
	if _, err := queries.InsertPublisherIdentity(ctx, controlstatedb.InsertPublisherIdentityParams{
		ID: id, TeamID: scope.TeamID, Name: enrollment.Name, Kind: enrollment.IdentityKind,
		CreatedByIdentityID: text(enrollment.CreatedByIdentityID), CreatedAt: timestamptz(now),
	}); err != nil {
		return PublisherIdentity{}, err
	}
	if _, err := queries.InsertPublisherIdentityKey(ctx, controlstatedb.InsertPublisherIdentityKeyParams{
		ID: keyID, PublisherIdentityID: id, Revision: 1, PublicKey: public, CreatedAt: timestamptz(now),
	}); err != nil {
		return PublisherIdentity{}, err
	}
	var expiresAt *time.Time
	if enrollment.IdentityKind == "automation" {
		short := now.Add(time.Hour)
		expiresAt = &short
	}
	if _, err := queries.InsertPublisherIdentityGrant(ctx, controlstatedb.InsertPublisherIdentityGrantParams{
		ID: grantID, PublisherIdentityID: id, Kind: scope.Kind,
		PublicURLID: nullableText(scope.PublicURLID), DomainID: nullableText(scope.DomainID), Namespace: nullableText(scope.Namespace),
		CreatedAt: timestamptz(now), ExpiresAt: nullableTime(expiresAt),
	}); err != nil {
		return PublisherIdentity{}, err
	}
	updated, err := queries.RedeemPublisherEnrollment(ctx, controlstatedb.RedeemPublisherEnrollmentParams{
		ID: enrollment.ID, PublisherIdentityID: text(id), KeyID: text(keyID), GrantID: text(grantID),
		PublicKey: public, RedeemedAt: timestamptz(now),
	})
	if err != nil || updated != 1 {
		return PublisherIdentity{}, ErrPublisherEnrollment
	}
	if err := tx.Commit(ctx); err != nil {
		return PublisherIdentity{}, err
	}
	return PublisherIdentity{ID: id, KeyID: keyID, GrantID: grantID, Scope: scope}, nil
}

type CreatePublisherGrantRequest struct {
	PublisherIdentityID string
	Scope               PublisherScope
	EditorID            string
	EditorMembershipID  string
	PolicyRevision      uint64
	ExpiresAt           *time.Time
	Now                 time.Time
}

// CreatePublisherGrant adds one independently revocable scope to an active
// identity after checking the current URL editor and team boundary.
func (d *Database) CreatePublisherGrant(ctx context.Context, request CreatePublisherGrantRequest) (result string, retErr error) {
	if !opaqueid.Valid(request.PublisherIdentityID, opaqueid.PublisherIdentityPrefix) ||
		request.ExpiresAt != nil && !request.ExpiresAt.After(request.Now) {
		return "", ErrPublisherIdentity
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer rollback(ctx, tx, "create publisher grant", &retErr)()
	queries := controlstatedb.New(tx)
	identity, err := queries.LockPublisherIdentity(ctx, request.PublisherIdentityID)
	if err != nil || identity.TeamID != request.Scope.TeamID || identity.RevokedAt.Valid {
		return "", ErrPublisherIdentity
	}
	if err := authorizePublisherGrantScope(ctx, queries, request.Scope, request.EditorID, request.EditorMembershipID, request.PolicyRevision); err != nil {
		return "", err
	}
	id, err := opaqueid.New(opaqueid.PublisherGrantPrefix)
	if err != nil {
		return "", err
	}
	if _, err := queries.InsertPublisherIdentityGrant(ctx, controlstatedb.InsertPublisherIdentityGrantParams{
		ID: id, PublisherIdentityID: request.PublisherIdentityID, Kind: request.Scope.Kind,
		PublicURLID: nullableText(request.Scope.PublicURLID), DomainID: nullableText(request.Scope.DomainID),
		Namespace: nullableText(request.Scope.Namespace), CreatedAt: timestamptz(request.Now),
		ExpiresAt: nullableTime(request.ExpiresAt),
	}); err != nil {
		var constraint *pgconn.PgError
		if errors.As(err, &constraint) && constraint.Code == "23505" &&
			(constraint.ConstraintName == "publisher_identity_grants_active_url" || constraint.ConstraintName == "publisher_identity_grants_active_namespace") {
			return "", ErrPublisherIdentity
		}
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return id, nil
}

func (d *Database) RevokePublisherGrant(ctx context.Context, teamID, publisherID, grantID string, now time.Time) error {
	revoked, err := controlstatedb.New(d.pool).RevokePublisherIdentityGrant(ctx, controlstatedb.RevokePublisherIdentityGrantParams{
		ID: grantID, PublisherIdentityID: publisherID, TeamID: teamID, RevokedAt: timestamptz(now),
	})
	if err != nil {
		return err
	}
	if revoked != 1 {
		return ErrPublisherIdentity
	}
	return nil
}

func validatePublisherScope(ctx context.Context, queries *controlstatedb.Queries, scope PublisherScope) error {
	if !scope.valid() {
		return ErrPublisherIdentity
	}
	if scope.Kind == "saved_url" {
		route, err := queries.GetPublisherGrantURL(ctx, scope.PublicURLID)
		if err != nil || route.TeamID != scope.TeamID || route.Ephemeral || route.LifecycleState != string(PublicURLLifecycleEnabled) || route.Purpose != string(PublicURLPurposeApp) {
			return ErrPublisherIdentity
		}
		return nil
	}
	domain, err := queries.GetReadyEphemeralCredentialDomain(ctx, controlstatedb.GetReadyEphemeralCredentialDomainParams{
		DomainID: scope.DomainID, TeamID: text(scope.TeamID),
	})
	if err != nil || domain.ID != scope.DomainID || !hostnameWithin(scope.Namespace, domain.CanonicalDomain) {
		return ErrPublisherIdentity
	}
	return nil
}

type PublisherAccess struct {
	PublisherIdentity
	Token string
	Until time.Time
}

// ExchangePublisherAssertion issues a token for exactly one active grant. the
// same assertion ID cannot mint another token, even under concurrent exchange.
func (d *Database) ExchangePublisherAssertion(ctx context.Context, clientID, grantID, audience, jwt string, now time.Time) (result PublisherAccess, retErr error) {
	if !opaqueid.Valid(clientID, opaqueid.PublisherIdentityPrefix) || !opaqueid.Valid(grantID, opaqueid.PublisherGrantPrefix) {
		return PublisherAccess{}, ErrPublisherIdentity
	}
	keyID, err := publisheridentity.KeyID(jwt)
	if err != nil {
		return PublisherAccess{}, ErrPublisherIdentity
	}
	if err := d.requireOpen(); err != nil {
		return PublisherAccess{}, err
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return PublisherAccess{}, err
	}
	defer rollback(ctx, tx, "exchange publisher assertion", &retErr)()
	queries := controlstatedb.New(tx)
	identity, err := queries.LockPublisherIdentity(ctx, clientID)
	if err != nil || identity.RevokedAt.Valid {
		return PublisherAccess{}, ErrPublisherIdentity
	}
	key, err := queries.GetPublisherIdentityKey(ctx, controlstatedb.GetPublisherIdentityKeyParams{
		KeyID: keyID, PublisherIdentityID: clientID,
	})
	if err != nil || key.RetiredAt.Valid || key.IdentityRevokedAt.Valid {
		return PublisherAccess{}, ErrPublisherIdentity
	}
	assertion, err := publisheridentity.Verify(jwt, clientID, audience, keyID, key.PublicKey, now)
	if err != nil {
		return PublisherAccess{}, ErrPublisherIdentity
	}
	grant, err := queries.GetPublisherIdentityGrant(ctx, controlstatedb.GetPublisherIdentityGrantParams{
		GrantID: grantID, PublisherIdentityID: clientID,
	})
	if err != nil || grant.RevokedAt.Valid || grant.IdentityRevokedAt.Valid || grant.ExpiresAt.Valid && !grant.ExpiresAt.Time.After(now) {
		return PublisherAccess{}, ErrPublisherIdentity
	}
	scope := PublisherScope{TeamID: identity.TeamID, Kind: grant.Kind, PublicURLID: grant.PublicURLID.String,
		DomainID: grant.DomainID.String, Namespace: grant.Namespace.String}
	if err := validatePublisherScope(ctx, queries, scope); err != nil {
		return PublisherAccess{}, ErrPublisherIdentity
	}
	if err := queries.DeleteExpiredPublisherAssertions(ctx, timestamptz(now)); err != nil {
		return PublisherAccess{}, err
	}
	if err := queries.DeleteExpiredPublisherAccessTokens(ctx, timestamptz(now)); err != nil {
		return PublisherAccess{}, err
	}
	claimed, err := queries.ClaimPublisherAssertion(ctx, controlstatedb.ClaimPublisherAssertionParams{
		PublisherIdentityID: clientID, AssertionID: assertion.ID, ExpiresAt: timestamptz(assertion.Until),
	})
	if err != nil || claimed != 1 {
		return PublisherAccess{}, ErrPublisherIdentity
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return PublisherAccess{}, err
	}
	access := "pta_" + base64.RawURLEncoding.EncodeToString(secret)
	digest := sha256.Sum256([]byte(access))
	until := now.Add(publisherAccessLifetime)
	if grant.ExpiresAt.Valid && grant.ExpiresAt.Time.Before(until) {
		until = grant.ExpiresAt.Time
	}
	if err := queries.InsertPublisherAccessToken(ctx, controlstatedb.InsertPublisherAccessTokenParams{
		Digest: digest[:], PublisherIdentityID: clientID, GrantID: grantID, KeyID: keyID,
		CreatedAt: timestamptz(now), ExpiresAt: timestamptz(until),
	}); err != nil {
		return PublisherAccess{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return PublisherAccess{}, err
	}
	return PublisherAccess{PublisherIdentity: PublisherIdentity{ID: clientID, KeyID: keyID, GrantID: grantID, Scope: scope}, Token: access, Until: until}, nil
}

// AuthenticatePublisherAccess rechecks grant and identity revocation. the
// caller must also verify current saved-URL or namespace policy for its action.
func (d *Database) AuthenticatePublisherAccess(ctx context.Context, token string, now time.Time) (PublisherIdentity, error) {
	if !strings.HasPrefix(token, "pta_") || len(token) != 47 {
		return PublisherIdentity{}, ErrPublisherIdentity
	}
	digest := sha256.Sum256([]byte(token))
	row, err := controlstatedb.New(d.pool).GetPublisherAccessToken(ctx, digest[:])
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (row.IdentityRevokedAt.Valid || row.GrantRevokedAt.Valid ||
		!row.ExpiresAt.Time.After(now) || row.GrantExpiresAt.Valid && !row.GrantExpiresAt.Time.After(now)) {
		return PublisherIdentity{}, ErrPublisherIdentity
	}
	if err != nil {
		return PublisherIdentity{}, fmt.Errorf("read publisher access token: %w", err)
	}
	return PublisherIdentity{ID: row.PublisherIdentityID, GrantID: row.GrantID, KeyID: row.KeyID,
		Scope: PublisherScope{TeamID: row.TeamID, Kind: row.Kind, PublicURLID: row.PublicURLID.String,
			DomainID: row.DomainID.String, Namespace: row.Namespace.String}}, nil
}

// RotatePublisherKey requires a current scoped token from the previous key
// and a signed assertion proving possession of the replacement key. existing
// run credentials and issued access tokens remain valid until their own expiry.
func (d *Database) RotatePublisherKey(ctx context.Context, token, replacementID, audience string, public ed25519.PublicKey, proof string, now time.Time) (retErr error) {
	if !opaqueid.Valid(replacementID, opaqueid.PublisherIdentityKeyPrefix) || len(public) != ed25519.PublicKeySize {
		return ErrPublisherIdentity
	}
	identity, err := d.AuthenticatePublisherAccess(ctx, token, now)
	if err != nil {
		return err
	}
	assertion, err := publisheridentity.Verify(proof, identity.ID, audience, replacementID, public, now)
	if err != nil {
		return ErrPublisherIdentity
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "rotate publisher key", &retErr)()
	queries := controlstatedb.New(tx)
	current, err := queries.LockPublisherIdentityForRotation(ctx, identity.ID)
	if err != nil || current.RevokedAt.Valid {
		return ErrPublisherIdentity
	}
	grant, err := queries.GetPublisherIdentityGrant(ctx, controlstatedb.GetPublisherIdentityGrantParams{
		GrantID: identity.GrantID, PublisherIdentityID: identity.ID,
	})
	if err != nil || grant.RevokedAt.Valid || grant.ExpiresAt.Valid && !grant.ExpiresAt.Time.After(now) {
		return ErrPublisherIdentity
	}
	key, err := queries.GetPublisherIdentityKey(ctx, controlstatedb.GetPublisherIdentityKeyParams{
		KeyID: identity.KeyID, PublisherIdentityID: identity.ID,
	})
	if err != nil || key.RetiredAt.Valid {
		return ErrPublisherIdentity
	}
	if err := queries.DeleteExpiredPublisherAssertions(ctx, timestamptz(now)); err != nil {
		return err
	}
	claimed, err := queries.ClaimPublisherAssertion(ctx, controlstatedb.ClaimPublisherAssertionParams{
		PublisherIdentityID: identity.ID, AssertionID: assertion.ID, ExpiresAt: timestamptz(assertion.Until),
	})
	if err != nil || claimed != 1 {
		return ErrPublisherIdentity
	}
	revision, err := queries.NextPublisherIdentityKeyRevision(ctx, identity.ID)
	if err != nil {
		return err
	}
	if _, err := queries.InsertPublisherIdentityKey(ctx, controlstatedb.InsertPublisherIdentityKeyParams{
		ID: replacementID, PublisherIdentityID: identity.ID, PublicKey: public,
		Revision: int64(revision), CreatedAt: timestamptz(now),
	}); err != nil {
		return err
	}
	retired, err := queries.RetirePublisherIdentityKey(ctx, controlstatedb.RetirePublisherIdentityKeyParams{
		ID: identity.KeyID, PublisherIdentityID: identity.ID, RetiredAt: timestamptz(now),
	})
	if err != nil || retired != 1 {
		return ErrPublisherIdentity
	}
	return tx.Commit(ctx)
}

func (d *Database) RevokePublisherIdentity(ctx context.Context, teamID, publisherID string, now time.Time) error {
	_, err := controlstatedb.New(d.pool).RevokePublisherIdentity(ctx, controlstatedb.RevokePublisherIdentityParams{
		ID: publisherID, TeamID: teamID, RevokedAt: timestamptz(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrPublisherIdentity
	}
	return err
}

// BindPublisherRun connects one active run to the current identity grant
// while holding the public URL and run locks.
func (d *Database) BindPublisherRun(ctx context.Context, runID, publicURLID string, identity PublisherIdentity, now time.Time) (retErr error) {
	if identity.ID == "" || identity.GrantID == "" || identity.Scope.PublicURLID != publicURLID {
		return ErrPublisherIdentity
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "bind publisher run", &retErr)()
	queries := controlstatedb.New(tx)
	route, err := queries.LockPublicURLForRun(ctx, publicURLID)
	if err != nil || route.TeamID != identity.Scope.TeamID || route.LifecycleState != string(PublicURLLifecycleEnabled) {
		return ErrPublisherIdentity
	}
	run, err := queries.LockPublishRun(ctx, runID)
	if err != nil || run.PublicURLID != publicURLID || run.ClosedAt.Valid {
		return ErrPublisherIdentity
	}
	grant, err := queries.GetPublisherIdentityGrant(ctx, controlstatedb.GetPublisherIdentityGrantParams{
		GrantID: identity.GrantID, PublisherIdentityID: identity.ID,
	})
	if err != nil || grant.TeamID != route.TeamID || grant.Kind != "saved_url" || grant.PublicURLID.String != publicURLID ||
		grant.IdentityRevokedAt.Valid || grant.RevokedAt.Valid || grant.ExpiresAt.Valid && !grant.ExpiresAt.Time.After(now) {
		return ErrPublisherIdentity
	}
	bound, err := queries.AttachPublishRunIdentity(ctx, controlstatedb.AttachPublishRunIdentityParams{
		PublisherIdentityID: identity.ID, GrantID: identity.GrantID, PublishRunID: runID, PublicURLID: publicURLID,
		CreatedAt: timestamptz(now),
	})
	if err != nil || bound != 1 {
		return ErrPublisherIdentity
	}
	return tx.Commit(ctx)
}
