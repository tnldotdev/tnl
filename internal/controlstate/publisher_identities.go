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
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisheridentity"
)

var ErrPublisherIdentity = errors.New("publisher identity or grant is unavailable")
var ErrPublisherEnrollment = errors.New("publisher enrollment is invalid, expired, or consumed")

const PublisherEnrollmentLifetime = 10 * time.Minute
const PublisherAccessLifetime = 5 * time.Minute

type PublisherScope struct {
	TeamID, Kind, PublicURLID, PrivateServiceID, DomainID, Namespace, MembershipID string
	PublicURLScope                                                                 PublicURLScope
}
type PublisherIdentity struct {
	ID, KeyID, GrantID, CreatorID, Kind, GuestID string
	Scope                                        PublisherScope
}
type PublisherEnrollment struct {
	ID, Key string
	Scope   PublisherScope
	Until   time.Time
}
type PublisherAccess struct {
	PublisherIdentity
	Token string
	Until time.Time
}
type CreatePublisherEnrollmentRequest struct {
	Scope                                    PublisherScope
	Name, Kind, EditorID, EditorMembershipID string
	PolicyRevision                           uint64
	Now                                      time.Time
}
type CreatePublisherGrantRequest struct {
	PublisherIdentityID          string
	Scope                        PublisherScope
	EditorID, EditorMembershipID string
	PolicyRevision               uint64
	ExpiresAt                    *time.Time
	Now                          time.Time
}

func publisherLookupError(err, unavailable error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return unavailable
	}
	return err
}

func scopeFromGrant(team string, g controlstatedb.ControlPublisherGrant) PublisherScope {
	return PublisherScope{TeamID: team, Kind: g.Kind, PublicURLID: g.PublicURLID.String, PrivateServiceID: g.PrivateServiceID.String, DomainID: g.DomainID.String, Namespace: g.Namespace.String, MembershipID: g.MembershipID.String, PublicURLScope: PublicURLScope(g.PublicURLScope.String)}
}

// authorizePublisherScope captures an explicit grant after checking the current
// editor under team/membership locks. grant use never consults that membership.
func (d *Database) authorizePublisherScope(ctx context.Context, q *controlstatedb.Queries, scope PublisherScope, editor, membership string, revision uint64) (PublisherScope, error) {
	if !validStateText(editor) || revision == 0 {
		return scope, ErrPublisherIdentity
	}
	if _, err := q.LockLocalTeamForMutation(ctx, scope.TeamID); err != nil {
		return scope, err
	}
	m, err := q.GetActivePublishRunMembership(ctx, controlstatedb.GetActivePublishRunMembershipParams{TeamID: scope.TeamID, IdentityID: editor})
	if err != nil {
		return scope, publisherLookupError(err, ErrPublisherIdentity)
	}
	if m.ID != membership || m.PolicyRevision != int64(revision) {
		return scope, ErrPublisherIdentity
	}
	if scope.Kind == "private_service" {
		if !opaqueid.Valid(scope.PrivateServiceID, opaqueid.PrivateServicePrefix) || scope.PublicURLID != "" || scope.DomainID != "" || scope.Namespace != "" ||
			scope.MembershipID != "" || scope.PublicURLScope != "" || m.Role != "owner" && m.Role != "admin" {
			return scope, ErrPublisherIdentity
		}
		s, err := q.LockPrivateService(ctx, scope.PrivateServiceID)
		if err != nil {
			return scope, publisherLookupError(err, ErrPublisherIdentity)
		}
		if s.TeamID != scope.TeamID || !s.Enabled || s.DeletedAt.Valid {
			return scope, ErrPublisherIdentity
		}
		return scope, nil
	}
	if scope.Kind == "saved_url" {
		if scope.PrivateServiceID != "" || scope.DomainID != "" || scope.Namespace != "" {
			return scope, ErrPublisherIdentity
		}
		u, err := q.LockPublicURLForRun(ctx, scope.PublicURLID)
		if err != nil {
			return scope, publisherLookupError(err, ErrPublisherIdentity)
		}
		if u.TeamID != scope.TeamID || u.Ephemeral || u.LifecycleState != "enabled" || !PublicURLPurpose(u.Purpose).ValidForCreation() ||
			u.PublicURLScope == "member" && u.MembershipID.String != m.ID || u.PublicURLScope == "shared" && m.Role != "owner" && m.Role != "admin" {
			return scope, ErrPublisherIdentity
		}
		return PublisherScope{TeamID: scope.TeamID, Kind: "saved_url", PublicURLID: u.ID}, nil
	}
	if scope.Kind != "namespace" || scope.PublicURLID != "" || scope.PrivateServiceID != "" {
		return scope, ErrPublisherIdentity
	}
	c, err := q.GetPublicURLCreationContext(ctx, controlstatedb.GetPublicURLCreationContextParams{IdentityID: editor, DomainID: scope.DomainID, TeamID: scope.TeamID})
	if err != nil {
		return scope, err
	}
	if c.DomainState != "ready" {
		return scope, ErrPublisherIdentity
	}
	ns, direct := naming.PublicURLNamespace(naming.NamespaceFacts{Domain: c.CanonicalDomain, Managed: c.DomainKind == "managed", Mode: d.managedURLMode, Personal: c.TeamKind == "personal", Builtin: c.IdentityKind == "builtin" && c.TeamKind == "personal", TeamName: c.TeamDisplayName, MemberSlug: c.ActorMemberSlug, ManagedLabel: c.ActorManagedLabel})
	if ns == "" || scope.Namespace != "" && scope.Namespace != ns {
		return scope, ErrPublisherIdentity
	}
	scope.Namespace = ns
	scope.PublicURLScope, scope.MembershipID = PublicURLScopeMember, m.ID
	if direct {
		scope.PublicURLScope, scope.MembershipID = PublicURLScopeShared, ""
	}
	return scope, nil
}

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
	s, err := d.authorizePublisherScope(ctx, q, r.Scope, r.EditorID, r.EditorMembershipID, r.PolicyRevision)
	if err != nil {
		return result, err
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
	_, err = q.InsertPublisherEnrollment(ctx, controlstatedb.InsertPublisherEnrollmentParams{ID: id, EnrollmentKeyDigest: digest[:], TeamID: s.TeamID, Name: r.Name, IdentityKind: r.Kind, GrantKind: s.Kind, PublicURLID: nullableText(s.PublicURLID), PrivateServiceID: nullableText(s.PrivateServiceID), DomainID: nullableText(s.DomainID), Namespace: nullableText(s.Namespace), MembershipID: nullableText(s.MembershipID), PublicURLScope: nullableText(string(s.PublicURLScope)), CreatedByIdentityID: r.EditorID, CreatedAt: timestamptz(r.Now), ExpiresAt: timestamptz(until)})
	if err != nil {
		return result, err
	}
	if err := tx.Commit(ctx); err != nil {
		return result, err
	}
	return PublisherEnrollment{id, key, s, until}, nil
}

func insertPublisherGrant(ctx context.Context, q *controlstatedb.Queries, publisher, issuer string, s PublisherScope, expires *time.Time, now time.Time) (controlstatedb.ControlPublisherGrant, error) {
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

func insertPublisher(ctx context.Context, q *controlstatedb.Queries, s PublisherScope, name, kind, creator, guest string, public ed25519.PublicKey, expires *time.Time, now time.Time) (PublisherIdentity, error) {
	id, err := opaqueid.New(opaqueid.PublisherIdentityPrefix)
	if err != nil {
		return PublisherIdentity{}, err
	}
	kid, err := opaqueid.New(opaqueid.PublisherIdentityKeyPrefix)
	if err != nil {
		return PublisherIdentity{}, err
	}
	if _, err := q.InsertPublisherIdentity(ctx, controlstatedb.InsertPublisherIdentityParams{ID: id, TeamID: s.TeamID, Name: name, Kind: kind, CreatedByIdentityID: creator, GuestID: nullableText(guest), CreatedAt: timestamptz(now)}); err != nil {
		return PublisherIdentity{}, err
	}
	if err := q.InsertPublisherKey(ctx, controlstatedb.InsertPublisherKeyParams{ID: kid, PublisherIdentityID: id, PublicKey: public, Revision: 1, CreatedAt: timestamptz(now)}); err != nil {
		return PublisherIdentity{}, err
	}
	g, err := insertPublisherGrant(ctx, q, id, creator, s, expires, now)
	if err != nil {
		return PublisherIdentity{}, err
	}
	return PublisherIdentity{ID: id, KeyID: kid, GrantID: g.ID, CreatorID: creator, Kind: kind, GuestID: guest, Scope: s}, nil
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
	if err := validatePublisherScope(ctx, q, s, ""); err != nil {
		return result, publisherLookupError(err, ErrPublisherEnrollment)
	}
	var expires *time.Time
	if e.IdentityKind == "automation" || e.IdentityKind == "run" {
		until := now.Add(time.Hour)
		expires = &until
	}
	result, err = insertPublisher(ctx, q, s, e.Name, e.IdentityKind, e.CreatedByIdentityID, "", public, expires, now)
	if err != nil {
		return result, err
	}
	if err := q.RedeemPublisherEnrollment(ctx, controlstatedb.RedeemPublisherEnrollmentParams{ID: e.ID, IdentityID: text(result.ID), KeyID: text(result.KeyID), GrantID: text(result.GrantID), PublicKey: public, Now: timestamptz(now)}); err != nil {
		return PublisherIdentity{}, err
	}
	return result, tx.Commit(ctx)
}

func validatePublisherScope(ctx context.Context, q *controlstatedb.Queries, s PublisherScope, guest string) error {
	if s.Kind == "private_service" {
		if guest != "" || !opaqueid.Valid(s.PrivateServiceID, opaqueid.PrivateServicePrefix) || s.PublicURLID != "" || s.DomainID != "" || s.Namespace != "" {
			return ErrPublisherIdentity
		}
		service, err := q.LockPrivateService(ctx, s.PrivateServiceID)
		if err != nil {
			return publisherLookupError(err, ErrPublisherIdentity)
		}
		if service.TeamID != s.TeamID || service.DeletedAt.Valid || !service.Enabled {
			return ErrPublisherIdentity
		}
		return nil
	}
	if s.Kind == "saved_url" {
		if s.PrivateServiceID != "" {
			return ErrPublisherIdentity
		}
		u, err := q.LockPublicURLForRun(ctx, s.PublicURLID)
		if err != nil {
			return publisherLookupError(err, ErrPublisherIdentity)
		}
		if u.TeamID != s.TeamID || u.LifecycleState != "enabled" || guest == "" && (u.Ephemeral || !PublicURLPurpose(u.Purpose).ValidForCreation()) {
			return ErrPublisherIdentity
		}
		if guest != "" {
			owned, err := q.GuestOwnsPublicURL(ctx, controlstatedb.GuestOwnsPublicURLParams{GuestID: guest, PublicURLID: u.ID})
			if err != nil || !owned || u.Purpose != "demo" {
				return ErrPublisherIdentity
			}
			return nil
		}
		_, err = q.GetPublisherDomain(ctx, controlstatedb.GetPublisherDomainParams{ID: u.DomainID, TeamID: text(s.TeamID)})
		return err
	}
	if s.Kind != "namespace" || guest != "" || s.PrivateServiceID != "" {
		return ErrPublisherIdentity
	}
	domain, err := q.GetPublisherDomain(ctx, controlstatedb.GetPublisherDomainParams{ID: s.DomainID, TeamID: text(s.TeamID)})
	if err != nil {
		return publisherLookupError(err, ErrPublisherIdentity)
	}
	if s.Namespace != domain.CanonicalDomain && !strings.HasSuffix(s.Namespace, "."+domain.CanonicalDomain) {
		return ErrPublisherIdentity
	}
	return nil
}

// livePublisher locks identity before grant. callers creating runs hold the URL
// lock first; exchange does not lock URLs, avoiding a reversed lock order.
func (d *Database) livePublisher(ctx context.Context, q *controlstatedb.Queries, id, grant, sourceIP string, now time.Time) (PublisherIdentity, controlstatedb.ControlPublisherGrant, error) {
	i, err := q.LockPublisherIdentity(ctx, id)
	if err != nil {
		return PublisherIdentity{}, controlstatedb.ControlPublisherGrant{}, err
	}
	g, err := q.GetPublisherGrant(ctx, controlstatedb.GetPublisherGrantParams{ID: grant, PublisherIdentityID: id})
	if err != nil {
		return PublisherIdentity{}, g, publisherLookupError(err, ErrPublisherIdentity)
	}
	if i.RevokedAt.Valid || g.RevokedAt.Valid || g.ExpiresAt.Valid && !g.ExpiresAt.Time.After(now) {
		return PublisherIdentity{}, g, ErrPublisherIdentity
	}
	result := PublisherIdentity{ID: id, GrantID: grant, CreatorID: i.CreatedByIdentityID, Kind: i.Kind, GuestID: i.GuestID.String, Scope: scopeFromGrant(i.TeamID, g)}
	available, err := q.PublisherScopeAvailable(ctx, controlstatedb.PublisherScopeAvailableParams{PublisherIdentityID: id, GrantID: grant})
	if err != nil {
		return PublisherIdentity{}, g, err
	}
	if !available {
		return PublisherIdentity{}, g, ErrPublisherIdentity
	}
	if i.Kind == "guest" {
		trial, err := q.LockGuestTrialByID(ctx, i.GuestID.String)
		if err != nil {
			return PublisherIdentity{}, g, publisherLookupError(err, ErrPublisherIdentity)
		}
		if trial.TeamID != i.TeamID || g.Kind != "saved_url" || !trial.ExpiresAt.Time.After(now) || trial.EndedAt.Valid || trial.UsedReadyNs >= int64(GuestReadyAllowance) || trial.UsedBytes >= GuestByteAllowance || trial.ActiveReadyAt.Valid && time.Duration(trial.UsedReadyNs)+max(time.Duration(0), now.Sub(trial.ActiveReadyAt.Time)) >= GuestReadyAllowance {
			return PublisherIdentity{}, g, ErrPublisherIdentity
		}
		if sourceIP != "" {
			match, err := d.GuestSourceMatches(GuestTrial{ID: trial.ID, SourceIPDigest: trial.SourceIpDigest.String, SourceIPKeyID: trial.SourceIpKeyID.String}, sourceIP)
			if err != nil {
				return PublisherIdentity{}, g, err
			}
			if !match {
				return PublisherIdentity{}, g, ErrPublisherIdentity
			}
		}
	}
	return result, g, nil
}

func (d *Database) ExchangePublisherAssertion(ctx context.Context, id, grant, audience, assertion, sourceIP string, now time.Time) (result PublisherAccess, retErr error) {
	kid, err := publisheridentity.KeyID(assertion)
	if err != nil {
		return result, ErrPublisherIdentity
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "exchange publisher assertion", &retErr)()
	q := controlstatedb.New(tx)
	identity, g, err := d.livePublisher(ctx, q, id, grant, sourceIP, now)
	if err != nil {
		return result, err
	}
	if identity.GuestID != "" && sourceIP == "" {
		return result, ErrPublisherIdentity
	}
	k, err := q.GetPublisherKey(ctx, controlstatedb.GetPublisherKeyParams{ID: kid, PublisherIdentityID: id})
	if err != nil {
		return result, publisherLookupError(err, ErrPublisherIdentity)
	}
	if k.RetiredAt.Valid {
		return result, ErrPublisherIdentity
	}
	a, err := publisheridentity.Verify(assertion, id, kid, grant, audience, k.PublicKey, now)
	if err != nil {
		return result, ErrPublisherIdentity
	}
	if err := q.PrunePublisherAssertions(ctx, controlstatedb.PrunePublisherAssertionsParams{PublisherIdentityID: id, Now: timestamptz(now)}); err != nil {
		return result, err
	}
	claimed, err := q.ClaimPublisherAssertion(ctx, controlstatedb.ClaimPublisherAssertionParams{PublisherIdentityID: id, AssertionID: a.ID, ExpiresAt: timestamptz(a.Until)})
	if err != nil {
		return result, err
	}
	if claimed != 1 {
		return result, ErrPublisherIdentity
	}
	if err := q.PrunePublisherAccess(ctx, controlstatedb.PrunePublisherAccessParams{PublisherIdentityID: id, Now: timestamptz(now)}); err != nil {
		return result, err
	}
	// the identity lock also bounds active tokens, including rotation assertions.
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM control.publisher_access_tokens WHERE publisher_identity_id=$1`, id).Scan(&count); err != nil {
		return result, err
	}
	if count >= 256 {
		return result, ErrPublisherIdentity
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return result, err
	}
	token := "pta_" + base64.RawURLEncoding.EncodeToString(secret[:])
	digest := sha256.Sum256([]byte(token))
	until := now.Add(PublisherAccessLifetime)
	if g.ExpiresAt.Valid && g.ExpiresAt.Time.Before(until) {
		until = g.ExpiresAt.Time
	}
	identity.KeyID = kid
	if err := q.InsertPublisherAccess(ctx, controlstatedb.InsertPublisherAccessParams{AccessTokenDigest: digest[:], PublisherIdentityID: id, GrantID: grant, KeyID: kid, CreatedAt: timestamptz(now), ExpiresAt: timestamptz(until)}); err != nil {
		return result, err
	}
	return PublisherAccess{identity, token, until}, tx.Commit(ctx)
}

func (d *Database) AuthenticatePublisherAccess(ctx context.Context, token, sourceIP string, now time.Time) (result PublisherIdentity, retErr error) {
	if len(token) != 47 || !strings.HasPrefix(token, "pta_") {
		return result, ErrPublisherIdentity
	}
	digest := sha256.Sum256([]byte(token))
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "authenticate publisher access", &retErr)()
	q := controlstatedb.New(tx)
	a, err := q.GetPublisherAccess(ctx, digest[:])
	if err != nil {
		return result, publisherLookupError(err, ErrPublisherIdentity)
	}
	if !a.ExpiresAt.Time.After(now) {
		return result, ErrPublisherIdentity
	}
	result, _, err = d.livePublisher(ctx, q, a.PublisherIdentityID, a.GrantID, sourceIP, now)
	if err != nil {
		return PublisherIdentity{}, publisherLookupError(err, ErrPublisherIdentity)
	}
	if result.GuestID != "" && sourceIP == "" {
		return PublisherIdentity{}, ErrPublisherIdentity
	}
	result.KeyID = a.KeyID
	return result, nil
}

func (d *Database) RotatePublisherKey(ctx context.Context, token, sourceIP, replacementID, audience string, public ed25519.PublicKey, proof, currentProof string, now time.Time) (retErr error) {
	identity, err := d.AuthenticatePublisherAccess(ctx, token, sourceIP, now)
	if err != nil {
		return err
	}
	if !opaqueid.Valid(replacementID, opaqueid.PublisherIdentityKeyPrefix) {
		return ErrPublisherIdentity
	}
	a, err := publisheridentity.Verify(proof, identity.ID, replacementID, identity.GrantID, audience, public, now)
	if err != nil {
		return ErrPublisherIdentity
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "rotate publisher key", &retErr)()
	q := controlstatedb.New(tx)
	if _, _, err := d.livePublisher(ctx, q, identity.ID, identity.GrantID, sourceIP, now); err != nil {
		return err
	}
	k, err := q.GetPublisherKey(ctx, controlstatedb.GetPublisherKeyParams{ID: identity.KeyID, PublisherIdentityID: identity.ID})
	if err != nil {
		return publisherLookupError(err, ErrPublisherIdentity)
	}
	if k.RetiredAt.Valid {
		return ErrPublisherIdentity
	}
	current, err := publisheridentity.Verify(currentProof, identity.ID, identity.KeyID, identity.GrantID, publisheridentity.RotationAudience(audience, replacementID, public), k.PublicKey, now)
	if err != nil {
		return ErrPublisherIdentity
	}
	if err := q.PrunePublisherAssertions(ctx, controlstatedb.PrunePublisherAssertionsParams{PublisherIdentityID: identity.ID, Now: timestamptz(now)}); err != nil {
		return err
	}
	n, err := q.ClaimPublisherAssertion(ctx, controlstatedb.ClaimPublisherAssertionParams{PublisherIdentityID: identity.ID, AssertionID: a.ID, ExpiresAt: timestamptz(a.Until)})
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrPublisherIdentity
	}
	n, err = q.ClaimPublisherAssertion(ctx, controlstatedb.ClaimPublisherAssertionParams{PublisherIdentityID: identity.ID, AssertionID: current.ID, ExpiresAt: timestamptz(current.Until)})
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrPublisherIdentity
	}
	if _, err := q.RetirePublisherKey(ctx, controlstatedb.RetirePublisherKeyParams{ID: k.ID, Now: timestamptz(now)}); err != nil {
		return err
	}
	if err := q.InsertPublisherKey(ctx, controlstatedb.InsertPublisherKeyParams{ID: replacementID, PublisherIdentityID: identity.ID, PublicKey: public, Revision: k.Revision + 1, CreatedAt: timestamptz(now)}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (d *Database) CreatePublisherGrant(ctx context.Context, r CreatePublisherGrantRequest) (result string, retErr error) {
	if r.ExpiresAt != nil && !r.ExpiresAt.After(r.Now) {
		return "", ErrPublisherIdentity
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer rollback(ctx, tx, "create publisher grant", &retErr)()
	q := controlstatedb.New(tx)
	s, err := d.authorizePublisherScope(ctx, q, r.Scope, r.EditorID, r.EditorMembershipID, r.PolicyRevision)
	if err != nil {
		return "", err
	}
	i, err := q.LockPublisherIdentity(ctx, r.PublisherIdentityID)
	if err != nil {
		return "", publisherLookupError(err, ErrPublisherIdentity)
	}
	if i.TeamID != s.TeamID || i.RevokedAt.Valid || i.Kind == "guest" {
		return "", ErrPublisherIdentity
	}
	if i.CreatedByIdentityID != r.EditorID {
		m, err := q.GetActivePublishRunMembership(ctx, controlstatedb.GetActivePublishRunMembershipParams{TeamID: s.TeamID, IdentityID: r.EditorID})
		if err != nil {
			return "", err
		}
		if m.Role != "admin" && m.Role != "owner" {
			return "", ErrPublisherIdentity
		}
	}
	g, err := insertPublisherGrant(ctx, q, i.ID, r.EditorID, s, r.ExpiresAt, r.Now)
	if err != nil {
		return "", err
	}
	return g.ID, tx.Commit(ctx)
}

func (d *Database) RevokePublisherIdentity(ctx context.Context, team, id, editor string, now time.Time) (retErr error) {
	if !validStateText(editor) {
		return ErrPublisherIdentity
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "revoke publisher identity", &retErr)()
	q := controlstatedb.New(tx)
	if _, err := q.LockLocalTeamForMutation(ctx, team); err != nil {
		return publisherLookupError(err, ErrPublisherIdentity)
	}
	if err := authorizePublisherManagement(ctx, q, team, id, editor); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT private_service_id FROM control.publisher_grants
		WHERE publisher_identity_id=$1 AND kind='private_service' AND private_service_id IS NOT NULL
		ORDER BY private_service_id`, id)
	if err != nil {
		return err
	}
	var privateServices []string
	for rows.Next() {
		var serviceID string
		if err = rows.Scan(&serviceID); err != nil {
			rows.Close()
			return err
		}
		privateServices = append(privateServices, serviceID)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, serviceID := range privateServices {
		if err = closeRevokedPrivatePublication(ctx, tx, q, serviceID, id, "", now); err != nil {
			return err
		}
	}
	n, err := q.RevokePublisherIdentity(ctx, controlstatedb.RevokePublisherIdentityParams{ID: id, TeamID: team, Now: timestamptz(now)})
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrPublisherIdentity
	}
	return tx.Commit(ctx)
}
func (d *Database) RevokePublisherGrant(ctx context.Context, team, id, grant, editor string, now time.Time) (retErr error) {
	if !validStateText(editor) {
		return ErrPublisherIdentity
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "revoke publisher grant", &retErr)()
	q := controlstatedb.New(tx)
	if _, err := q.LockLocalTeamForMutation(ctx, team); err != nil {
		return publisherLookupError(err, ErrPublisherIdentity)
	}
	if err := authorizePublisherManagement(ctx, q, team, id, editor); err != nil {
		return err
	}
	selected, err := q.GetPublisherGrant(ctx, controlstatedb.GetPublisherGrantParams{ID: grant, PublisherIdentityID: id})
	if err != nil {
		return publisherLookupError(err, ErrPublisherIdentity)
	}
	if selected.Kind == "private_service" {
		if err = closeRevokedPrivatePublication(ctx, tx, q, selected.PrivateServiceID.String, id, grant, now); err != nil {
			return err
		}
	}
	n, err := q.RevokePublisherGrant(ctx, controlstatedb.RevokePublisherGrantParams{ID: grant, PublisherIdentityID: id, Now: timestamptz(now)})
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrPublisherIdentity
	}
	return tx.Commit(ctx)
}

func closeRevokedPrivatePublication(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, serviceID, publisherID, grantID string, now time.Time) error {
	if !opaqueid.Valid(serviceID, opaqueid.PrivateServicePrefix) {
		return ErrPublisherIdentity
	}
	service, err := q.LockPrivateService(ctx, serviceID)
	if err != nil {
		return err
	}
	if service.DeletedAt.Valid {
		return nil
	}
	var runID string
	var number int64
	err = tx.QueryRow(ctx, `SELECT id, run_number FROM control.private_service_runs
		WHERE private_service_id=$1 AND publisher_identity_id=$2 AND ($3='' OR publisher_grant_id=$3)
		AND closed_at IS NULL FOR UPDATE`, serviceID, publisherID, grantID).Scan(&runID, &number)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err = q.ClosePrivateServiceRun(ctx, controlstatedb.ClosePrivateServiceRunParams{
		ID: runID, PrivateServiceID: serviceID, RunNumber: number, Now: timestamptz(now),
	}); err != nil {
		return err
	}
	return privateRoutingTombstone(ctx, q, serviceID, now)
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
	if err := validatePublisherScope(ctx, q, s, guestID); err != nil {
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
	result, err = insertPublisher(ctx, q, s, "guest", "guest", u.CreatedByIdentityID, guestID, public, &until, now)
	if err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}
