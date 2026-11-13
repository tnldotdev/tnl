package state

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
)

// livePublisher locks identity before grant. callers creating runs hold the URL
// lock first; exchange does not lock URLs, avoiding a reversed lock order.
func (d *Database) livePublisher(ctx context.Context, q *controlstatedb.Queries, id, grant, sourceIP string, now time.Time) (PublisherIdentity, controlstatedb.ControlPublisherGrant, error) {
	clock := newAuthorizationClock(now)
	i, err := q.LockPublisherIdentity(ctx, id)
	if err != nil {
		return PublisherIdentity{}, controlstatedb.ControlPublisherGrant{}, err
	}
	g, err := q.GetPublisherGrant(ctx, controlstatedb.GetPublisherGrantParams{ID: grant, PublisherIdentityID: id})
	if err != nil {
		return PublisherIdentity{}, g, publisherLookupError(err, ErrPublisherIdentity)
	}
	identity, err := d.currentPublisher(ctx, q, i, g, sourceIP, clock.current())
	return identity, g, err
}

// snapshot checks share the same validation without taking an identity lock ahead
// of publication parents. management callers hold the team guard, then repeat
// the locked check after their resource work and before committing.
func (d *Database) currentPublisher(ctx context.Context, q *controlstatedb.Queries, i controlstatedb.ControlPublisherIdentity, g controlstatedb.ControlPublisherGrant, sourceIP string, now time.Time) (PublisherIdentity, error) {
	if i.RevokedAt.Valid || g.RevokedAt.Valid || g.ExpiresAt.Valid && !g.ExpiresAt.Time.After(now) {
		return PublisherIdentity{}, ErrPublisherIdentity
	}
	if i.Ownership == "member" {
		active, err := q.ActiveCompanyMembership(ctx, controlstatedb.ActiveCompanyMembershipParams{MembershipID: i.OwnerMembershipID.String, Now: timestamptz(now)})
		if err != nil {
			return PublisherIdentity{}, err
		}
		if !active {
			return PublisherIdentity{}, ErrPublisherIdentity
		}
	}
	result := PublisherIdentity{ID: i.ID, GrantID: g.ID, CreatorID: i.CreatedByIdentityID, Kind: i.Kind, GuestID: i.GuestID.String, Scope: scopeFromGrant(i.TeamID, g), Ownership: i.Ownership, OwnerMembershipID: i.OwnerMembershipID.String}
	available, err := q.PublisherScopeAvailable(ctx, controlstatedb.PublisherScopeAvailableParams{PublisherIdentityID: i.ID, GrantID: g.ID})
	if err != nil {
		return PublisherIdentity{}, err
	}
	if !available {
		return PublisherIdentity{}, ErrPublisherIdentity
	}
	if i.Kind == "guest" {
		trial, err := q.LockGuestTrialByID(ctx, i.GuestID.String)
		if err != nil {
			return PublisherIdentity{}, publisherLookupError(err, ErrPublisherIdentity)
		}
		if trial.TeamID != i.TeamID || g.Kind != "saved_public_url" || !trial.ExpiresAt.Time.After(now) || trial.EndedAt.Valid || trial.UsedReadyNs >= int64(GuestReadyAllowance) || trial.ActiveReadyAt.Valid && time.Duration(trial.UsedReadyNs)+max(time.Duration(0), now.Sub(trial.ActiveReadyAt.Time)) >= GuestReadyAllowance {
			return PublisherIdentity{}, ErrPublisherIdentity
		}
		if sourceIP != "" {
			match, err := d.GuestSourceMatches(GuestTrial{ID: trial.ID, SourceIPDigest: trial.SourceIpDigest.String, SourceIPKeyID: trial.SourceIpKeyID.String}, sourceIP)
			if err != nil {
				return PublisherIdentity{}, err
			}
			if !match {
				return PublisherIdentity{}, ErrPublisherIdentity
			}
		}
	}
	return result, nil
}

func (d *Database) ExchangePublisherAssertion(ctx context.Context, id, grant, audience, assertion, sourceIP string, now time.Time) (result PublisherAccess, retErr error) {
	clock := newAuthorizationClock(now)
	kid, err := publisherproof.KeyID(assertion)
	if err != nil {
		return result, ErrPublisherIdentity
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "exchange publisher assertion", &retErr)()
	q := controlstatedb.New(tx)
	identity, g, err := d.livePublisher(ctx, q, id, grant, sourceIP, clock.current())
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
	a, err := publisherproof.Verify(assertion, id, kid, grant, audience, k.PublicKey, clock.current())
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
	if !until.After(clock.current()) || !a.Until.After(clock.current()) {
		return result, ErrPublisherIdentity
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
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "authenticate publisher access", &retErr)()
	q := controlstatedb.New(tx)
	return d.authenticatePublisherAccess(ctx, q, token, sourceIP, now, true)
}

func (d *Database) authenticatePublisherAccess(ctx context.Context, q *controlstatedb.Queries, token, sourceIP string, now time.Time, lock bool) (result PublisherIdentity, err error) {
	clock := newAuthorizationClock(now)
	if len(token) != 47 || !strings.HasPrefix(token, "pta_") {
		return result, ErrPublisherIdentity
	}
	digest := sha256.Sum256([]byte(token))
	a, err := q.GetPublisherAccess(ctx, digest[:])
	if err != nil {
		return result, publisherLookupError(err, ErrPublisherIdentity)
	}
	if !a.ExpiresAt.Time.After(now) {
		return result, ErrPublisherIdentity
	}
	if lock {
		result, _, err = d.livePublisher(ctx, q, a.PublisherIdentityID, a.GrantID, sourceIP, clock.current())
	} else {
		var identity controlstatedb.ControlPublisherIdentity
		var grant controlstatedb.ControlPublisherGrant
		identity, err = q.ReadPublisherIdentity(ctx, a.PublisherIdentityID)
		if err == nil {
			grant, err = q.ReadPublisherGrant(ctx, controlstatedb.ReadPublisherGrantParams{ID: a.GrantID, PublisherIdentityID: a.PublisherIdentityID})
		}
		if err == nil {
			result, err = d.currentPublisher(ctx, q, identity, grant, sourceIP, clock.current())
		}
	}
	if err != nil {
		return PublisherIdentity{}, publisherLookupError(err, ErrPublisherIdentity)
	}
	if result.GuestID != "" && sourceIP == "" {
		return PublisherIdentity{}, ErrPublisherIdentity
	}
	if !a.ExpiresAt.Time.After(clock.current()) {
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
	a, err := publisherproof.Verify(proof, identity.ID, replacementID, identity.GrantID, audience, public, now)
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
	current, err := publisherproof.Verify(currentProof, identity.ID, identity.KeyID, identity.GrantID, publisherproof.RotationAudience(audience, replacementID, public), k.PublicKey, now)
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
