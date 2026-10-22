package controlstate

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/oidcauth"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

type CompanyIntentBinding struct {
	ID           string
	BindingToken string
	RedirectURI  string
}

type CompanyLoginIntent struct {
	ID                   string    `json:"intent_id"`
	TeamID               string    `json:"team_id"`
	IdentityConnectionID string    `json:"identity_connection_id"`
	ConnectionRevision   int64     `json:"connection_revision"`
	SourceID             string    `json:"source_id"`
	Issuer               string    `json:"issuer"`
	ClientID             string    `json:"client_id"`
	RedirectURI          string    `json:"redirect_uri"`
	Nonce                string    `json:"nonce"`
	BindingToken         string    `json:"binding_token,omitempty"`
	ExpiresAt            time.Time `json:"expires_at"`
}

func companyRandom() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// CompanyActorNonce binds a verified standard OIDC nonce to one exact HTTP
// operation. the body digest is of the bytes sent, not reserialized JSON.
func CompanyActorNonce(method, path string, body []byte) string {
	bodyHash := sha256.Sum256(body)
	bound := sha256.Sum256([]byte("tnl.company.actor.v1\n" + method + "\n" + path + "\n" + base64.RawURLEncoding.EncodeToString(bodyHash[:])))
	return base64.RawURLEncoding.EncodeToString(bound[:])
}

type companyActorKey struct{}
type companyActorProof struct {
	identity OIDCIdentity
	nonce    string
}

// WithCompanyActorProof accepts only the result of the configured OIDC verifier.
// mutations consume the assertion and recheck current ownership in their own tx.
func WithCompanyActorProof(ctx context.Context, identity OIDCIdentity, expectedNonce string) context.Context {
	return context.WithValue(ctx, companyActorKey{}, companyActorProof{identity, expectedNonce})
}

func lockCompanyOwner(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, p ControlPrincipal, team string, now time.Time) (controlstatedb.LockTeamActorContextRow, string, error) {
	proof, website := ctx.Value(companyActorKey{}).(companyActorProof)
	if !website {
		a, err := lockTeamActor(ctx, q, p.IdentityID, team)
		if err != nil {
			return a, "", err
		}
		if a.Kind != "organization" || a.ActorRole != "owner" {
			return a, "", ErrAuthorityAccess
		}
		return a, p.IdentityID, nil
	}
	if proof.nonce == "" || proof.identity.Nonce != proof.nonce || !proof.identity.AssertionExpiry.After(now) || proof.identity.AssertionDigest == ([32]byte{}) {
		return controlstatedb.LockTeamActorContextRow{}, "", ErrControlAuthentication
	}
	if proof.identity.IssuedAt.IsZero() || proof.identity.IssuedAt.After(now) || proof.identity.IssuedAt.Before(now.Add(-5*time.Minute)) || proof.identity.AssertionExpiry.After(proof.identity.IssuedAt.Add(5*time.Minute)) {
		return controlstatedb.LockTeamActorContextRow{}, "", ErrControlAuthentication
	}
	if err := q.LockIdentityBootstrap(ctx); err != nil {
		return controlstatedb.LockTeamActorContextRow{}, "", err
	}
	if _, err := q.LockLocalTeamForMutation(ctx, team); err != nil {
		return controlstatedb.LockTeamActorContextRow{}, "", publisherLookupError(err, ErrAuthorityAccess)
	}
	i, err := q.FindOIDCIdentity(ctx, controlstatedb.FindOIDCIdentityParams{Issuer: text(proof.identity.Issuer), Subject: text(proof.identity.Subject)})
	if err != nil {
		return controlstatedb.LockTeamActorContextRow{}, "", publisherLookupError(err, ErrAuthorityAccess)
	}
	var a controlstatedb.LockTeamActorContextRow
	var required, exception bool
	err = tx.QueryRow(ctx, `SELECT t.id,t.kind,t.policy_revision,m.id,m.role,t.company_sign_in_required,m.personal_account_exception FROM control.teams t JOIN control.team_memberships m ON m.team_id=t.id JOIN control.identities i ON i.id=m.identity_id WHERE t.id=$1 AND i.id=$2 AND i.disabled_at IS NULL AND t.deleted_at IS NULL AND m.removed_at IS NULL AND m.manual_suspended_at IS NULL AND m.role='owner' AND t.kind='organization' FOR UPDATE OF t,m`, team, i.ID).Scan(&a.ID, &a.Kind, &a.PolicyRevision, &a.ActorMembershipID, &a.ActorRole, &required, &exception)
	if err != nil {
		return a, "", publisherLookupError(err, ErrAuthorityAccess)
	}
	if required && !exception {
		_, currentErr := q.GetCurrentIdentityConnection(ctx, team)
		if currentErr != nil && !errors.Is(currentErr, pgx.ErrNoRows) {
			return a, "", currentErr
		}
		// a disconnected source cannot authenticate anyone. a fresh, scoped
		// owner proof can read/reconfigure its settings without granting visits
		// or publishing authority to any suspended member.
		if currentErr == nil {
			active, e := q.ActiveCompanyMembership(ctx, controlstatedb.ActiveCompanyMembershipParams{MembershipID: a.ActorMembershipID, Now: timestamptz(now)})
			if e != nil {
				return a, "", e
			}
			if !active {
				return a, "", ErrAuthorityAccess
			}
			valid := false
			for _, c := range proof.identity.TeamContexts {
				if c.TeamID == team {
					ok, e := verifiedCompanyProof(ctx, q, i.ID, proof.identity.Issuer, c, now)
					if e != nil {
						return a, "", e
					}
					valid = valid || ok
				}
			}
			if !valid {
				return a, "", ErrAuthorityAccess
			}
		}
	}
	if err = consumeCompanyAssertion(ctx, q, proof.identity, now); err != nil {
		return a, "", err
	}
	return a, i.ID, nil
}

func consumeCompanyAssertion(ctx context.Context, q *controlstatedb.Queries, identity OIDCIdentity, now time.Time) error {
	if !identity.AssertionExpiry.After(now) || identity.AssertionDigest == ([32]byte{}) {
		return ErrControlAuthentication
	}
	if err := q.DeleteExpiredOIDCAssertionExchanges(ctx, timestamptz(now)); err != nil {
		return err
	}
	n, err := q.ConsumeOIDCAssertion(ctx, controlstatedb.ConsumeOIDCAssertionParams{AssertionDigest: identity.AssertionDigest[:], ConsumedAt: timestamptz(now), ExpiresAt: timestamptz(identity.AssertionExpiry)})
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrOIDCAssertionReplay
	}
	return nil
}

func validCompanyAuthentication(c oidcauth.TeamContext, now time.Time) bool {
	at := time.Unix(c.AuthenticatedAt, 0)
	return validStateText(c.TeamID) && validStateText(c.IdentityConnectionID) && validStateText(c.Subject) && len(c.Subject) <= 256 && validStateText(c.SourceID) && len(c.SourceID) <= 256 && c.ConnectionRevision > 0 && !at.After(now) && at.Add(CompanyAuthenticationLifetime).After(now)
}

func verifiedCompanyProof(ctx context.Context, q *controlstatedb.Queries, identity, issuer string, c oidcauth.TeamContext, now time.Time) (bool, error) {
	if !validCompanyAuthentication(c, now) {
		return false, nil
	}
	return q.ValidateVerifiedCompanyProof(ctx, controlstatedb.ValidateVerifiedCompanyProofParams{ConnectionID: c.IdentityConnectionID, TeamID: c.TeamID, Issuer: issuer, SourceID: c.SourceID, ConnectionRevision: c.ConnectionRevision, IdentityID: identity, Subject: c.Subject, Now: timestamptz(now)})
}

// storeVerifiedCompanyContexts is the sole company session creation boundary.
// ID-token expiry gates exchange, not the lifetime of the derived control proof.
// refresh retains the original authentication deadline and never slides it.
func storeVerifiedCompanyContexts(ctx context.Context, q *controlstatedb.Queries, session, identity string, verified OIDCIdentity, refreshExpiry, now time.Time) error {
	if len(verified.TeamContexts) == 0 {
		if verified.CompanyIntent != nil {
			return ErrControlAuthentication
		}
		return nil
	}
	if len(verified.TeamContexts) != 1 || verified.CompanyIntent == nil {
		return ErrControlAuthentication
	}
	intent, err := q.LockCompanyLoginIntent(ctx, verified.CompanyIntent.ID)
	if err != nil {
		return publisherLookupError(err, ErrControlAuthentication)
	}
	digest := sha256.Sum256([]byte(verified.CompanyIntent.BindingToken))
	if intent.ConsumedAt.Valid || !intent.ExpiresAt.Time.After(now) || subtle.ConstantTimeCompare(digest[:], intent.BindingDigest) != 1 || verified.Nonce != intent.Nonce || verified.Issuer != intent.Issuer || verified.ClientID != intent.ClientID || verified.CompanyIntent.RedirectURI != intent.RedirectUri {
		return ErrControlAuthentication
	}
	matched := false
	seen := make(map[string]bool)
	for _, proof := range verified.TeamContexts {
		if proof.TeamID != intent.TeamID || proof.IdentityConnectionID != intent.IdentityConnectionID || proof.ConnectionRevision != intent.ConnectionRevision {
			return ErrControlAuthentication
		}
		if seen[proof.TeamID] {
			return ErrControlAuthentication
		}
		seen[proof.TeamID] = true
		if _, err := q.LockLocalTeamForSession(ctx, proof.TeamID); err != nil {
			return publisherLookupError(err, ErrControlAuthentication)
		}
		allowed, err := verifiedCompanyProof(ctx, q, identity, verified.Issuer, proof, now)
		if err != nil {
			return err
		}
		if !allowed {
			return ErrControlAuthentication
		}
		if proof.TeamID == intent.TeamID && proof.IdentityConnectionID == intent.IdentityConnectionID && proof.ConnectionRevision == intent.ConnectionRevision {
			matched = true
		}
		until := minTime(refreshExpiry, time.Unix(proof.AuthenticatedAt, 0).Add(CompanyAuthenticationLifetime))
		if err = q.InsertCompanySessionContext(ctx, controlstatedb.InsertCompanySessionContextParams{SessionID: session, TeamID: proof.TeamID, ConnectionID: proof.IdentityConnectionID, ConnectionRevision: proof.ConnectionRevision, Subject: proof.Subject, AuthenticatedAt: timestamptz(time.Unix(proof.AuthenticatedAt, 0)), ExpiresAt: timestamptz(until)}); err != nil {
			return err
		}
	}
	if !matched {
		return ErrControlAuthentication
	}
	n, err := q.ConsumeCompanyLoginIntent(ctx, controlstatedb.ConsumeCompanyLoginIntentParams{ID: intent.ID, Now: timestamptz(now)})
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrControlAuthentication
	}
	return nil
}

func (d *Database) CreateCompanyLoginIntent(ctx context.Context, team, issuer, client, redirect string, now time.Time) (result CompanyLoginIntent, retErr error) {
	if !validStateText(team) || len(team) > 128 || now.IsZero() || !validStateText(client) || !validStateText(redirect) || !validStateText(issuer) {
		return result, ErrAuthorityInvalid
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "create company login intent", &retErr)()
	q := controlstatedb.New(tx)
	if _, err = q.LockLocalTeamForSession(ctx, team); err != nil {
		return result, publisherLookupError(err, ErrAuthorityAccess)
	}
	c, err := q.GetCurrentIdentityConnection(ctx, team)
	if err != nil {
		return result, publisherLookupError(err, ErrAuthorityAccess)
	}
	if c.State != "active" || c.Issuer != issuer {
		return result, ErrAuthorityAccess
	}
	id, err := opaqueid.New("cai_")
	if err != nil {
		return result, err
	}
	nonce, err := companyRandom()
	if err != nil {
		return result, err
	}
	binding, err := companyRandom()
	if err != nil {
		return result, err
	}
	digest := sha256.Sum256([]byte(binding))
	until := now.Add(10 * time.Minute)
	if _, err = tx.Exec(ctx, `DELETE FROM control.company_login_intents WHERE expires_at<=$1`, now); err != nil {
		return result, err
	}
	var count int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM control.company_login_intents`).Scan(&count); err != nil {
		return result, err
	}
	if count >= 10000 {
		return result, ErrAuthorityConflict
	}
	_, err = tx.Exec(ctx, `INSERT INTO control.company_login_intents(id,team_id,identity_connection_id,connection_revision,issuer,client_id,redirect_uri,nonce,binding_digest,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, id, team, c.ID, c.Revision, issuer, client, redirect, nonce, digest[:], now, until)
	if err != nil {
		return result, err
	}
	result = CompanyLoginIntent{ID: id, TeamID: team, IdentityConnectionID: c.ID, ConnectionRevision: c.Revision, SourceID: c.SourceID, Issuer: issuer, ClientID: client, RedirectURI: redirect, Nonce: nonce, BindingToken: binding, ExpiresAt: until}
	return result, tx.Commit(ctx)
}

func (d *Database) ResolveCompanyLoginIntent(ctx context.Context, id, binding string, now time.Time) (result CompanyLoginIntent, retErr error) {
	if !opaqueid.Valid(id, "cai_") || len(binding) != 43 || now.IsZero() {
		return result, ErrControlAuthentication
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "resolve company login intent", &retErr)()
	q := controlstatedb.New(tx)
	i, err := q.LockCompanyLoginIntent(ctx, id)
	if err != nil {
		return result, publisherLookupError(err, ErrControlAuthentication)
	}
	digest := sha256.Sum256([]byte(binding))
	if i.ConsumedAt.Valid || !i.ExpiresAt.Time.After(now) || subtle.ConstantTimeCompare(digest[:], i.BindingDigest) != 1 {
		return result, ErrControlAuthentication
	}
	c, err := q.GetCurrentIdentityConnection(ctx, i.TeamID)
	if err != nil {
		return result, publisherLookupError(err, ErrControlAuthentication)
	}
	if c.ID != i.IdentityConnectionID || c.Revision != i.ConnectionRevision || c.State != "active" {
		return result, ErrControlAuthentication
	}
	result = CompanyLoginIntent{ID: i.ID, TeamID: i.TeamID, IdentityConnectionID: c.ID, ConnectionRevision: c.Revision, SourceID: c.SourceID, Issuer: i.Issuer, ClientID: i.ClientID, RedirectURI: i.RedirectUri, Nonce: i.Nonce, ExpiresAt: i.ExpiresAt.Time}
	return result, tx.Commit(ctx)
}

func (d *Database) ResolveCompanyAccount(ctx context.Context, issuer, subject string) (string, error) {
	if !validStateText(issuer) || !validStateText(subject) || len(subject) > 256 {
		return "", ErrAuthorityInvalid
	}
	i, err := controlstatedb.New(d.pool).FindOIDCIdentity(ctx, controlstatedb.FindOIDCIdentityParams{Issuer: text(issuer), Subject: text(subject)})
	if err != nil {
		return "", publisherLookupError(err, ErrControlIdentity)
	}
	if i.DisabledAt.Valid {
		return "", ErrAuthorityAccess
	}
	return i.ID, nil
}
