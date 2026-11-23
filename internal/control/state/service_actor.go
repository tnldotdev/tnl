package state

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

var (
	ErrServiceManagerRequired       = errors.New("current service manager required")
	ErrServiceSourceSignInRequired  = errors.New("current company source sign-in required")
	ErrServiceVerifiedEmailRequired = errors.New("verified email required")
)

// ServiceActorNonce binds only the service-access bridge, including the exact
// escaped request target (and raw query, if present) and the bytes sent.
func ServiceActorNonce(method, target string, body []byte) string {
	bodyHash := sha256.Sum256(body)
	bound := sha256.Sum256([]byte("tnl.service.actor.v1\n" + method + "\n" + target + "\n" + base64.RawURLEncoding.EncodeToString(bodyHash[:])))
	return base64.RawURLEncoding.EncodeToString(bound[:])
}

type serviceActorKey struct{}
type serviceActorProof struct {
	identity OIDCIdentity
	nonce    string
}

// WithServiceActorProof accepts only configured-issuer verification at the
// authority bridge. it grants no control session or public URL authority.
func WithServiceActorProof(ctx context.Context, identity OIDCIdentity, nonce string) context.Context {
	return context.WithValue(ctx, serviceActorKey{}, serviceActorProof{identity, nonce})
}

func serviceActor(ctx context.Context) (serviceActorProof, bool) {
	p, ok := ctx.Value(serviceActorKey{}).(serviceActorProof)
	return p, ok
}

func validateServiceActorProof(p serviceActorProof, now time.Time) error {
	if p.nonce == "" || p.identity.Nonce != p.nonce ||
		!p.identity.AssertionExpiry.After(now) || p.identity.AssertionDigest == ([32]byte{}) ||
		p.identity.IssuedAt.IsZero() || p.identity.IssuedAt.After(now) ||
		p.identity.IssuedAt.Before(now.Add(-5*time.Minute)) ||
		p.identity.AssertionExpiry.After(p.identity.IssuedAt.Add(5*time.Minute)) {
		return ErrControlAuthentication
	}
	if !validStateText(p.identity.AssertionID) || len(p.identity.AssertionID) > 256 {
		return ErrControlAuthentication
	}
	return nil
}

// consumeServiceActor resolves the account again in the operation's transaction;
// an earlier account lookup is not authorization. successful reads consume too.
func consumeServiceActor(ctx context.Context, q *controlstatedb.Queries, actor string, now time.Time) (OIDCIdentity, error) {
	p, ok := serviceActor(ctx)
	if !ok || validateServiceActorProof(p, now) != nil {
		return OIDCIdentity{}, ErrControlAuthentication
	}
	i, err := q.FindOIDCIdentity(ctx, controlstatedb.FindOIDCIdentityParams{Issuer: text(p.identity.Issuer), Subject: text(p.identity.Subject)})
	if err != nil {
		return OIDCIdentity{}, publisherLookupError(err, ErrControlAuthentication)
	}
	if i.ID != actor || i.DisabledAt.Valid {
		return OIDCIdentity{}, ErrControlAuthentication
	}
	if _, err = q.LockVisitorIdentity(ctx, actor); err != nil {
		return OIDCIdentity{}, publisherLookupError(err, ErrControlAuthentication)
	}
	if err = consumeCompanyAssertion(ctx, q, p.identity, now); err != nil {
		return OIDCIdentity{}, err
	}
	// consume the issuer's JTI as well as the exact JWT. re-signing the same
	// assertion ID for another operation must not produce another authorization.
	jti := p.identity
	jti.AssertionDigest = sha256.Sum256([]byte("tnl.service.actor.jti.v1\n" + jti.Issuer + "\n" + jti.AssertionID))
	if err = consumeCompanyAssertion(ctx, q, jti, now); err != nil {
		return OIDCIdentity{}, err
	}
	return p.identity, nil
}

// callers checking several services reuse this fact in the same transaction.
// consuming an assertion again, even after an admin denial, is not a fallback.
func serviceMembershipForActor(ctx context.Context, tx pgx.Tx, team, actor string, now time.Time) (member serviceMembership, err error) {
	clock := newAuthorizationClock(now)
	if _, signed := serviceActor(ctx); signed {
		if _, err = controlstatedb.New(tx).LockLocalTeamForMutation(ctx, team); err != nil {
			return member, publisherLookupError(err, ErrServiceManagerRequired)
		}
	}
	return serviceMembershipUnderTeamGuard(ctx, tx, team, actor, clock)
}

func serviceMembershipUnderTeamGuard(ctx context.Context, tx pgx.Tx, team, actor string, clock authorizationClock) (serviceMembership, error) {
	var identity *OIDCIdentity
	if _, signed := serviceActor(ctx); signed {
		consumed, err := consumeServiceActor(ctx, controlstatedb.New(tx), actor, clock.current())
		if err != nil {
			return serviceMembership{}, err
		}
		identity = &consumed
	}
	return currentServiceMembership(ctx, tx, team, actor, identity, clock.current())
}

// the request already consumed any signed assertion. recheck its deadline and
// current membership after the operation's last possible wait.
func recheckServiceMembership(ctx context.Context, tx pgx.Tx, team, actor string, authorized serviceMembership, clock authorizationClock) error {
	var identity *OIDCIdentity
	if proof, signed := serviceActor(ctx); signed {
		if err := validateServiceActorProof(proof, clock.current()); err != nil {
			return err
		}
		identity = &proof.identity
	}
	current, err := currentServiceMembership(ctx, tx, team, actor, identity, clock.current())
	if err != nil {
		return err
	}
	if current != authorized {
		return ErrServiceAccess
	}
	return nil
}

// currentServiceMembership repeats the defining permission checks without
// consuming a signed assertion again. callers retain the operation's team guard.
func currentServiceMembership(ctx context.Context, tx pgx.Tx, team, actor string, identity *OIDCIdentity, now time.Time) (member serviceMembership, err error) {
	q := controlstatedb.New(tx)
	signed := identity != nil
	denied := ErrServiceAccess
	if signed {
		denied = ErrServiceManagerRequired
	}
	var required, exception, active bool
	query := `SELECT m.id,m.role,t.company_sign_in_required,m.personal_account_exception,control.active_membership(m.id,$3)
		FROM control.teams t JOIN control.team_memberships m ON m.team_id=t.id
		JOIN control.identities person ON person.id=m.identity_id AND person.disabled_at IS NULL
		WHERE t.id=$1 AND m.identity_id=$2 AND t.deleted_at IS NULL
		AND m.removed_at IS NULL AND m.manual_suspended_at IS NULL`
	if signed {
		query += ` FOR SHARE OF t,m`
	}
	err = tx.QueryRow(ctx, query, team, actor, now).Scan(&member.id, &member.role, &required, &exception, &active)
	if err != nil {
		return serviceMembership{}, publisherLookupError(err, denied)
	}
	if !signed {
		if !active {
			return serviceMembership{}, denied
		}
		if err = requireTeamSession(ctx, q, team, actor, now); err != nil {
			if errors.Is(err, ErrAuthorityAccess) {
				err = errors.Join(ErrServiceAccess, err)
			}
			return serviceMembership{}, err
		}
		member.teamID = team
		return member, nil
	}
	if required && !exception {
		valid := false
		for _, c := range identity.TeamContexts {
			if c.TeamID != team {
				continue
			}
			ok, err := verifiedCompanyProof(ctx, q, actor, identity.Issuer, c, now)
			if err != nil {
				return serviceMembership{}, err
			}
			valid = valid || ok
		}
		// unlike company configuration recovery, disconnected or replaced
		// sources never authorize service access management.
		if !active || !valid {
			return serviceMembership{}, ErrServiceSourceSignInRequired
		}
	} else if !active {
		return serviceMembership{}, denied
	}
	member.teamID = team
	return member, nil
}

func serviceReadOptions(ctx context.Context) pgx.TxOptions {
	if _, signed := serviceActor(ctx); signed {
		return pgx.TxOptions{}
	}
	return pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}
}

// beginServiceAccess keeps issuer identity updates ahead of team/admission locks,
// matching company owner proof and OIDC login's identity bootstrap ordering.
func (d *Database) beginServiceAccess(ctx context.Context, options pgx.TxOptions) (pgx.Tx, error) {
	tx, err := d.pool.BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	if _, signed := serviceActor(ctx); signed {
		if err = controlstatedb.New(tx).LockIdentityBootstrap(ctx); err != nil {
			rollback(ctx, tx, "begin service access", &err)()
			return nil, err
		}
	}
	return tx, nil
}

func serviceActorRecipientSource(ctx context.Context, q *controlstatedb.Queries, team, actor string, i OIDCIdentity, now time.Time) error {
	allowed, err := q.CompanySubjectSessionAuthorized(ctx, controlstatedb.CompanySubjectSessionAuthorizedParams{TeamID: team, IdentityID: actor, SessionID: "", Now: timestamptz(now)})
	if err != nil || allowed {
		return err
	}
	active, err := q.ActiveTeamSubject(ctx, controlstatedb.ActiveTeamSubjectParams{TeamID: team, IdentityID: actor, Now: timestamptz(now)})
	if err != nil {
		return err
	}
	if !active {
		return ErrServiceSourceSignInRequired
	}
	for _, c := range i.TeamContexts {
		if c.TeamID != team {
			continue
		}
		valid, err := verifiedCompanyProof(ctx, q, actor, i.Issuer, c, now)
		if err != nil {
			return err
		}
		if valid {
			return nil
		}
	}
	return ErrServiceSourceSignInRequired
}
