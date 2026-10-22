package controlstate

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/oidcauth"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

type configuredAdmission struct {
	issuer, connection string
	rule               oidcauth.AdmissionRule
}

// ConfigureOIDCAdmissions runs once before serving. an existing/retired source
// is never replaced by configuration reconciliation; replacement is an explicit
// owner operation, and the new source's eligibility stays independently scoped.
func (d *Database) ConfigureOIDCAdmissions(ctx context.Context, issuer string, rules []oidcauth.AdmissionRule, now time.Time) (retErr error) {
	if len(rules) == 0 {
		return nil
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "configure OIDC admissions", &retErr)()
	q := controlstatedb.New(tx)
	if err := q.LockIdentityBootstrap(ctx); err != nil {
		return err
	}
	configured := map[string]configuredAdmission{}
	for _, rule := range rules {
		if !naming.ValidAuthorityLabel(rule.Team) {
			return ErrAuthorityInvalid
		}
		team, err := q.FindSeedTeam(ctx, rule.Team)
		if err != nil {
			return err
		}
		key, _ := json.Marshal([]string{"oidc-admission", issuer, team.ID, rule.SourceID})
		inserted, err := q.ConsumeAuthenticationSeed(ctx, controlstatedb.ConsumeAuthenticationSeedParams{SeedKey: string(key), AppliedAt: timestamptz(now)})
		if err != nil {
			return err
		}
		var id string
		err = tx.QueryRow(ctx, `SELECT id FROM control.identity_connections WHERE team_id=$1 AND issuer=$2 AND source_id=$3 ORDER BY created_at DESC LIMIT 1`, team.ID, issuer, rule.SourceID).Scan(&id)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if id == "" && inserted == 1 {
			id, err = opaqueid.New("icn_")
			if err != nil {
				return err
			}
			secret, err := companyRandom()
			if err != nil {
				return err
			}
			digest := sha256.Sum256([]byte(secret))
			_, err = tx.Exec(ctx, `INSERT INTO control.identity_connections(id,team_id,issuer,source_id,admission,state,revision,provisioning_digest,setup_digest,setup_expires_at,activated_at,created_by_identity_id,created_at,updated_at) VALUES($1,$2,$3,$4,'managed','active',1,$5,$5,$6,$6,$7,$6,$6)`, id, team.ID, issuer, rule.SourceID, digest[:], now, team.CreatedByIdentityID)
			if err != nil {
				return err
			}
			if _, err = tx.Exec(ctx, `UPDATE control.teams SET company_sign_in_required=true,policy_revision=policy_revision+1 WHERE id=$1`, team.ID); err != nil {
				return err
			}
		}
		if id != "" {
			configured[team.ID] = configuredAdmission{issuer: issuer, connection: id, rule: rule}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	d.oidcAdmissions = configured
	return nil
}

// mapDirectOIDCAdmission runs inside the session transaction. only server-owned
// rules and signed standard claims can produce a direct-provider team context.
func (d *Database) mapDirectOIDCAdmission(ctx context.Context, q *controlstatedb.Queries, identityID string, i *OIDCIdentity, now time.Time) error {
	if i.CompanyIntent == nil {
		return nil
	}
	intent, err := q.LockCompanyLoginIntent(ctx, i.CompanyIntent.ID)
	if err != nil {
		return err
	}
	a, configured := d.oidcAdmissions[intent.TeamID]
	if !configured {
		return nil
	}
	if a.issuer != i.Issuer || a.connection != intent.IdentityConnectionID || len(i.TeamContexts) != 0 || !a.rule.Allows(oidcauth.Identity{Subject: i.Subject, TenantID: i.TenantID, HostedDomain: i.HostedDomain, Groups: i.Groups}) {
		return ErrControlAuthentication
	}
	if i.AuthenticatedAt.IsZero() || i.AuthenticatedAt.Unix() <= 0 || i.AuthenticatedAt.After(now.Add(time.Minute)) || !i.AuthenticatedAt.Add(CompanyAuthenticationLifetime).After(now) {
		return ErrControlAuthentication
	}
	c, err := q.GetCurrentIdentityConnection(ctx, intent.TeamID)
	if err != nil {
		return err
	}
	if c.ID != a.connection || c.Revision != intent.ConnectionRevision || identityConnectionState(c.State) != identityConnectionActive {
		return ErrControlAuthentication
	}
	// only first-ever membership admission is automatic. tombstones, suspension,
	// roles, and bindings to another source are never overwritten.
	history, err := q.HasTeamMembershipHistory(ctx, controlstatedb.HasTeamMembershipHistoryParams{TeamID: intent.TeamID, IdentityID: identityID})
	if err != nil {
		return err
	}
	if !history {
		membership, err := opaqueid.New(opaqueid.MembershipPrefix)
		if err != nil {
			return err
		}
		reservation, err := opaqueid.New(opaqueid.SlugReservationPrefix)
		if err != nil {
			return err
		}
		label, err := availableManagedLabel(ctx, q, now)
		if err != nil {
			return err
		}
		if err := q.CreateActiveSlugReservation(ctx, controlstatedb.CreateActiveSlugReservationParams{ID: reservation, TeamID: intent.TeamID, MemberSlug: label, IdentityID: text(identityID), CreatedAt: timestamptz(now)}); err != nil {
			return err
		}
		if err := q.CreateSeedMember(ctx, controlstatedb.CreateSeedMemberParams{ID: membership, TeamID: intent.TeamID, IdentityID: identityID, SlugReservationID: reservation, ManagedLabel: label, CreatedAt: timestamptz(now)}); err != nil {
			return err
		}
	}
	key, _ := json.Marshal([]string{"oidc-member-binding", intent.TeamID, identityID})
	first, err := q.ConsumeAuthenticationSeed(ctx, controlstatedb.ConsumeAuthenticationSeedParams{SeedKey: string(key), AppliedAt: timestamptz(now)})
	if err != nil {
		return err
	}
	if first == 1 {
		if err := q.BindInitialOIDCMembership(ctx, controlstatedb.BindInitialOIDCMembershipParams{TeamID: intent.TeamID, IdentityID: identityID, ConnectionID: text(c.ID)}); err != nil {
			return err
		}
	}
	previous, err := q.GetCompanyEligibility(ctx, controlstatedb.GetCompanyEligibilityParams{IdentityConnectionID: c.ID, IdentityID: identityID})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if err == nil && previous.Subject != i.Subject {
		return ErrControlAuthentication
	}
	digest := sha256.Sum256([]byte(i.Issuer + "\x00" + i.Subject))
	if err := q.PutCompanyEligibility(ctx, controlstatedb.PutCompanyEligibilityParams{IdentityConnectionID: c.ID, TeamID: intent.TeamID, IdentityID: identityID, Subject: i.Subject, ConnectionRevision: c.Revision, Revision: previous.Revision + 1, Eligible: true, ValidUntil: timestamptz(i.AuthenticatedAt.Add(CompanyAuthenticationLifetime)), RequestDigest: digest[:], Now: timestamptz(now)}); err != nil {
		return err
	}
	i.TeamContexts = []oidcauth.TeamContext{{TeamID: intent.TeamID, IdentityConnectionID: c.ID, ConnectionRevision: c.Revision, SourceID: c.SourceID, Subject: i.Subject, AuthenticatedAt: i.AuthenticatedAt.Unix()}}
	return nil
}
