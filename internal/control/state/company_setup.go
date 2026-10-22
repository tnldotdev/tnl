package state

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

type CompanyConnections struct {
	Active *IdentityConnection `json:"active,omitempty"`
	Setup  *IdentityConnection `json:"setup,omitempty"`
}

func (d *Database) ReadCompanyConnections(ctx context.Context, p ControlPrincipal, team string, now time.Time) (result CompanyConnections, retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "read company connections", &retErr)()
	q := controlstatedb.New(tx)
	if _, _, err = lockCompanyOwner(ctx, tx, q, p, team, now); err != nil {
		return result, err
	}
	rows, err := tx.Query(ctx, `SELECT id FROM control.identity_connections WHERE team_id=$1 AND (state='active' OR state='pending' AND setup_expires_at>$2) ORDER BY id`, team, now)
	if err != nil {
		return result, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return result, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, err
	}
	for _, id := range ids {
		c, err := q.LockIdentityConnection(ctx, controlstatedb.LockIdentityConnectionParams{TeamID: team, ID: id})
		if err != nil {
			return result, err
		}
		view := connectionFromRow(c)
		if c.State == "pending" {
			result.Setup = &view
		} else {
			result.Active = &view
		}
	}
	return result, tx.Commit(ctx)
}

func (d *Database) ActivateIdentityConnection(ctx context.Context, p ControlPrincipal, team, id, setupToken string, revision int64, source OIDCIdentity, now time.Time, provisioningToken string) (result IdentityConnectionSecret, retErr error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(provisioningToken)
	if err != nil || len(raw) != 32 {
		return result, ErrAuthorityInvalid
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "activate company connection", &retErr)()
	q := controlstatedb.New(tx)
	if err = q.LockIdentityBootstrap(ctx); err != nil {
		return result, err
	}
	a, owner, err := lockCompanyOwner(ctx, tx, q, p, team, now)
	if err != nil {
		return result, err
	}
	if actor, ok := ctx.Value(companyActorKey{}).(companyActorProof); ok {
		source = actor.identity
	} else {
		if err = consumeCompanyAssertion(ctx, q, source, now); err != nil {
			return result, err
		}
	}
	c, err := q.LockIdentityConnection(ctx, controlstatedb.LockIdentityConnectionParams{TeamID: team, ID: id})
	if err != nil {
		return result, publisherLookupError(err, ErrAuthorityAccess)
	}
	digest := sha256.Sum256([]byte(setupToken))
	if c.State == "active" && c.Revision == revision+1 && c.CreatedByIdentityID == owner && source.Issuer == c.Issuer && setupToken != "" && subtle.ConstantTimeCompare(digest[:], c.SetupDigest) == 1 {
		actual := sha256.Sum256([]byte(provisioningToken))
		if subtle.ConstantTimeCompare(actual[:], c.ProvisioningDigest) != 1 {
			return result, ErrAuthorityConflict
		}
		verified := false
		for _, proof := range source.TeamContexts {
			if proof.TeamID == team && proof.IdentityConnectionID == id {
				ok, e := verifiedCompanyProof(ctx, q, owner, source.Issuer, proof, now)
				if e != nil {
					return result, e
				}
				verified = verified || ok
			}
		}
		if !verified {
			return result, ErrAuthorityAccess
		}
		return IdentityConnectionSecret{IdentityConnection: connectionFromRow(c), ProvisioningToken: provisioningToken}, tx.Commit(ctx)
	}
	if c.State != "pending" || c.Revision != revision || !c.SetupExpiresAt.Time.After(now) || c.CreatedByIdentityID != owner || setupToken == "" || subtle.ConstantTimeCompare(digest[:], c.SetupDigest) != 1 || source.Issuer != c.Issuer {
		return result, ErrAuthorityConflict
	}
	i, err := q.FindOIDCIdentity(ctx, controlstatedb.FindOIDCIdentityParams{Issuer: text(source.Issuer), Subject: text(source.Subject)})
	if err != nil || i.ID != owner {
		return result, ErrAuthorityAccess
	}
	var ownerException bool
	var ownerSource pgtype.Text
	if err = tx.QueryRow(ctx, `SELECT personal_account_exception,identity_connection_id FROM control.team_memberships WHERE id=$1`, a.ActorMembershipID).Scan(&ownerException, &ownerSource); err != nil {
		return result, err
	}
	verified := false
	for _, proof := range source.TeamContexts {
		if proof.TeamID == team && proof.IdentityConnectionID == id && proof.ConnectionRevision == revision && proof.SourceID == c.SourceID && validCompanyAuthentication(proof, now) {
			e, eErr := q.GetCompanyEligibility(ctx, controlstatedb.GetCompanyEligibilityParams{IdentityConnectionID: id, IdentityID: owner})
			if eErr != nil {
				return result, publisherLookupError(eErr, ErrAuthorityAccess)
			}
			verified = e.Subject == proof.Subject && (e.Eligible || ownerException) && e.ConnectionRevision == revision && e.ValidUntil.Time.After(now)
		}
	}
	if !verified {
		return result, ErrAuthorityAccess
	}
	old, err := q.GetCurrentIdentityConnection(ctx, team)
	if c.ReplacesID.Valid {
		if err != nil || old.ID != c.ReplacesID.String || old.Revision != c.ReplacesRevision.Int64 {
			return result, ErrAuthorityConflict
		}
		if _, err = tx.Exec(ctx, `UPDATE control.identity_connections SET state='retired',revision=revision+1,updated_at=$2 WHERE id=$1`, old.ID, now); err != nil {
			return result, err
		}
	} else if err == nil {
		return result, ErrAuthorityConflict
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}
	hash := sha256.Sum256([]byte(provisioningToken))
	if _, err = tx.Exec(ctx, `UPDATE control.identity_connections SET state='active',revision=revision+1,activated_at=$2,updated_at=$2,provisioning_digest=$3 WHERE id=$1`, id, now, hash[:]); err != nil {
		return result, err
	}
	if _, err = tx.Exec(ctx, `UPDATE control.company_eligibility SET connection_revision=$2 WHERE identity_connection_id=$1 AND connection_revision=$3`, id, revision+1, revision); err != nil {
		return result, err
	}
	if _, err = tx.Exec(ctx, `UPDATE control.teams SET company_sign_in_required=true WHERE id=$1`, team); err != nil {
		return result, err
	}
	details := companyAccessAuditDetails{ConnectionRevision: revision + 1, State: "active", Admission: c.Admission, ReplacedID: c.ReplacesID.String}
	bootstrapIdentity := ""
	if ownerSource.Valid {
		// the consenting current owner explicitly authorizes this one bootstrap
		// binding. keep the same membership/identity and all manual decisions so
		// they can authenticate to the new source before approving other rebinds.
		tag, err := tx.Exec(ctx, `UPDATE control.team_memberships SET identity_connection_id=$4,authority_revision=(SELECT policy_revision+1 FROM control.teams WHERE id=$2),updated_at=$5 WHERE id=$1 AND team_id=$2 AND identity_id=$3 AND identity_connection_id=$6 AND removed_at IS NULL`, a.ActorMembershipID, team, owner, id, now, ownerSource.String)
		if err != nil {
			return result, err
		}
		if tag.RowsAffected() != 1 {
			return result, ErrAuthorityConflict
		}
		details.BootstrapMembershipID = a.ActorMembershipID
		details.PreviousConnectionID = ownerSource.String
		bootstrapIdentity = owner
	}
	c.State, c.Revision = "active", revision+1
	if err = companyPolicyChanged(ctx, tx, q, team, id, owner, bootstrapIdentity, "connection.activate", details, now); err != nil {
		return result, err
	}
	return IdentityConnectionSecret{IdentityConnection: connectionFromRow(c), ProvisioningToken: provisioningToken}, tx.Commit(ctx)
}

func (d *Database) RotateCompanyProvisioningToken(ctx context.Context, p ControlPrincipal, team, id string, revision int64, now time.Time) (result IdentityConnectionSecret, retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "rotate company provisioning token", &retErr)()
	q := controlstatedb.New(tx)
	a, owner, err := lockCompanyOwner(ctx, tx, q, p, team, now)
	if err != nil {
		return result, err
	}
	c, err := q.LockIdentityConnection(ctx, controlstatedb.LockIdentityConnectionParams{TeamID: team, ID: id})
	if err != nil {
		return result, publisherLookupError(err, ErrAuthorityAccess)
	}
	if c.Revision != revision || c.State != "active" {
		return result, ErrAuthorityConflict
	}
	token, err := companyRandom()
	if err != nil {
		return result, err
	}
	digest := sha256.Sum256([]byte(token))
	if _, err = tx.Exec(ctx, `UPDATE control.identity_connections SET provisioning_digest=$2,updated_at=$3 WHERE id=$1`, id, digest[:], now); err != nil {
		return result, err
	}
	if err = q.InsertCompanyAccessAudit(ctx, controlstatedb.InsertCompanyAccessAuditParams{TeamID: team, IdentityConnectionID: text(id), ActorIdentityID: text(owner), Operation: "connection.rotate_provisioning", Revision: a.PolicyRevision, Now: timestamptz(now), Details: `{}`}); err != nil {
		return result, err
	}
	return IdentityConnectionSecret{IdentityConnection: connectionFromRow(c), ProvisioningToken: token}, tx.Commit(ctx)
}
