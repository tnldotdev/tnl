package controlstate

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

// TeamUsageActorNonce separates usage reads from service management assertions.
// target includes the escaped path and exact raw query; body is the bytes sent.
func TeamUsageActorNonce(method, target string, body []byte) string {
	bodyHash := sha256.Sum256(body)
	bound := sha256.Sum256([]byte("tnl.team-usage.actor.v1\n" + method + "\n" + target + "\n" + base64.RawURLEncoding.EncodeToString(bodyHash[:])))
	return base64.RawURLEncoding.EncodeToString(bound[:])
}

// AuthorizeWebsiteTeamUsage consumes one verified website assertion and checks
// current membership/source permission. it grants no service manager authority.
func (d *Database) AuthorizeWebsiteTeamUsage(ctx context.Context, team, actor string, now time.Time) (retErr error) {
	tx, err := d.beginServiceAccess(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "authorize website team usage", &retErr)()
	q := controlstatedb.New(tx)
	if _, err = q.LockLocalTeamForMutation(ctx, team); err != nil {
		return publisherLookupError(err, ErrAuthorityAccess)
	}
	i, err := consumeServiceActor(ctx, q, actor, now)
	if err != nil {
		return err
	}
	if i.AuthenticatedAt.Unix() <= 0 || i.AuthenticatedAt.After(now) {
		return ErrControlAuthentication
	}
	var required, exception, active bool
	err = tx.QueryRow(ctx, `SELECT t.company_sign_in_required,m.personal_account_exception,control.active_membership(m.id,$3)
		FROM control.teams t JOIN control.team_memberships m ON m.team_id=t.id
		WHERE t.id=$1 AND m.identity_id=$2 AND t.deleted_at IS NULL
		AND m.removed_at IS NULL AND m.manual_suspended_at IS NULL
		FOR UPDATE OF t,m`, team, actor, now).Scan(&required, &exception, &active)
	if err != nil {
		return publisherLookupError(err, ErrAuthorityAccess)
	}
	if !active {
		return ErrAuthorityAccess
	}
	if required && !exception {
		valid := false
		for _, c := range i.TeamContexts {
			if c.TeamID != team || c.AuthenticatedAt != i.AuthenticatedAt.Unix() {
				continue
			}
			ok, err := verifiedCompanyProof(ctx, q, actor, i.Issuer, c, now)
			if err != nil {
				return err
			}
			valid = valid || ok
		}
		if !valid {
			return ErrServiceSourceSignInRequired
		}
	}
	return tx.Commit(ctx)
}
