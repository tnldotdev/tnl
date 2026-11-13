package state

import (
	"context"
	"crypto/ed25519"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

type deploymentConnectFacts struct {
	PublicKey ed25519.PublicKey
	ExpiresAt time.Time
	Revision  int64
}

// resolve under current visitor authority, not management authority. the existing
// run selector checks the exact binding's subject again before returning a run.
func (d *Database) SelectDeploymentServiceRun(ctx context.Context, team, project, deployment, service string, source VisitorTokenSource, now time.Time) (result ServiceSelection, retErr error) {
	if !naming.ValidServiceName(service) {
		return result, ErrVisitorPermission
	}
	switch source.(type) {
	case DeviceTokenSource, WorkloadTokenSource, RegisteredKeyTokenSource:
	default:
		return result, ErrVisitorPermission
	}
	clock := newAuthorizationClock(now)
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "resolve deployment service", &retErr)()
	var id string
	err = tx.QueryRow(ctx, `SELECT binding.service_id FROM control.applied_project_services binding
	    JOIN control.project_publisher_groups deployment ON deployment.id=binding.group_id AND deployment.deleted_at IS NULL
	    WHERE binding.team_id=$1 AND binding.project_key=$2 AND binding.service=$4
	    AND (deployment.id=$3 OR EXISTS(SELECT 1 FROM control.publisher_group_names alias WHERE alias.group_id=deployment.id AND alias.name=$3))`, team, project, deployment, service).Scan(&id)
	if err != nil {
		return result, publisherLookupError(err, ErrVisitorPermission)
	}
	authority, err := d.visitorAuthorityForSource(ctx, tx, visitorscope.Scope{Kind: visitorscope.Service, ID: id}, source, clock)
	if err != nil {
		return result, err
	}
	subject, err := visitortoken.ConnectorSubject(authority.Permission.Subject)
	if err != nil {
		return result, err
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	result, err = d.SelectVisitorServiceRun(ctx, id, subject, clock.current())
	if err != nil {
		return ServiceSelection{}, err
	}
	result.ExpiresAt = minTime(result.ExpiresAt, minTime(authority.Permission.ExpiresAt, authority.ConnectorUntil))
	if !result.ExpiresAt.After(clock.current()) {
		return ServiceSelection{}, ErrVisitorPermission
	}
	return result, nil
}

// callers hold the service/team admission guard. the same current selection is
// used for issuance, retained connector owners and publisher policy snapshots.
func deploymentConnectAuthority(ctx context.Context, tx pgx.Tx, grant, key, service string, now time.Time) (facts deploymentConnectFacts, err error) {
	err = tx.QueryRow(ctx, `SELECT public_key,expires_at,revision FROM control.deployment_connect_authority($1,$2,$3,$4)`, grant, key, service, now).Scan(&facts.PublicKey, &facts.ExpiresAt, &facts.Revision)
	return facts, publisherLookupError(err, ErrVisitorPermission)
}

// lock after publication parents, never before selecting or locking their runs.
// a repeatable-read preparation may have established its snapshot before waiting
// for the team guard. row locks force a serialization retry if an authority parent
// changed during that wait; a plain snapshot read cannot prove current authority.
func (d *Database) lockRegisteredVisitorAuthority(ctx context.Context, tx pgx.Tx, source VisitorTokenSource, permission visitortoken.Permission, clock authorizationClock) error {
	registered, ok := source.(RegisteredKeyTokenSource)
	if !ok {
		return nil
	}
	subject, ok := permission.Subject.(visitortoken.RegisteredKey)
	if !ok || permission.Scope.Kind != visitorscope.Service {
		return ErrVisitorPermission
	}
	identity, err := d.authenticatePublisherAccess(ctx, controlstatedb.New(tx), registered.Credential, "", clock.current(), true)
	if err != nil {
		return err
	}
	if identity.GrantID != subject.GrantID || identity.KeyID != subject.KeyID || identity.Scope.Kind != DeploymentCredentialGrant {
		return ErrVisitorPermission
	}
	var public []byte
	if err = tx.QueryRow(ctx, `SELECT public_key FROM control.publisher_identity_keys WHERE id=$1 AND publisher_identity_id=$2 AND retired_at IS NULL FOR SHARE`, subject.KeyID, identity.ID).Scan(&public); err != nil {
		return publisherLookupError(err, ErrVisitorPermission)
	}
	if _, err = tx.Exec(ctx, `SELECT grant_id FROM control.deployment_management_services WHERE grant_id=$1 FOR SHARE`, subject.GrantID); err != nil {
		return err
	}
	facts, err := deploymentConnectAuthority(ctx, tx, subject.GrantID, subject.KeyID, permission.Scope.ID, clock.current())
	if err != nil {
		return err
	}
	digest, err := visitortoken.KeyDigest(ed25519.PublicKey(public))
	if err != nil || digest != subject.KeySHA256 || !permission.ExpiresAt.After(clock.current()) || !facts.ExpiresAt.After(clock.current()) {
		return ErrVisitorPermission
	}
	return nil
}
