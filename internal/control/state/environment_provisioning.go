package state

import (
	"context"
	"crypto/sha256"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

// the private capability keeps machine provenance separate from human sessions.
// authentication captures a deadline; the owning operation checks exact scope in
// its mutation transaction and spends that same deadline after all lock waits.
func (d *Database) authenticateEnvironmentProvisioner(ctx context.Context, credential string) (a EnvironmentPublisherManager, err error) {
	if len(credential) > 256 {
		return a, ErrControlAuthentication
	}
	digest := sha256.Sum256([]byte(credential))
	err = d.pool.QueryRow(ctx, `SELECT s.machine_id,s.grant_id,LEAST(s.expires_at,g.expires_at) FROM control.machine_provisioning_sessions s JOIN control.machine_identities m ON m.id=s.machine_id JOIN control.machine_provisioning_grants g ON g.id=s.grant_id AND g.machine_id=m.id WHERE s.credential_digest=$1 AND s.identity_revision=m.revision AND m.revoked_at IS NULL AND g.revoked_at IS NULL AND s.created_at<=$2 AND s.expires_at>$2 AND g.expires_at>$2`, digest[:], time.Now()).Scan(&a.machineID, &a.provisioningGrantID, &a.deadline)
	if err != nil {
		return EnvironmentPublisherManager{}, publisherLookupError(err, ErrControlAuthentication)
	}
	a.provisioningCredential = credential
	return a, nil
}

func (a EnvironmentPublisherManager) issuer() publisherIssuer {
	return publisherIssuer{IdentityID: a.identityID, MachineID: a.machineID, ProvisioningGrantID: a.provisioningGrantID}
}

func (a EnvironmentPublisherManager) checkProvisioner(ctx context.Context, tx pgx.Tx, team string) error {
	if !a.deadline.After(time.Now()) {
		return ErrControlAuthentication
	}
	digest := sha256.Sum256([]byte(a.provisioningCredential))
	var current bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.machine_provisioning_sessions s JOIN control.machine_identities m ON m.id=s.machine_id JOIN control.machine_provisioning_grants g ON g.id=s.grant_id AND g.machine_id=m.id WHERE s.credential_digest=$1 AND m.id=$2 AND g.id=$3 AND m.team_id=$4 AND g.team_id=$4 AND s.identity_revision=m.revision AND m.revoked_at IS NULL AND g.revoked_at IS NULL AND s.created_at<=$5 AND s.expires_at>$5 AND g.expires_at>$5)`, digest[:], a.machineID, a.provisioningGrantID, team, time.Now()).Scan(&current)
	if err != nil {
		return err
	}
	if !current || !a.deadline.After(time.Now()) {
		return ErrMachineDenied
	}
	return nil
}

func (a EnvironmentPublisherManager) start(ctx context.Context, tx pgx.Tx, team string) error {
	if _, err := controlstatedb.New(tx).LockLocalTeamForMutation(ctx, team); err != nil {
		return publisherLookupError(err, ErrServiceAccess)
	}
	if a.provisioningCredential != "" {
		return a.checkProvisioner(ctx, tx, team)
	}
	if a.internalActor {
		return serviceManager(ctx, tx, team, a.identityID)
	}
	return a.check(ctx, tx, team)
}

func environmentManagement(ctx context.Context, tx pgx.Tx, team, actor string, a EnvironmentPublisherManager) (EnvironmentPublisherManager, error) {
	// actor-only entry points are retained for trusted state operations. HTTP
	// always supplies a captured credential; machine capabilities have no actor.
	if a.accessID == "" && a.provisioningCredential == "" && actor != "" {
		a = EnvironmentPublisherManager{identityID: actor, internalActor: true}
	}
	if actor != "" && actor != a.identityID {
		return EnvironmentPublisherManager{}, ErrServiceAccess
	}
	return a, a.start(ctx, tx, team)
}

func (a EnvironmentPublisherManager) authorize(ctx context.Context, tx pgx.Tx, scope ProvisioningScope, spend bool) error {
	if a.provisioningCredential == "" {
		return a.start(ctx, tx, scope.TeamID)
	}
	p, err := authorizeProvisioning(ctx, tx, a.provisioningCredential, scope, time.Now(), spend)
	if err != nil {
		return err
	}
	if p.MachineID != a.machineID || p.GrantID != a.provisioningGrantID || !a.deadline.After(time.Now()) {
		return ErrMachineDenied
	}
	return nil
}

func definitionServiceNames(definition ServiceDefinition) []string {
	return sortedProjectKeys(definition.Services)
}

func (d *Database) authorizeEnvironmentCreationRetry(ctx context.Context, tx pgx.Tx, a EnvironmentPublisherManager, row controlstatedb.ControlEnvironment) error {
	if a.provisioningCredential == "" {
		return nil
	}
	var same bool
	if err := tx.QueryRow(ctx, `SELECT COALESCE(created_by_machine_id=$2 AND provisioning_grant_id=$3,false) FROM control.environments WHERE id=$1`, row.ID, a.machineID, a.provisioningGrantID).Scan(&same); err != nil {
		return err
	}
	if !same {
		return ErrMachineDenied
	}
	// a create retry must not expose later additions outside its service allowlist.
	return d.authorizeEnvironmentProjection(ctx, tx, a, row, ProvisioningCreate)
}

func (d *Database) authorizeEnvironmentProjection(ctx context.Context, tx pgx.Tx, a EnvironmentPublisherManager, row controlstatedb.ControlEnvironment, op ProvisioningOperation) error {
	definition, _, _, err := d.environmentProjection(ctx, tx, row)
	if err != nil {
		return err
	}
	return a.authorize(ctx, tx, ProvisioningScope{Operation: op, TeamID: row.TeamID, ProjectKey: row.ProjectKey, EnvironmentID: row.ID, Services: definitionServiceNames(definition)}, false)
}
