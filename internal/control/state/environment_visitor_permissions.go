package state

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

type EnvironmentVisitorPermission struct {
	ID                 string                     `json:"id"`
	MachineID          string                     `json:"machine_id"`
	TeamID             string                     `json:"team_id"`
	ProjectKey         string                     `json:"project_key"`
	Scope              EnvironmentPermissionScope `json:"scope"`
	Services           []string                   `json:"services"`
	MaxDurationSeconds int                        `json:"max_duration_seconds"`
	ExpiresAt          time.Time                  `json:"expires_at"`
}

func (d *Database) CreateEnvironmentVisitorPermission(ctx context.Context, p EnvironmentVisitorPermission, actor string, now time.Time) (result EnvironmentVisitorPermission, retErr error) {
	tx, err := d.machineManagerTransaction(ctx, p.TeamID, actor)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "create environment visitor permission", &retErr)()
	result, err = createEnvironmentVisitorPermission(ctx, tx, p, now)
	if err != nil {
		return result, err
	}
	if err = serviceManager(ctx, tx, p.TeamID, actor); err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}

// the caller holds the team manager guard; approval composes this same permission
// operation with machine registration and its durable recovery receipt.
func createEnvironmentVisitorPermission(ctx context.Context, tx pgx.Tx, p EnvironmentVisitorPermission, now time.Time) (result EnvironmentVisitorPermission, err error) {
	if !naming.ValidProjectKey(p.ProjectKey) || !p.ExpiresAt.After(now) || p.ExpiresAt.After(now.Add(366*24*time.Hour)) || p.MaxDurationSeconds < 0 || p.MaxDurationSeconds > 31557600 {
		return result, ErrEnvironmentInvalid
	}
	if p.Scope, err = normalizeEnvironmentPermissionScope(p.Scope); err != nil {
		return result, err
	}
	if p.Services, err = normalizeEnvironmentPermissionServices(p.Services); err != nil {
		return result, err
	}
	if _, err = controlstatedb.New(tx).LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: p.TeamID, ProjectKey: p.ProjectKey}); err != nil {
		return result, publisherLookupError(err, ErrMachineDenied)
	}
	captured, err := captureEnvironmentPermissionScope(ctx, tx, p.TeamID, p.ProjectKey, p.Scope)
	if err != nil {
		return result, err
	}
	m, err := machineIdentity(ctx, tx, p.MachineID)
	if err != nil || m.TeamID != p.TeamID {
		if err == nil {
			err = ErrMachineDenied
		}
		return result, err
	}
	p.ID, err = opaqueid.New("mwp_")
	if err != nil {
		return result, err
	}
	future := p.Scope.IncludeFutureEnvironments != nil && *p.Scope.IncludeFutureEnvironments
	_, err = tx.Exec(ctx, `INSERT INTO control.machine_workload_permissions(id,machine_id,team_id,project_key,collection_id,include_future_environments,environment_ids,services,max_duration_seconds,expires_at) VALUES($1,$2,$3,$4,NULLIF($5,''),$6,$7,$8,$9,$10)`, p.ID, p.MachineID, p.TeamID, p.ProjectKey, p.Scope.CollectionID, future, captured, p.Services, p.MaxDurationSeconds, p.ExpiresAt)
	if err != nil {
		return result, err
	}
	return p, nil
}

func (d *Database) RevokeEnvironmentVisitorPermission(ctx context.Context, team, id, actor string, now time.Time) (retErr error) {
	tx, err := d.machineManagerTransaction(ctx, team, actor)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "revoke environment visitor permission", &retErr)()
	tag, err := tx.Exec(ctx, `UPDATE control.machine_workload_permissions SET revoked_at=COALESCE(revoked_at,$3) WHERE id=$1 AND team_id=$2`, id, team, now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrMachineDenied
	}
	return tx.Commit(ctx)
}

// the saved permission selects identity and trust. request claims never select
// a verifier, and a machine ID cannot search for a more permissive grant.
func (d *Database) EnvironmentVisitorIdentityPolicy(ctx context.Context, permission string, now time.Time) (MachineIdentity, error) {
	var id string
	err := d.pool.QueryRow(ctx, `SELECT machine_id FROM control.machine_workload_permissions WHERE id=$1 AND revoked_at IS NULL AND expires_at>$2`, permission, now).Scan(&id)
	if err != nil {
		return MachineIdentity{}, publisherLookupError(err, ErrMachineDenied)
	}
	return d.MachineIdentityPolicy(ctx, id)
}

// admission holds the team guard. every visitor session must have its own exact
// environment/permission binding; an unlinked old session is never a fallback.
func verifyMachineSession(ctx context.Context, tx pgx.Tx, id string, now time.Time) error {
	var allowed bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM control.workload_session_machines binding
		JOIN control.workload_sessions session ON session.id=binding.session_id
		JOIN control.machine_identities machine ON machine.id=binding.machine_id AND machine.team_id=session.team_id AND machine.revision=binding.identity_revision AND machine.revoked_at IS NULL
		JOIN control.machine_workload_permissions permission ON permission.id=binding.permission_id AND permission.machine_id=machine.id AND permission.team_id=session.team_id AND permission.project_key=session.project_key AND permission.revoked_at IS NULL AND permission.expires_at>$2
		JOIN control.environments environment ON environment.id=binding.environment_id AND environment.team_id=session.team_id AND environment.project_key=session.project_key AND environment.retired_at IS NULL
		WHERE binding.session_id=$1 AND binding.permission_deadline>$2
		AND (permission.collection_id IS NULL OR permission.collection_id=environment.collection_id)
		AND ((permission.collection_id IS NOT NULL AND permission.include_future_environments) OR environment.id=ANY(permission.environment_ids))
	)`, id, now).Scan(&allowed)
	if err != nil {
		return err
	}
	if !allowed {
		return ErrWorkloadDenied
	}
	return nil
}
