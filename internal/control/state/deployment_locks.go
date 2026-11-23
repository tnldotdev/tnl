package state

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

// both modes join the same team queue before selecting a project or deployment.
// choose once at entry; a reader never upgrades a parent lock.
type deploymentLockMode bool

const (
	deploymentRead     deploymentLockMode = false
	deploymentMutation deploymentLockMode = true
)

func (m deploymentLockMode) team(ctx context.Context, q *controlstatedb.Queries, id string) error {
	lock := q.LockLocalTeamForSession
	if m == deploymentMutation {
		lock = q.LockLocalTeamForMutation
	}
	_, err := lock(ctx, id)
	return err
}

// team management and key rotation take the identity lock, but an access
// exchange can also hold it directly. wait for that writer before the fresh
// credential check, after all selected publication parents.
func observeDeploymentCredential(ctx context.Context, tx pgx.Tx, publisher, grant string) error {
	var id string
	if err := tx.QueryRow(ctx, `SELECT id FROM control.publisher_identities WHERE id=$1 FOR SHARE`, publisher).Scan(&id); err != nil {
		return publisherLookupError(err, ErrPublisherIdentity)
	}
	_, err := controlstatedb.New(tx).GetPublisherGrant(ctx, controlstatedb.GetPublisherGrantParams{ID: grant, PublisherIdentityID: publisher})
	return publisherLookupError(err, ErrPublisherIdentity)
}

func (m deploymentLockMode) project(ctx context.Context, q *controlstatedb.Queries, team, project string) (controlstatedb.ControlAppliedProject, error) {
	if m == deploymentMutation {
		return q.LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: team, ProjectKey: project})
	}
	return q.ObserveAppliedProject(ctx, controlstatedb.ObserveAppliedProjectParams{TeamID: team, ProjectKey: project})
}

func (m deploymentLockMode) selectDeployment(ctx context.Context, q *controlstatedb.Queries, team, project, selector string) (controlstatedb.ControlDeployment, error) {
	if m == deploymentMutation {
		return q.LockDeployment(ctx, controlstatedb.LockDeploymentParams{TeamID: team, ProjectKey: project, Selector: selector})
	}
	return q.ObserveDeployment(ctx, controlstatedb.ObserveDeploymentParams{TeamID: team, ProjectKey: project, Selector: selector})
}
