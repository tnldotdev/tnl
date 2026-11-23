package state

import (
	"context"

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
