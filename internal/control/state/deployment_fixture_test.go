package state

import (
	"context"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

// fixtures approve the bindings present at setup, never a rule for future names.
func testDeploymentPublisherEnrollment(d *Database, ctx context.Context, team, project, selector, actor string, members int, lifetime time.Duration, now time.Time) (DeploymentPublisherEnrollment, error) {
	scope := DeploymentScope{TeamID: team, ProjectKey: project, ActorID: actor}
	deployment, err := d.GetDeployment(ctx, scope, selector)
	if err != nil {
		return DeploymentPublisherEnrollment{}, err
	}
	key, err := opaqueid.New(opaqueid.IdempotencyPrefix)
	if err != nil {
		return DeploymentPublisherEnrollment{}, err
	}
	return d.CreateDeploymentPublisherEnrollment(ctx, CreateDeploymentPublisherEnrollmentRequest{
		DeploymentScope: scope, Selector: deployment.ID, Services: sortedProjectKeys(deployment.Services),
		IdempotencyKey: key, MaxMembers: members, Lifetime: lifetime, Now: now,
	})
}
