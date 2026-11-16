package state

import (
	"context"
	"time"
)

// retirement is an empty apply plus an inventory marker in the same transaction.
// preserve the source binding and revision so stale writers cannot recreate it.
func (d *Database) RetireProject(ctx context.Context, team, project, actor string, expected int64, now time.Time) (AppliedProjectConfiguration, error) {
	if expected < 1 {
		return AppliedProjectConfiguration{}, ErrProjectConfigurationInvalid
	}
	return d.ApplyProjectConfiguration(ctx, ApplyProjectConfigurationRequest{retire: true, Deployment: "local", ServiceDeclarations: map[string]string{}, TeamID: team, ProjectKey: project, ActorID: actor, ExpectedRevision: expected, Now: now})
}
