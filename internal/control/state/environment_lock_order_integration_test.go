package state

import (
	"context"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationEnvironmentLockOrderRemovalAndTargetUpdate(t *testing.T) {
	for _, removal := range []string{"environment", "legacy-project"} {
		t.Run(removal, func(t *testing.T) {
			d, now, _, _ := newPublishRunPrerequisites(t)
			first := appliedProjectRequest(t, d, now)
			teamRequest := authorityTeamRequest(first.ActorID)
			teamRequest.DisplayName, teamRequest.IdempotencyKey = "second-team", "second-team"
			team, err := d.CreateTeam(t.Context(), teamRequest, now)
			if err != nil {
				t.Fatal(err)
			}
			second := first
			second.TeamID = team.ID
			definition := environmentDefinition(t, d, second, map[string]ServiceDefinitionService{"api": {Protocol: "http"}})
			updated, _ := createTestEnvironment(t, d, second, "updated", definition.Revision, EnvironmentTargets{"api": {Address: "original.internal:3000"}})
			updater := enrollTestEnvironment(t, d, second, updated)
			start := func(member enrolledGroupReplica, name string) ServiceRunState {
				t.Helper()
				for _, assignment := range member.assignments.Services {
					if assignment.Service != name {
						continue
					}
					access := groupAssignmentAccess(t, d, member, assignment, now)
					prepared, err := d.PrepareServiceRun(t.Context(), assignment.ServiceID, access.PublisherIdentity, "lock-order/"+assignment.GrantID, now, ServiceMetadata{Protocol: "http", PublisherPool: true, TrustRevision: assignment.TrustRevision}, assignment.Environment)
					if err != nil {
						t.Fatal(err)
					}
					run, err := d.StartServiceRun(t.Context(), assignment.ServiceID, prepared.RunID, prepared.RunNumber, access.PublisherIdentity, now)
					if err != nil {
						t.Fatal(err)
					}
					return run
				}
				t.Fatal("missing assigned service", name)
				return ServiceRunState{}
			}
			updateRun := start(updater, "api")
			var remove func(context.Context) error
			var removedRun ServiceRunState
			if removal == "environment" {
				original := environmentDefinition(t, d, first, map[string]ServiceDefinitionService{"keep": {Protocol: "http"}, "remove": {Protocol: "http"}})
				environment, _ := createTestEnvironment(t, d, first, "removed", original.Revision, EnvironmentTargets{"keep": {Address: "kept.internal:3000"}, "remove": {Address: "removed.internal:3000"}})
				removedRun = start(enrollTestEnvironment(t, d, first, environment), "remove")
				next := environmentDefinition(t, d, first, map[string]ServiceDefinitionService{"keep": {Protocol: "http"}})
				remove = func(ctx context.Context) error {
					_, err := d.ApplyEnvironment(ctx, ApplyEnvironmentRequest{TeamID: first.TeamID, ProjectKey: first.ProjectKey, ActorID: first.ActorID, EnvironmentApplication: EnvironmentApplication{EnvironmentID: environment.ID, ExpectedRevision: environment.MutationRevision, DefinitionRevision: next.Revision}, Now: now})
					return err
				}
			} else {
				first.Configuration = ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"production": {}}, Services: map[string]ProjectServiceConfiguration{
					"keep": {PublisherGroup: "production", Protocol: "http", Target: "kept.internal:3000"}, "remove": {PublisherGroup: "production", Protocol: "http", Target: "removed.internal:3000"},
				}}
				applied, err := d.ApplyProjectConfiguration(t.Context(), first)
				if err != nil {
					t.Fatal(err)
				}
				enrollment, err := d.IssuePublisherGroupEnrollment(t.Context(), first.TeamID, first.ProjectKey, "production", first.ActorID, 1, time.Hour, now)
				if err != nil {
					t.Fatal(err)
				}
				removedRun = start(enrollAppliedGroup(t, d, first, enrollment, now), "remove")
				first.ExpectedRevision = applied.Revision
				delete(first.Configuration.Services, "remove")
				remove = func(ctx context.Context) error {
					_, err := d.ApplyProjectConfiguration(ctx, first)
					return err
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			workers := newIntegrationWorkers(t, cancel)
			gate, err := d.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if _, err := controlstatedb.New(gate).LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: updateRun.RunID, ServiceID: updateRun.ServiceID}); err != nil {
				t.Fatal(err)
			}
			changed := make(chan error, 1)
			workers.Go(func() {
				_, err := d.ApplyEnvironment(ctx, ApplyEnvironmentRequest{TeamID: second.TeamID, ProjectKey: second.ProjectKey, ActorID: second.ActorID, EnvironmentApplication: EnvironmentApplication{EnvironmentID: updated.ID, ExpectedRevision: updated.MutationRevision, DefinitionRevision: definition.Revision, Targets: EnvironmentTargets{"api": {Address: "replacement.internal:3000"}}}, Now: now})
				changed <- err
			})
			updatingPID := waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), changed)
			removed := make(chan error, 1)
			workers.Go(func() { removed <- remove(ctx) })
			waitForPostgresBlock(t, ctx, d, updatingPID, removed)
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			updateErr, removeErr := awaitIntegrationResult(t, ctx, changed), awaitIntegrationResult(t, ctx, removed)
			if updateErr != nil || removeErr != nil {
				t.Fatalf("cross-team target update = %v; removal = %v", updateErr, removeErr)
			}
			for _, run := range []ServiceRunState{updateRun, removedRun} {
				var closed bool
				if err := d.pool.QueryRow(ctx, `SELECT closed_at IS NOT NULL FROM control.service_runs WHERE id=$1`, run.RunID).Scan(&closed); err != nil || !closed {
					t.Fatal("committed mutation retained a stale run", run.RunID, err)
				}
			}
		})
	}
}
