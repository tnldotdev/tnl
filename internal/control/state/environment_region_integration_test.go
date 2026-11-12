package state

import (
	"errors"
	"slices"
	"testing"
)

func TestIntegrationEnvironmentPublicationRetainsRegionPreferences(t *testing.T) {
	d, now, _, _ := newPublishRunPrerequisites(t)
	regionalRelays(t, d, now)
	r := appliedProjectRequest(t, d, now)
	definition := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "http"}})
	environment, _ := createTestEnvironment(t, d, r, "regional", definition.Revision, EnvironmentTargets{"api": {Address: "original.internal:3000"}})
	member := enrollTestEnvironment(t, d, r, environment)
	assignment := member.assignments.Services[0]
	access := groupAssignmentAccess(t, d, member, assignment, now)
	metadata := ServiceMetadata{Protocol: "http", PublisherPool: true, TrustRevision: assignment.TrustRevision}
	preferences := []string{"fly:sjc", "aws:us-west-1"}
	prepared, err := d.PrepareServiceRun(t.Context(), assignment.ServiceID, access.PublisherIdentity, "regional-original", now, metadata, assignment.Environment, preferences...)
	if err != nil {
		t.Fatal("prepare assigned environment with region preferences", err)
	}
	assertStored := func(run string, application *EnvironmentPublication) {
		t.Helper()
		var saved EnvironmentPublication
		var regions []string
		err := d.pool.QueryRow(t.Context(), `SELECT environment_id,environment_mutation_revision,environment_configuration_hash,preferred_regions FROM control.service_runs WHERE id=$1`, run).
			Scan(&saved.EnvironmentID, &saved.MutationRevision, &saved.ConfigurationHash, &regions)
		if err != nil || saved != *application || !slices.Equal(regions, preferences) {
			t.Fatal("preparation did not persist both independent inputs", err)
		}
	}
	assertStored(prepared.RunID, assignment.Environment)
	if _, err := d.PrepareServiceRun(t.Context(), assignment.ServiceID, access.PublisherIdentity, "regional-original", now, metadata, assignment.Environment, "aws:us-west-1"); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("matching environment fence permitted changed retry preferences", err)
	}
	updated, err := d.ApplyEnvironment(t.Context(), ApplyEnvironmentRequest{
		TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, Now: now,
		EnvironmentApplication: EnvironmentApplication{EnvironmentID: environment.ID, ExpectedRevision: environment.MutationRevision,
			DefinitionRevision: definition.Revision, Targets: EnvironmentTargets{"api": {Address: "replacement.internal:3000"}}},
	})
	if err != nil {
		t.Fatal("apply regional environment target", err)
	}
	if _, err := d.PrepareServiceRun(t.Context(), assignment.ServiceID, access.PublisherIdentity, "stale-regional-worker", now, metadata, assignment.Environment, "aws:us-west-1"); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("different preferences refreshed a stale environment worker", err)
	}
	if _, err := d.StartServiceRun(t.Context(), assignment.ServiceID, prepared.RunID, prepared.RunNumber, access.PublisherIdentity, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("regional preparation started after its environment changed", err)
	}
	current, err := d.GetPublisherGroupAssignments(t.Context(), member.lease.AccessToken, now)
	if err != nil || len(current.Services) != 1 || current.Services[0].Environment == nil || current.Services[0].Environment.MutationRevision != updated.MutationRevision {
		t.Fatal("read current regional assignment", err)
	}
	assignment = current.Services[0]
	prepared, err = d.PrepareServiceRun(t.Context(), assignment.ServiceID, access.PublisherIdentity, "regional-current", now, metadata, assignment.Environment, preferences...)
	if err != nil {
		t.Fatal("prepare current regional environment", err)
	}
	assertStored(prepared.RunID, assignment.Environment)
	run, err := d.StartServiceRun(t.Context(), assignment.ServiceID, prepared.RunID, prepared.RunNumber, access.PublisherIdentity, now)
	if err != nil || len(run.Connections) != 2 {
		t.Fatal("start current regional environment", err)
	}
	if run.Connections[0].RelayServiceID != "fly" || run.Connections[1].RelayServiceID != "aws-a" {
		t.Fatal("environment preparation lost ordered region preferences before placement")
	}
}
