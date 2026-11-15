package state

import (
	"reflect"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationServiceConfigurationBatchKeepsCanonicalOwners(t *testing.T) {
	d, now, project, applied, remote := serviceReleaseProject(t, "http", false)
	ctx := t.Context()
	project.ExpectedRevision = applied.Revision
	project.ServiceDeclarations["worker"] = "http"
	project.Configuration.Services["worker"] = ProjectServiceConfiguration{
		Protocol: "http", Target: "localhost:3001", Public: new(true),
		HTTP: &config.HTTPService{Access: &config.Access{Mode: "anonymous", IP: []string{"192.0.2.0/24"}}},
	}
	applied, err := d.ApplyProjectConfiguration(ctx, project)
	if err != nil {
		t.Fatal(err)
	}
	local, err := d.RealizeLocalProjectService(ctx, RealizeLocalProjectServiceRequest{
		TeamID: project.TeamID, ActorID: project.ActorID, ProjectKey: project.ProjectKey,
		SourceFingerprint: project.SourceFingerprint, Service: "app", WorktreeKey: "batch-local",
		Configuration: ProjectServiceConfiguration{Protocol: "http", Target: "localhost:3002", Public: new(true),
			HTTP: &config.HTTPService{Access: &config.Access{IP: []string{"198.51.100.0/24"}}}},
		Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	plain, err := d.CreateServiceAt(ctx, project.TeamID, project.ActorID, "plain", "batch-plain", ServicePlacement{}, now, ServiceMetadata{Protocol: "http"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{local.ServiceID, plain.ID}
	for _, service := range applied.Services {
		ids = append(ids, service.ServiceID)
	}
	q := controlstatedb.New(d.pool)
	expected := make(map[string]*ProjectServiceConfiguration, len(ids))
	for _, id := range ids {
		value, err := d.serviceConfiguration(ctx, q, id)
		if err != nil {
			t.Fatal(err)
		}
		expected[id] = value
	}
	actual, err := d.serviceConfigurations(ctx, q, append(ids, ids...))
	if err != nil || !reflect.DeepEqual(actual, expected) || actual[plain.ID] != nil {
		t.Fatal("batch configuration changed a local, deployment, or declaration-free owner", err)
	}
	// corrupting one owner must not select a second declaration source or
	// silently omit the service while returning the rest of the snapshot.
	if _, err := q.SetServiceConfiguration(ctx, controlstatedb.SetServiceConfigurationParams{
		ServiceID: remote.ID, Ciphertext: []byte("unexpected service-owned configuration"), StorageKeyID: text(d.storageKey.CurrentID()),
	}); err != nil {
		t.Fatal(err)
	}
	if actual, err := d.serviceConfigurations(ctx, q, ids); err == nil || actual != nil {
		t.Fatal("a batched remote service accepted conflicting configuration authority")
	}
}
