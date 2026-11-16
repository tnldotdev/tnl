package state

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationAppliedDeploymentSelectionPreservesSiblings(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "selected_apply")
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	r.Deployment = "local"
	r.ServiceDeclarations = map[string]string{"web": "http", "db": "postgres"}
	local, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	localCiphertext := func() []byte {
		t.Helper()
		row, err := controlstatedb.New(d.pool).GetAppliedProject(ctx, controlstatedb.GetAppliedProjectParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey})
		if err != nil {
			t.Fatal(err)
		}
		record, err := d.openAppliedProjectRecord(row)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(record.Deployments["local"], local.Configuration) {
			t.Fatal("remote apply changed local desired input")
		}
		return row.ConfigurationCiphertext
	}
	for _, name := range []string{"staging", "production"} {
		r.Deployment = name
		r.ExpectedRevision = local.Revision
		r.Configuration = ProjectConfiguration{Settings: &DeploymentSettings{}, Services: map[string]ProjectServiceConfiguration{"db": {Protocol: "postgres", Target: name + ".internal:5432"}}}
		selected, err := d.ApplyProjectConfiguration(ctx, r)
		if err != nil {
			t.Fatal(err)
		}
		if selected.Deployment != name || len(selected.Services) != 1 || len(selected.Deployments) != 1 || selected.Services[0].Deployment != name || selected.Configuration.Services["db"].Target != name+".internal:5432" {
			t.Fatal("selected apply leaked sibling bindings", selected)
		}
		local.Revision = selected.Revision
		_ = localCiphertext()
	}
	production, err := d.GetDeployment(ctx, DeploymentScope{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID}, "production")
	if err != nil {
		t.Fatal(err)
	}
	r.Deployment = "staging"
	r.Configuration = ProjectConfiguration{Settings: &DeploymentSettings{}, Services: map[string]ProjectServiceConfiguration{}}
	r.ExpectedRevision = local.Revision
	removed, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil || len(removed.Services) != 0 {
		t.Fatal("selected removal failed", removed, err)
	}
	unchanged, err := d.GetDeployment(ctx, DeploymentScope{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID}, "production")
	if err != nil || !reflect.DeepEqual(unchanged, production) {
		t.Fatal("removing staging changed production", err)
	}
	status, err := d.GetProjectConfiguration(ctx, r.TeamID, r.ProjectKey, r.ActorID, "local")
	if err != nil || !reflect.DeepEqual(status.Configuration, local.Configuration) || len(status.Services) != 1 || status.Services[0].Service != "web" {
		t.Fatal("remote apply retired local desired state", status, err)
	}
	missing, err := d.GetProjectConfiguration(ctx, r.TeamID, r.ProjectKey, r.ActorID, "customer")
	if err != nil || missing.Revision != removed.Revision || len(missing.Configuration.Services) != 0 {
		t.Fatal("new selection lost the project concurrency revision", missing, err)
	}
	r.ExpectedRevision = removed.Revision
	r.ServiceDeclarations = map[string]string{"web": "http"}
	if _, err := d.ApplyProjectConfiguration(ctx, r); !errors.Is(err, ErrProjectManaged) {
		t.Fatal("removed logical declaration still bound by a sibling", err)
	}
	r.ServiceDeclarations = map[string]string{"web": "http", "db": "mysql"}
	if _, err := d.ApplyProjectConfiguration(ctx, r); !errors.Is(err, ErrProjectManaged) {
		t.Fatal("changed a sibling's logical protocol", err)
	}
	if _, err := d.GetProjectService(ctx, GetProjectServiceRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint, Deployment: "staging", Service: "db", IdentityID: r.ActorID, Now: now}); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("removed binding fell back to production", err)
	}
}

func TestIntegrationAppliedDeploymentWorkloadRightsStaySelected(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "selected_workload")
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	r.Deployment = "production"
	r.ServiceDeclarations = map[string]string{"api": "http", "db": "postgres"}
	r.Configuration = workloadConfiguration()
	p := r.Configuration.Workloads["test"]
	p.Deployment = "production"
	r.Configuration.Workloads["test"] = p
	applied, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	exchange, _ := workloadExchange(t, r, now)
	session, err := d.ExchangeWorkload(ctx, exchange, now)
	if err != nil {
		t.Fatal(err)
	}
	before, err := d.ListWorkloadServices(ctx, session.Credential, now)
	if err != nil || len(before) != 2 {
		t.Fatal(before, err)
	}
	r.Deployment, r.ExpectedRevision = "staging", applied.Revision
	r.Configuration = ProjectConfiguration{Settings: &DeploymentSettings{}, Services: map[string]ProjectServiceConfiguration{"db": {Protocol: "postgres", Target: "staging.internal:5432"}}}
	staging, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	after, err := d.ListWorkloadServices(ctx, session.Credential, now)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("sibling apply changed existing workload rights", after, err)
	}
	if _, err := d.WorkloadPolicy(ctx, r.TeamID, r.ProjectKey, "test", r.SourceFingerprint); err != nil {
		t.Fatal("sibling apply removed policy", err)
	}
	// the same project-wide policy name cannot silently move deployments.
	r.ExpectedRevision = staging.Revision
	r.Configuration = workloadConfiguration()
	r.Configuration.Settings = &DeploymentSettings{}
	p.Deployment = "staging"
	r.Configuration.Workloads["test"] = p
	if _, err := d.ApplyProjectConfiguration(ctx, r); !errors.Is(err, ErrProjectConfigurationInvalid) {
		t.Fatal("sibling stole an existing policy name", err)
	}
	// remove the old policy, then explicitly approve the other deployment. the
	// issued session must remain revoked, not gain same-named replacement rights.
	r.Deployment = "production"
	r.Configuration = workloadConfiguration()
	r.Configuration.Workloads = nil
	removed, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	r.Deployment, r.ExpectedRevision = "staging", removed.Revision
	r.Configuration = workloadConfiguration()
	r.Configuration.Settings = &DeploymentSettings{}
	r.Configuration.Workloads["test"] = p
	if _, err := d.ApplyProjectConfiguration(ctx, r); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ListWorkloadServices(ctx, session.Credential, now.Add(time.Second)); !errors.Is(err, ErrWorkloadDenied) {
		t.Fatal("old session gained replacement deployment rights", err)
	}
}
