package state

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestIntegrationDeploymentNamespaceAndRename(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "managed_deployment_names")
	r := appliedProjectRequest(t, d, now)
	r.ProjectLabel = "storefront"
	r.Configuration = ProjectConfiguration{Services: map[string]ProjectServiceConfiguration{
		"orders": {Protocol: "postgres", Target: "orders.internal:5432", Access: &ProjectServiceAccess{Team: true}},
		"testdb": {Protocol: "postgres", Target: "staging.internal:5432"},
	}}
	staging := projectServiceSelection(r, "staging", "testdb")
	stage, err := d.ApplyProjectConfiguration(t.Context(), staging)
	if err != nil {
		t.Fatal(err)
	}
	r = projectServiceSelection(r, "production", "orders")
	r.ExpectedRevision = stage.Revision
	first, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil || len(first.Deployments) != 1 || len(first.Services) != 1 {
		t.Fatalf("apply: %+v %v", first, err)
	}
	var deployment AppliedDeployment
	for _, candidate := range first.Deployments {
		if candidate.Name == "production" {
			deployment = candidate
		}
	}
	if deployment.ID == "" || !strings.HasPrefix(deployment.Namespace, "production.storefront.") {
		t.Fatal("deployment did not use the readable project and existing owner namespace", deployment)
	}
	var endpoint AppliedProjectService
	for _, candidate := range first.Services {
		if candidate.Service == "orders" {
			endpoint = candidate
		}
	}
	if endpoint.Hostname != "orders."+deployment.Namespace || endpoint.Port != 0 || endpoint.Public {
		t.Fatal("managed endpoint missing", endpoint)
	}
	var urls int
	if err = d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.public_urls WHERE team_id=$1`, r.TeamID).Scan(&urls); err != nil || urls != 0 {
		t.Fatal("service became a public URL", urls, err)
	}
	scope := DeploymentScope{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID}
	beforeRename, err := d.GetDeployment(t.Context(), scope, deployment.ID)
	if err != nil {
		t.Fatal(err)
	}
	renamed, err := d.RenameDeployment(t.Context(), r.TeamID, r.ProjectKey, "production", "live", r.ActorID, first.Revision, now.Add(time.Second))
	if err != nil || renamed.Revision != first.Revision+1 || renamed.Deployment != "live" {
		t.Fatal("rename failed", renamed, err)
	}
	afterRename, err := d.GetDeployment(t.Context(), scope, deployment.ID)
	if err != nil || afterRename.Revision != beforeRename.Revision {
		t.Fatal("selector rename changed the serving revision", afterRename, err)
	}
	for _, candidate := range renamed.Deployments {
		if candidate.Name == "live" && (candidate.ID != deployment.ID || candidate.Namespace != deployment.Namespace) {
			t.Fatal("rename changed deployment authority", candidate)
		}
	}
	for _, candidate := range renamed.Services {
		if candidate.Service == "orders" && (candidate.ServiceID != endpoint.ServiceID || candidate.Hostname != endpoint.Hostname || candidate.Port != endpoint.Port) {
			t.Fatal("rename changed the client profile", candidate)
		}
	}
	retry, err := d.RenameDeployment(t.Context(), r.TeamID, r.ProjectKey, "production", "live", r.ActorID, first.Revision, now.Add(2*time.Second))
	if err != nil || retry.Revision != renamed.Revision {
		t.Fatal("rename retry changed state", retry, err)
	}
	r.Configuration = renamed.Configuration
	r.Deployment = "live"
	r.ExpectedRevision = renamed.Revision
	r.ProjectLabel = "a-different-checkout"
	r.Now = now.Add(3 * time.Second)
	for name, binding := range r.Configuration.Services {
		binding.Public = new(true)
		r.Configuration.Services[name] = binding
	}
	changed, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range changed.Services {
		if candidate.Service == "orders" && (candidate.Hostname != endpoint.Hostname || candidate.ServiceID != endpoint.ServiceID || candidate.Port < 1024 || !candidate.Public || candidate.TrustRevision != endpoint.TrustRevision) {
			t.Fatal("reachability changed endpoint identity", candidate)
		}
	}
	// the old key still belongs to the same live namespace, not a new deployment.
	r.ExpectedRevision = changed.Revision
	r.Deployment = "production"
	r.Configuration = ProjectConfiguration{Settings: &DeploymentSettings{}, Services: map[string]ProjectServiceConfiguration{}}
	if _, err = d.ApplyProjectConfiguration(t.Context(), r); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("a renamed deployment's namespace was silently adopted", err)
	}
	current, err := d.GetProjectConfiguration(t.Context(), r.TeamID, r.ProjectKey, r.ActorID, "live")
	if err != nil || current.Revision != changed.Revision || len(current.Deployments) != 1 {
		t.Fatal("failed name claim was not atomic", current, err)
	}
}

func TestIntegrationManagedProjectLabelCollision(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "managed_project_collision")
	r := appliedProjectRequest(t, d, now)
	r.ProjectLabel = "storefront"
	r.Configuration.Settings = &DeploymentSettings{}
	r = selectedProjectRequest(r, "production")
	if _, err := d.ApplyProjectConfiguration(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	r.ProjectKey = "another-source"
	r.SourceFingerprint = strings.Repeat("b", 64)
	if _, err := d.ApplyProjectConfiguration(t.Context(), r); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("a different Git source adopted the namespace", err)
	}
}
