package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/naming/tcpport"
)

func TestIntegrationProjectStatusWorktreeInventory(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "project_status")
	if err := d.ConfigureIngressServicePorts(t.Context(), PrimaryIngressPoolID, []tcpport.Range{{First: 25443, Last: 25600}}); err != nil {
		t.Fatal(err)
	}
	r := appliedProjectRequest(t, d, now)
	r.ProjectLabel = "storefront"
	local := ProjectServiceConfiguration{Protocol: "postgres", Target: "localhost:5432", TargetTLS: &ProjectTargetTLS{Hostname: "database.internal"}}
	r.Configuration = ProjectConfiguration{Services: map[string]ProjectServiceConfiguration{"db": local, "web": {Target: "app"}}}
	r = selectedProjectRequest(r, "local")
	applied, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := d.GetProjectStatus(t.Context(), r.TeamID, r.ProjectKey, r.ActorID, "", now)
	if err != nil || len(initial.Publications) != 2 || initial.Publications[0].Reason != "not_realized" {
		t.Fatal("unrealized declarations missing", initial, err)
	}
	for i := range 102 {
		_, err = d.RealizeLocalProjectService(t.Context(), RealizeLocalProjectServiceRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint, Service: "db", WorktreeKey: fmt.Sprintf("checkout-%03d", i), ActorID: r.ActorID, Configuration: local, Now: now})
		if err != nil {
			t.Fatal(err)
		}
	}
	page, err := d.GetProjectStatus(t.Context(), r.TeamID, r.ProjectKey, r.ActorID, "", now)
	if err != nil || len(page.Publications) != 100 || page.NextCursor == "" || page.Revision != applied.Revision || page.ProjectLabel != "storefront" {
		t.Fatal("first status page", page, err)
	}
	seen := map[string]bool{}
	for _, p := range page.Publications {
		if p.Reason != "not_publishing" || p.ServiceID == "" || p.WorktreeKey == "" || seen[p.ServiceID] {
			t.Fatal("worktree identity missing or duplicated", p)
		}
		seen[p.ServiceID] = true
	}
	last, err := d.GetProjectStatus(t.Context(), r.TeamID, r.ProjectKey, r.ActorID, page.NextCursor, now)
	if err != nil || len(last.Publications) != 3 || last.NextCursor != "" {
		t.Fatal("last status page", last, err)
	}
	for _, p := range last.Publications {
		if p.ServiceID != "" && seen[p.ServiceID] {
			t.Fatal("page repeated a worktree", p)
		}
	}
	if _, err = d.GetProjectStatus(t.Context(), r.TeamID, "other", r.ActorID, page.NextCursor, now); !errors.Is(err, ErrDiscoveryCursor) {
		t.Fatal("cursor crossed project", err)
	}
	if _, err = d.GetProjectStatus(t.Context(), r.TeamID, r.ProjectKey, "other-actor", "", now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("status did not recheck management access", err)
	}
	data, err := json.Marshal(page)
	if err != nil || strings.Contains(string(data), "localhost") || strings.Contains(string(data), "target_tls") || strings.Contains(string(data), "configuration") {
		t.Fatal("status leaked configuration", string(data), err)
	}
}

func TestIntegrationProjectStatusKeepsSameNamedDeploymentBindings(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "deployment_status")
	if err := d.ConfigureIngressServicePorts(t.Context(), PrimaryIngressPoolID, []tcpport.Range{{First: 25443, Last: 25600}}); err != nil {
		t.Fatal(err)
	}
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{Services: map[string]ProjectServiceConfiguration{"db": {Protocol: "postgres", Target: "localhost:5432"}}}
	r = selectedProjectRequest(r, "local")
	local, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	r.ExpectedRevision = local.Revision
	r.Deployment = "staging"
	r.Configuration.PublisherGroups = map[string]ProjectPublisherGroup{"staging": {}}
	r.Configuration.Services["db"] = ProjectServiceConfiguration{PublisherGroup: "staging", Protocol: "postgres", Target: "staging.internal:5432"}
	staging, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	customer, err := d.CreateDeployment(t.Context(), CreateDeploymentRequest{
		DeploymentScope: DeploymentScope{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID},
		Name:            "customer", IdempotencyKey: "status-customer", Targets: map[string]DeploymentTarget{"db": {Address: "customer.internal:5432"}}, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	status, err := d.GetProjectStatus(t.Context(), r.TeamID, r.ProjectKey, r.ActorID, "", now)
	if err != nil || len(status.Publications) != 3 {
		t.Fatal("same-named bindings were lost", status, err)
	}
	seen := map[string]bool{}
	for _, publication := range status.Publications {
		if publication.Service != "db" || seen[publication.PublisherGroup] {
			t.Fatal("status mixed deployment selectors", publication)
		}
		seen[publication.PublisherGroup] = true
	}
	if !seen["local"] || !seen["staging"] || !seen["customer"] {
		t.Fatal("status borrowed another deployment's selector", seen)
	}
	retired, err := d.RetireProject(t.Context(), r.TeamID, r.ProjectKey, r.ActorID, staging.Revision, now)
	if err != nil || retired.RetiredAt == nil {
		t.Fatal("retirement did not include all deployment owners", retired, err)
	}
	status, err = d.GetProjectStatus(t.Context(), r.TeamID, r.ProjectKey, r.ActorID, "", now)
	if err != nil || len(status.Publications) != 0 {
		t.Fatal("retirement retained sibling publications", status, err)
	}
	if _, err = d.GetDeployment(t.Context(), DeploymentScope{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID}, customer.ID); err == nil {
		t.Fatal("retirement retained an independently managed deployment")
	}
}
