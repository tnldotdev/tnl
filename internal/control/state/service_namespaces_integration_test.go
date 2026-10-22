package state

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestIntegrationGroupNamespaceAndRename(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "managed_group_names")
	r := appliedProjectRequest(t, d, now)
	r.ProjectLabel = "storefront"
	r.Configuration = ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"production": {}, "staging": {}}, Services: map[string]ProjectServiceConfiguration{
		"orders": {PublisherGroup: "production", Protocol: "postgres", Target: "orders.internal:5432", Access: &ProjectServiceAccess{Team: true}},
		"testdb": {PublisherGroup: "staging", Protocol: "postgres", Target: "staging.internal:5432"},
	}}
	first, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil || len(first.Groups) != 2 || len(first.Services) != 2 {
		t.Fatalf("apply: %+v %v", first, err)
	}
	var group AppliedPublisherGroup
	for _, candidate := range first.Groups {
		if candidate.Name == "production" {
			group = candidate
		}
	}
	if group.ID == "" || !strings.HasPrefix(group.Namespace, "production.storefront.") {
		t.Fatal("group did not use the readable project and existing owner namespace", group)
	}
	var endpoint AppliedProjectService
	for _, candidate := range first.Services {
		if candidate.Service == "orders" {
			endpoint = candidate
		}
	}
	if endpoint.Hostname != "orders."+group.Namespace || endpoint.Port < 20000 || endpoint.Port > 60000 || endpoint.Public {
		t.Fatal("managed endpoint missing", endpoint)
	}
	var urls int
	if err = d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.public_urls WHERE team_id=$1`, r.TeamID).Scan(&urls); err != nil || urls != 0 {
		t.Fatal("service became a public URL", urls, err)
	}
	renamed, err := d.RenamePublisherGroup(t.Context(), r.TeamID, r.ProjectKey, "production", "live", r.ActorID, first.Revision, now.Add(time.Second))
	if err != nil || renamed.Revision != first.Revision+1 || renamed.Configuration.Services["orders"].PublisherGroup != "live" {
		t.Fatal("rename failed", renamed, err)
	}
	for _, candidate := range renamed.Groups {
		if candidate.Name == "live" && (candidate.ID != group.ID || candidate.Namespace != group.Namespace) {
			t.Fatal("rename changed group authority", candidate)
		}
	}
	for _, candidate := range renamed.Services {
		if candidate.Service == "orders" && (candidate.ServiceID != endpoint.ServiceID || candidate.Hostname != endpoint.Hostname || candidate.Port != endpoint.Port) {
			t.Fatal("rename changed the client profile", candidate)
		}
	}
	retry, err := d.RenamePublisherGroup(t.Context(), r.TeamID, r.ProjectKey, "production", "live", r.ActorID, first.Revision, now.Add(2*time.Second))
	if err != nil || retry.Revision != renamed.Revision {
		t.Fatal("rename retry changed state", retry, err)
	}
	r.Configuration = renamed.Configuration
	r.ExpectedRevision = renamed.Revision
	r.ProjectLabel = "a-different-checkout"
	r.Now = now.Add(3 * time.Second)
	public := r.Configuration.PublisherGroups["live"]
	public.Public = true
	r.Configuration.PublisherGroups["live"] = public
	changed, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range changed.Services {
		if candidate.Service == "orders" && (candidate.Hostname != endpoint.Hostname || candidate.Port != endpoint.Port || !candidate.Public) {
			t.Fatal("reachability changed endpoint identity", candidate)
		}
	}
	// the old key still belongs to the same live namespace, not a new group.
	r.ExpectedRevision = changed.Revision
	r.Configuration.PublisherGroups["production"] = ProjectPublisherGroup{}
	if _, err = d.ApplyProjectConfiguration(t.Context(), r); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("a renamed group's namespace was silently adopted", err)
	}
	current, err := d.GetProjectConfiguration(t.Context(), r.TeamID, r.ProjectKey, r.ActorID)
	if err != nil || current.Revision != changed.Revision || len(current.Groups) != 2 {
		t.Fatal("failed name claim was not atomic", current, err)
	}
}

func TestIntegrationManagedProjectLabelCollision(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "managed_project_collision")
	r := appliedProjectRequest(t, d, now)
	r.ProjectLabel = "storefront"
	r.Configuration.PublisherGroups = map[string]ProjectPublisherGroup{"production": {}}
	if _, err := d.ApplyProjectConfiguration(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	r.ProjectKey = "another-source"
	r.SourceFingerprint = strings.Repeat("b", 64)
	if _, err := d.ApplyProjectConfiguration(t.Context(), r); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("a different Git source adopted the namespace", err)
	}
}
