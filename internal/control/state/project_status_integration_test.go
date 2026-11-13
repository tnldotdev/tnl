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
	r.Configuration = ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"production": {}}, Services: map[string]ProjectServiceConfiguration{"db": local, "web": {Target: "app"}}}
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
