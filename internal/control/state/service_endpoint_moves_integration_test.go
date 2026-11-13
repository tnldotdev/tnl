package state

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
)

func TestIntegrationServiceGroupMove(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "managed_group_move")
	r := appliedProjectRequest(t, d, now)
	r.Deployment = "production"
	r.ServiceDeclarations = map[string]string{"orders": "postgres", "testdb": "postgres"}
	r.Configuration = ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"production": {}}, Services: map[string]ProjectServiceConfiguration{
		"orders": {PublisherGroup: "production", Name: "database", Protocol: "postgres", Target: "orders.internal:5432", Access: &ProjectServiceAccess{Team: true}},
	}}
	first, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	old := first.Services[0]
	staging := r
	staging.Deployment, staging.ExpectedRevision = "staging", first.Revision
	staging.Configuration = ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"staging": {}}, Services: map[string]ProjectServiceConfiguration{
		"testdb": {PublisherGroup: "staging", Name: "database", Protocol: "postgres", Target: "staging.internal:5432"},
	}}
	second, err := d.ApplyProjectConfiguration(t.Context(), staging)
	if err != nil {
		t.Fatal(err)
	}
	grants, _, err := d.ListServiceGrants(t.Context(), old.ServiceID, r.ActorID, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.ListServiceAudit(t.Context(), r.TeamID, r.ActorID, ServiceAuditFilter{Service: "database"}, now); !errors.Is(err, serviceaudit.ErrInvalid) {
		t.Fatal("ambiguous name selected an arbitrary service", err)
	}
	// a colliding destination must roll back the complete apply.
	staging.ExpectedRevision = second.Revision
	s := r.Configuration.Services["orders"]
	s.PublisherGroup = "staging"
	staging.Configuration.Services["orders"] = s
	if _, err = d.ApplyProjectConfiguration(t.Context(), staging); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("accepted a conflicting destination", err)
	}
	current, err := d.GetProjectConfiguration(t.Context(), r.TeamID, r.ProjectKey, r.ActorID, "production")
	if err != nil || current.Revision != second.Revision || current.Services[0] != old {
		t.Fatal("failed move changed the endpoint", current, err)
	}
	delete(staging.Configuration.Services, "testdb")
	staging.Now = now.Add(time.Second)
	moved, err := d.ApplyProjectConfiguration(t.Context(), staging)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := moved.Services[0]
	if endpoint.ServiceID == old.ServiceID || endpoint.Hostname == old.Hostname || !strings.HasPrefix(endpoint.Hostname, "database.staging.") {
		t.Fatal("another deployment adopted the original identity or namespace", old, endpoint)
	}
	production, err := d.GetProjectConfiguration(t.Context(), r.TeamID, r.ProjectKey, r.ActorID, "production")
	if err != nil || len(production.Services) != 1 || production.Services[0] != old || !reflect.DeepEqual(production.Configuration, first.Configuration) {
		t.Fatal("staging replacement changed production", production, err)
	}
	after, _, err := d.ListServiceGrants(t.Context(), old.ServiceID, r.ActorID, "")
	if err != nil || len(after) != len(grants) {
		t.Fatal("move lost visitor grants", after, err)
	}
	for i, grant := range grants {
		if after[i].ID != grant.ID || after[i].RevokedAt != nil {
			t.Fatal("move replaced visitor grants", grants, after)
		}
	}
	retry, err := d.ApplyProjectConfiguration(t.Context(), staging)
	if err != nil || retry.Services[0] != endpoint || retry.Revision != moved.Revision {
		t.Fatal("move retry changed endpoint", retry, err)
	}
}
