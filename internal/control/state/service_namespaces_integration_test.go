package state

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestIntegrationGroupNamespaceAndRename(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "managed_group_names")
	r := retainedEnvironmentProject(t, d, now)
	first, request := retainedServiceEnvironment(t, d, r, "production", map[string]EnvironmentServicePublication{"orders": {Protocol: "postgres", Target: "orders.internal:5432"}})
	staging, _ := retainedServiceEnvironment(t, d, r, "staging", map[string]EnvironmentServicePublication{"orders": {Protocol: "postgres", Target: "staging.internal:5432"}})
	endpoint := first.Services[0]
	if endpoint.Port < 20000 || endpoint.Port > 60000 || endpoint.Public || strings.Contains(endpoint.Hostname, first.Name) || endpoint.Hostname == staging.Services[0].Hostname {
		t.Fatal("endpoint came from human selector or shared namespace", endpoint)
	}
	var urls int
	if err := d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.public_urls WHERE team_id=$1`, r.TeamID).Scan(&urls); err != nil || urls != 0 {
		t.Fatal("service became public URL", err)
	}
	// renaming a human selector is a durable fixture perturbation, not a public
	// namespace mutation API. captured endpoint authority remains unchanged.
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.environments SET name='live' WHERE id=$1`, first.ID); err != nil {
		t.Fatal(err)
	}
	renamed, err := d.GetEnvironment(t.Context(), r.TeamID, r.ProjectKey, first.ID, r.ActorID)
	if err != nil || renamed.Name != "live" || !reflect.DeepEqual(renamed.Services, first.Services) {
		t.Fatal("selector change altered endpoint authority", err)
	}
	if retry, err := d.CreateEnvironment(t.Context(), request); err != nil || retry.ID != first.ID || retry.MutationRevision != first.MutationRevision {
		t.Fatal("creation retry replaced renamed selector", err)
	}
	changed, err := d.ApplyEnvironment(t.Context(), ApplyEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, EnvironmentApplication: EnvironmentApplication{EnvironmentID: first.ID, ExpectedRevision: first.MutationRevision, DefinitionRevision: first.AppliedDefinitionRevision, Public: new(true)}, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if changed.Services[0].ServiceID != endpoint.ServiceID || changed.Services[0].Hostname != endpoint.Hostname || changed.Services[0].Port != endpoint.Port || !changed.Services[0].Public {
		t.Fatal("reachability changed endpoint identity")
	}
	// a newly available friendly name receives new IDs, never the old namespace.
	request.IdempotencyKey = "new-production"
	replacement, err := d.CreateEnvironment(t.Context(), request)
	if err != nil || replacement.ID == first.ID || replacement.Services[0].ServiceID == endpoint.ServiceID || replacement.Services[0].Hostname == endpoint.Hostname {
		t.Fatal("friendly name adopted existing authority", err)
	}
	before := privateOwnershipSnapshot(t, d)
	request.IdempotencyKey = "colliding-production"
	request.Targets = EnvironmentTargets{"orders": {Address: "conflicting.internal:5432"}}
	if _, err := d.CreateEnvironment(t.Context(), request); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("duplicate active selector accepted", err)
	}
	if !reflect.DeepEqual(before, privateOwnershipSnapshot(t, d)) {
		t.Fatal("failed selector claim partially committed")
	}
}

func TestIntegrationManagedProjectLabelCollision(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "managed_project_collision")
	r := retainedEnvironmentProject(t, d, now)
	definition := ServiceDefinition{Services: map[string]ServiceDefinitionService{"orders": {Protocol: "postgres"}}}
	if _, err := d.CreateServiceDefinition(t.Context(), CreateServiceDefinitionRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint, ProjectLabel: "storefront", ActorID: r.ActorID, Definition: definition, Now: now}); err != nil {
		t.Fatal(err)
	}
	first, err := retainedNamespaceClaim(t, d, r, "production", "", now)
	if err != nil {
		t.Fatal(err)
	}
	other := r
	other.ProjectKey = "another-source"
	other.SourceFingerprint = strings.Repeat("b", 64)
	if _, err := d.CreateServiceDefinition(t.Context(), CreateServiceDefinitionRequest{TeamID: r.TeamID, ProjectKey: other.ProjectKey, SourceFingerprint: other.SourceFingerprint, ProjectLabel: "storefront", ActorID: r.ActorID, Definition: definition, Now: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := retainedNamespaceClaim(t, d, other, "production", "", now); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("another source adopted reserved namespace", err)
	}
	var active bool
	if err := d.pool.QueryRow(t.Context(), `SELECT deleted_at IS NULL FROM control.project_publisher_groups WHERE id=$1`, first).Scan(&active); err != nil || !active {
		t.Fatal("collision retired existing owner", err)
	}
}
