package state

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestIntegrationAppliedPrivateLookupIsSourceBound(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "applied_private_lookup")
	f := newRetainedVisitorFixture(t, d, now, retainedGitHubTrust(), 3600, false)
	r := f.project
	other, _ := retainedServiceEnvironment(t, d, r, "staging", map[string]EnvironmentServicePublication{"api": {Protocol: "http", Target: "do-not-return.internal:3000"}})
	visitor := finalVisitorIdentity(t, d, now, "applied-visitor@example.test")
	id := ""
	for _, service := range f.environment.Services {
		if service.Service == "api" {
			id = service.ServiceID
		}
	}
	grant, err := d.CreateServiceGrant(t.Context(), id, r.ActorID, "applied-visitor", "identity", visitor, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	inventory, _, err := d.ListAvailableServices(t.Context(), visitor, "", now)
	if err != nil || len(inventory) != 1 || inventory[0].ID != id || inventory[0].Endpoint == nil {
		t.Fatal("visitor did not resolve exact offline service", err)
	}
	encoded, err := json.Marshal(inventory)
	if err != nil || strings.Contains(string(encoded), "internal:") {
		t.Fatal("visitor metadata returned a target", err)
	}
	if _, err := d.GetEnvironment(t.Context(), r.TeamID, r.ProjectKey, f.environment.ID, visitor); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("visitor lookup granted manager access", err)
	}
	request, key := retainedVisitorPreparation(t, f, now)
	request.Services = map[string]string{"api": "http"}
	signRetainedVisitorPreparation(&request, key)
	resolved, err := d.PrepareEnvironmentVisitor(t.Context(), request, now)
	if err != nil || resolved.Services["api"].ID != id {
		t.Fatal("permission did not select saved environment", err)
	}
	for _, mutate := range []func(*PrepareEnvironmentVisitorRequest){
		func(r *PrepareEnvironmentVisitorRequest) { r.ProjectKey = "another-source" },
		func(r *PrepareEnvironmentVisitorRequest) { r.EnvironmentID = other.ID },
		func(r *PrepareEnvironmentVisitorRequest) { r.Services = map[string]string{"database": "http"} },
		func(r *PrepareEnvironmentVisitorRequest) { r.Services = map[string]string{"other": "http"} },
		func(r *PrepareEnvironmentVisitorRequest) { r.Services = map[string]string{"local": "http"} },
	} {
		wrong := request
		mutate(&wrong)
		wrong.Nonce = rand.Text()
		signRetainedVisitorPreparation(&wrong, key)
		if _, err := d.PrepareEnvironmentVisitor(t.Context(), wrong, now); !errors.Is(err, ErrMachineDenied) {
			t.Fatal("project/environment/service mismatch adopted another service", err)
		}
	}
	// immutable provenance remains checked at the project owner; it is not a
	// caller-supplied visitor selector or a way to bypass an exact permission.
	if _, err := d.CreateServiceDefinition(t.Context(), CreateServiceDefinitionRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: strings.Repeat("b", 64), ActorID: r.ActorID, Definition: ServiceDefinition{Services: map[string]ServiceDefinitionService{"api": {Protocol: "http"}}}, Now: now}); !errors.Is(err, ErrProjectSourceConflict) {
		t.Fatal("source mismatch adopted saved project", err)
	}
	if err := d.RevokeServiceGrant(t.Context(), id, r.ActorID, grant.ID, now); err != nil {
		t.Fatal(err)
	}
	inventory, _, err = d.ListAvailableServices(t.Context(), visitor, "", now)
	if err != nil || len(inventory) != 0 {
		t.Fatal("revoked human grant retained inventory", err)
	}
	if err := d.RevokeEnvironmentVisitorPermission(t.Context(), r.TeamID, f.permission.ID, r.ActorID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.PrepareEnvironmentVisitor(t.Context(), request, now); !errors.Is(err, ErrMachineDenied) {
		t.Fatal("revoked visitor permission retained resolution", err)
	}
}
