package state

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestIntegrationAppliedPrivateLookupIsSourceBound(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "applied_private_lookup")
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"production": {}, "staging": {}}, Services: map[string]ProjectServiceConfiguration{
		"orders": {PublisherGroup: "production", Name: "database", Protocol: "postgres", Target: "do-not-return.internal:5432"},
		"other":  {PublisherGroup: "staging", Name: "database", Protocol: "postgres", Target: "other.internal:5432"},
		"local":  {Protocol: "http", Target: "app"},
	}}
	applied, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	id := ""
	for _, service := range applied.Services {
		if service.Service == "orders" {
			id = service.ServiceID
		}
	}
	visitor := finalVisitorIdentity(t, d, now, "applied-visitor@example.test")
	grant, err := d.CreateServiceGrant(t.Context(), id, r.ActorID, "applied-visitor", "identity", visitor, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	request := GetProjectServiceRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint, Service: "orders", IdentityID: visitor, Now: now}
	service, err := d.GetProjectService(t.Context(), request)
	if err != nil || service.ID != id || service.Endpoint == nil {
		t.Fatal("visitor did not resolve its exact offline service", service, err)
	}
	encoded, err := json.Marshal(service)
	if err != nil || strings.Contains(string(encoded), "do-not-return.internal") {
		t.Fatal("visitor metadata returned a target", err)
	}
	if _, err = d.GetProjectConfiguration(t.Context(), r.TeamID, r.ProjectKey, visitor); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("visitor lookup granted manager access", err)
	}
	for _, mutate := range []func(*GetProjectServiceRequest){
		func(r *GetProjectServiceRequest) { r.SourceFingerprint = strings.Repeat("b", 64) },
		func(r *GetProjectServiceRequest) { r.ProjectKey = "another-source" },
		func(r *GetProjectServiceRequest) { r.Service = "database" },
		func(r *GetProjectServiceRequest) { r.Service = "other" },
		func(r *GetProjectServiceRequest) { r.Service = "local" },
	} {
		wrong := request
		mutate(&wrong)
		if _, err = d.GetProjectService(t.Context(), wrong); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("source or grant mismatch adopted another service", wrong, err)
		}
	}
	if err = d.RevokeServiceGrant(t.Context(), id, r.ActorID, grant.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err = d.GetProjectService(t.Context(), request); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("revoked visitor retained applied metadata access", err)
	}
}
