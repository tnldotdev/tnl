package state

import (
	"errors"
	"fmt"
	"testing"
)

func TestIntegrationAuthorizedRouteHostnameLookup(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "service_lookup")
	actor := oidcRouteRequest(t, d, now)
	var target ServiceRecord
	for index := range 105 {
		name := fmt.Sprintf("lookup-%03d", index)
		var err error
		target, err = d.CreateServiceAt(t.Context(), actor.TeamID, actor.ActingIdentityID, name, name,
			ServicePlacement{}, now, ServiceMetadata{}, &ProjectServiceConfiguration{Target: "localhost:3000"})
		if err != nil {
			t.Fatal(err)
		}
	}
	page, next, err := d.ListServices(t.Context(), actor.TeamID, actor.ActingIdentityID, "")
	if err != nil || len(page) != 100 || next == "" {
		t.Fatal("service pagination changed", len(page), next, err)
	}
	last, cursor, err := d.ListServices(t.Context(), actor.TeamID, actor.ActingIdentityID, next)
	if err != nil || len(last) != 5 || cursor != "" {
		t.Fatal("service pagination lost the final page", len(last), cursor, err)
	}
	got, err := d.GetService(t.Context(), target.ID, actor.ActingIdentityID)
	if err != nil || got.ID != target.ID || got.Endpoint.Hostname != target.Endpoint.Hostname || !got.Enabled {
		t.Fatal("exact lookup lost saved service identity", err)
	}
	if _, err := d.GetService(t.Context(), target.ID, "identity_other"); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("another identity read the service", err)
	}
	if _, err := d.SetServiceEnabled(t.Context(), target.ID, actor.ActingIdentityID, false, now); err != nil {
		t.Fatal(err)
	}
	got, err = d.GetService(t.Context(), target.ID, actor.ActingIdentityID)
	if err != nil || got.Enabled {
		t.Fatal("suspended service disappeared from management", err)
	}
	if err := d.DeleteService(t.Context(), target.ID, actor.ActingIdentityID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetService(t.Context(), target.ID, actor.ActingIdentityID); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("deleted service remained readable", err)
	}
}
