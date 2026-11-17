package state

import (
	"errors"
	"testing"
	"time"
)

func TestIntegrationPublicURLPurposeSurvivesReadAndIsNotRelabeledByRetry(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "service_intent")
	actor := oidcRouteRequest(t, d, now)
	declaration := ProjectServiceConfiguration{Target: "localhost:3000", Protocol: "http"}
	service, err := d.CreateServiceAt(t.Context(), actor.TeamID, actor.ActingIdentityID, "web", "intent",
		ServicePlacement{}, now, ServiceMetadata{}, &declaration)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*ProjectServiceConfiguration){
		func(c *ProjectServiceConfiguration) { c.Protocol = "tcp" },
		func(c *ProjectServiceConfiguration) { c.Ephemeral = true },
		func(c *ProjectServiceConfiguration) { c.Public = new(true) },
	} {
		changed := declaration
		change(&changed)
		if _, err := d.CreateServiceAt(t.Context(), actor.TeamID, actor.ActingIdentityID, "web", "intent",
			ServicePlacement{}, now.Add(time.Second), ServiceMetadata{}, &changed); !errors.Is(err, ErrServiceConflict) {
			t.Fatal("create retry changed the service intent", err)
		}
	}
	replayed, err := d.CreateServiceAt(t.Context(), actor.TeamID, actor.ActingIdentityID, "web", "intent",
		ServicePlacement{}, now.Add(time.Second), ServiceMetadata{}, &declaration)
	if err != nil || replayed.ID != service.ID || replayed.Protocol != "http" || replayed.Ephemeral || replayed.Endpoint.Public {
		t.Fatal("create retry changed the saved service", err)
	}
}
