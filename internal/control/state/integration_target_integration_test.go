package state

import (
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
)

func TestIntegrationHandlerBackedPublicURLTargets(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "service_target")
	actor := oidcRouteRequest(t, d, now)
	for _, target := range []string{"", "invalid"} {
		if _, err := d.CreateServiceAt(t.Context(), actor.TeamID, actor.ActingIdentityID, "invalid", "invalid",
			ServicePlacement{}, now, ServiceMetadata{}, &ProjectServiceConfiguration{Target: target}); !errors.Is(err, ErrProjectConfigurationInvalid) {
			t.Fatal("invalid service target accepted", target, err)
		}
	}
	declaration := ProjectServiceConfiguration{Target: "localhost:3000"}
	service, err := d.CreateServiceAt(t.Context(), actor.TeamID, actor.ActingIdentityID, "web", "target",
		ServicePlacement{}, now, ServiceMetadata{}, &declaration)
	if err != nil {
		t.Fatal(err)
	}
	for _, prefixes := range [][]string{{"192.0.2.10/32"}, {}} {
		declaration.HTTP = &config.HTTPService{Access: &config.Access{Mode: "restricted", IP: prefixes}}
		if _, err := d.ConfigureService(t.Context(), service.ID, actor.ActingIdentityID, service.ServiceMetadata,
			&declaration, ServiceUpdateConditions{UnconditionalConfiguration: true}, now.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		loaded, _, err := d.GetServiceConfiguration(t.Context(), service.ID, actor.ActingIdentityID)
		if err != nil || loaded.Target != "localhost:3000" || len(loaded.HTTP.Access.IP) != len(prefixes) {
			t.Fatal("policy update changed the publisher's saved target", err)
		}
	}
}
