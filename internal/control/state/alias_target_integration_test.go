package state

import (
	"bytes"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
)

func TestIntegrationSavedAliasTargetStaysLocalThroughPolicyUpdates(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "service_app_target")
	actor := oidcRouteRequest(t, d, now)
	declaration := ProjectServiceConfiguration{Target: "app"}
	service, err := d.CreateServiceAt(t.Context(), actor.TeamID, actor.ActingIdentityID, "web", "app",
		ServicePlacement{}, now, ServiceMetadata{}, &declaration)
	if err != nil {
		t.Fatal(err)
	}
	declaration.HTTP = &config.HTTPService{Access: &config.Access{Mode: "restricted", IP: []string{"192.0.2.10/32"}}}
	updated, err := d.ConfigureService(t.Context(), service.ID, actor.ActingIdentityID, service.ServiceMetadata,
		&declaration, ServiceUpdateConditions{}, now.Add(time.Second))
	if err != nil || updated.TrustRevision != service.TrustRevision || updated.Endpoint.Hostname != service.Endpoint.Hostname {
		t.Fatal("policy update changed target trust or endpoint", err)
	}
	loaded, _, err := d.GetServiceConfiguration(t.Context(), service.ID, actor.ActingIdentityID)
	if err != nil || loaded.Target != "app" {
		t.Fatal("app-owned target was replaced by a server address", err)
	}
	var ciphertext []byte
	if err := d.pool.QueryRow(t.Context(), `SELECT configuration_ciphertext FROM control.services WHERE id=$1`, service.ID).Scan(&ciphertext); err != nil || bytes.Contains(ciphertext, []byte("192.0.2.10")) {
		t.Fatal("configuration policy was not encrypted", err)
	}
}
