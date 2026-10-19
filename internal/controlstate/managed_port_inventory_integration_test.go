package controlstate

import (
	"errors"
	"testing"

	"github.com/tnldotdev/tnl/internal/tcpport"
)

func TestIntegrationManagedServicePortInventory(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "managed_ports")
	ctx := t.Context()
	if err := d.ConfigureIngressServicePorts(ctx, PrimaryIngressPoolID, []tcpport.Range{{First: 25443, Last: 25443}}); err != nil {
		t.Fatal(err)
	}
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{Publishers: map[string]ProjectPublisherGroup{"production": {}}, Services: map[string]ProjectServiceConfiguration{
		"api": {Publisher: "production", Target: "localhost:3000"},
	}}
	first, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil || first.Services[0].Port != 25443 {
		t.Fatal("allocation ignored pool inventory", first, err)
	}
	if err = d.ConfigureIngressServicePorts(ctx, PrimaryIngressPoolID, []tcpport.Range{{First: 25000, Last: 25001}}); !errors.Is(err, ErrManagedPortsInUse) {
		t.Fatal("removed a held port", err)
	}
	r.ExpectedRevision = first.Revision
	r.Configuration.Services["orders"] = ProjectServiceConfiguration{Publisher: "production", Protocol: "postgres", Target: "localhost:5432"}
	if _, err = d.ApplyProjectConfiguration(ctx, r); !errors.Is(err, ErrManagedPortsExhausted) {
		t.Fatal("exhaustion lost its classification", err)
	}
	current, err := d.GetProjectConfiguration(ctx, r.TeamID, r.ProjectKey, r.ActorID)
	if err != nil || current.Revision != first.Revision || len(current.Services) != 1 {
		t.Fatal("exhausted allocation partially applied", current, err)
	}
	if err = d.ConfigureIngressServicePorts(ctx, PrimaryIngressPoolID, []tcpport.Range{{First: 25443, Last: 25443}, {First: 30000, Last: 30000}}); err != nil {
		t.Fatal(err)
	}
	expanded, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil || expanded.Services[0].Port != 25443 || expanded.Services[1].Port != 30000 {
		t.Fatal("expansion changed an existing profile", expanded, err)
	}
	r.ExpectedRevision = expanded.Revision
	delete(r.Configuration.Services, "orders")
	if _, err = d.ApplyProjectConfiguration(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err = d.ConfigureIngressServicePorts(ctx, PrimaryIngressPoolID, []tcpport.Range{{First: 25443, Last: 25443}}); !errors.Is(err, ErrManagedPortsInUse) {
		t.Fatal("removed a quarantined port", err)
	}
}
