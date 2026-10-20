package controlstate

import (
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/tcpport"
)

func TestIntegrationManagedServicePortInventory(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "managed_ports")
	ctx := t.Context()
	metrics := observability.New("control")
	assertCapacity := func(configured, claimed, quarantined, available int) {
		t.Helper()
		if err := d.RefreshPortPoolMetrics(ctx, metrics); err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		metrics.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
		for state, value := range map[string]int{"configured": configured, "claimed": claimed, "quarantined": quarantined, "available": available} {
			want := fmt.Sprintf("tnl_control_tcp_port_pool_ports{tnl_ingress_pool=%q,tnl_state=%q} %d", PrimaryIngressPoolID, state, value)
			if !strings.Contains(w.Body.String(), want) {
				t.Errorf("missing %s", want)
			}
		}
	}
	if err := d.ConfigureIngressServicePorts(ctx, PrimaryIngressPoolID, []tcpport.Range{{First: 25443, Last: 25443}}); err != nil {
		t.Fatal(err)
	}
	assertCapacity(1, 0, 0, 1)
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{Publishers: map[string]ProjectPublisherGroup{"production": {}}, Services: map[string]ProjectServiceConfiguration{
		"api": {Publisher: "production", Target: "localhost:3000"},
	}}
	first, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil || first.Services[0].Port != 25443 {
		t.Fatal("allocation ignored pool inventory", first, err)
	}
	assertCapacity(1, 1, 0, 0)
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
	assertCapacity(2, 1, 1, 0)
}
