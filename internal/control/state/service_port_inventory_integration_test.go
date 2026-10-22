package state

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/naming/tcpport"
	"github.com/tnldotdev/tnl/internal/observability"
)

func TestIntegrationServicePortInventory(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "service_ports")
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
	r.Configuration = ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"production": {}}, Services: map[string]ProjectServiceConfiguration{
		"api": {PublisherGroup: "production", Target: "localhost:3000"},
	}}
	first, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil || first.Services[0].Port != 25443 {
		t.Fatal("allocation ignored pool inventory", first, err)
	}
	assertCapacity(1, 1, 0, 0)
	if err = d.ConfigureIngressServicePorts(ctx, PrimaryIngressPoolID, []tcpport.Range{{First: 25000, Last: 25001}}); !errors.Is(err, ErrServicePortsInUse) {
		t.Fatal("removed a held port", err)
	}
	r.ExpectedRevision = first.Revision
	r.Configuration.Services["orders"] = ProjectServiceConfiguration{PublisherGroup: "production", Protocol: "postgres", Target: "localhost:5432"}
	if _, err = d.ApplyProjectConfiguration(ctx, r); !errors.Is(err, ErrServicePortsExhausted) {
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
	if err = d.ConfigureIngressServicePorts(ctx, PrimaryIngressPoolID, []tcpport.Range{{First: 25443, Last: 25443}}); !errors.Is(err, ErrServicePortsInUse) {
		t.Fatal("removed a quarantined port", err)
	}
	assertCapacity(2, 1, 1, 0)
	// a complete refresh removes a vanished pool, while failure cannot claim a
	// newer successful snapshot. scrape remains usable after the pool is closed.
	if _, err := d.pool.Exec(ctx, `INSERT INTO control.ingress_pools(id,state,created_at,updated_at) VALUES('temporary-pool','disabled',$1,$1)`, now); err != nil {
		t.Fatal(err)
	}
	if err := d.ConfigureIngressServicePorts(ctx, "temporary-pool", []tcpport.Range{{First: 32000, Last: 32000}}); err != nil {
		t.Fatal(err)
	}
	if err := d.RefreshPortPoolMetrics(ctx, metrics); err != nil {
		t.Fatal(err)
	}
	if _, err := d.pool.Exec(ctx, `DELETE FROM control.ingress_service_port_ranges WHERE ingress_pool_id='temporary-pool'`); err != nil {
		t.Fatal(err)
	}
	if err := d.RefreshPortPoolMetrics(ctx, metrics); err != nil {
		t.Fatal(err)
	}
	failed, cancel := context.WithCancel(ctx)
	cancel()
	if err := d.RefreshPortPoolMetrics(failed, metrics); err == nil {
		t.Fatal("canceled refresh succeeded")
	}
	d.pool.Close()
	w := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	if w.Code != 200 || strings.Contains(w.Body.String(), `tnl_ingress_pool="temporary-pool"`) || !strings.Contains(w.Body.String(), "tnl_control_tcp_port_pool_last_success_timestamp_seconds ") {
		t.Fatal("inventory freshness or disappeared pool incorrect", w.Body.String())
	}
}
