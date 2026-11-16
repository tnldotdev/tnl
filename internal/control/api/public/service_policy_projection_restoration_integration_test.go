package public

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"testing"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationServiceRestoredDualStackUpdateAndPostQuantumListProjection(t *testing.T) {
	f := newRestoredServiceHTTP(t)
	body := fmt.Sprintf(`{"protocol":"http","publisher_pool":false,"expected_trust_revision":%q,
		"configuration":{"target":"localhost:4000","require_post_quantum":true,
		"http":{"access":{"mode":"restricted","ip":["2001:db8::9/64","192.0.2.9/24"]}}}}`, fmt.Sprint(f.service.TrustRevision))
	status, wire, _ := f.call(f.owner, http.MethodPut, "/v1/services/"+f.service.ID, "", []byte(body))
	var updated controlv1.Service
	if status != 200 || json.Unmarshal(wire, &updated) != nil || updated.Id != f.service.ID || !updated.RequirePostQuantum {
		t.Fatalf("dual-stack policy update lost exact service or PQ: status=%d body=%s", status, wire)
	}
	saved, _, err := f.database.GetServiceConfiguration(t.Context(), f.service.ID, f.actor)
	if err != nil || saved == nil || saved.Target != "localhost:4000" ||
		saved.RequirePostQuantum == nil || !*saved.RequirePostQuantum || saved.HTTP == nil || saved.HTTP.Access == nil ||
		!reflect.DeepEqual(saved.HTTP.Access.IP, []string{"192.0.2.0/24", "2001:db8::/64"}) {
		t.Fatal("HTTP update did not persist exact canonical dual-stack and PQ intent", err)
	}
	status, wire, _ = f.call(f.owner, http.MethodGet, "/v1/services?team_id="+f.team, "", nil)
	var page controlv1.ServicePage
	if status != 200 || json.Unmarshal(wire, &page) != nil || len(page.Services) != 1 ||
		page.Services[0].Id != f.service.ID {
		t.Fatal("management list lost the configured service")
	}
	var fields map[string]json.RawMessage
	var services []map[string]json.RawMessage
	var postQuantum bool
	if json.Unmarshal(wire, &fields) != nil || json.Unmarshal(fields["services"], &services) != nil ||
		len(services) != 1 || json.Unmarshal(services[0]["require_post_quantum"], &postQuantum) != nil || !postQuantum {
		t.Fatal("management list lost saved PQ policy")
	}
	status, wire, _ = f.call(f.owner, http.MethodGet, "/v1/visitor/services", "", nil)
	postQuantum = false
	if status != http.StatusOK || json.Unmarshal(wire, &fields) != nil || json.Unmarshal(fields["services"], &services) != nil ||
		len(services) != 1 || json.Unmarshal(services[0]["require_post_quantum"], &postQuantum) != nil || !postQuantum {
		t.Fatalf("visitor list lost saved PQ policy: status=%d body=%s", status, wire)
	}
}
