package public

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationServiceRestoredManagementCursorUsesCurrentTeam(t *testing.T) {
	f := newRestoredServiceHTTP(t)
	other, err := f.database.CreateServiceAt(t.Context(), f.team, f.actor, "second", "second", controlstate.ServicePlacement{},
		time.Now(), controlstate.ServiceMetadata{Protocol: "http"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	status, wire, _ := f.call(f.owner, http.MethodGet, "/v1/services?team_id="+f.team, "", nil)
	var first controlv1.ServicePage
	if status != 200 || json.Unmarshal(wire, &first) != nil || len(first.Services) != 2 {
		t.Fatalf("current team inventory lost one of its two actual services: status=%d", status)
	}
	if first.Services[0].TeamId != f.team || first.Services[1].TeamId != f.team ||
		first.Services[0].Id == first.Services[1].Id ||
		first.Services[0].Id != f.service.ID && first.Services[0].Id != other.ID ||
		first.Services[1].Id != f.service.ID && first.Services[1].Id != other.ID {
		t.Fatal("team list returned a foreign or repeated service")
	}
	status, wire, _ = f.call(f.owner, http.MethodGet,
		"/v1/services?team_id="+f.team+"&cursor="+first.Services[0].Id, "", nil)
	var next controlv1.ServicePage
	if status != 200 || json.Unmarshal(wire, &next) != nil || len(next.Services) != 1 ||
		next.Services[0].Id != first.Services[1].Id {
		t.Fatalf("exact management cursor lost or repeated a service: status=%d", status)
	}
}

func TestIntegrationServiceRestoredTargetlessHTTPPolicyUpdate(t *testing.T) {
	f := newRestoredServiceHTTP(t)
	body := fmt.Sprintf(`{"team_id":%q,"name":"targetless","protocol":"http"}`, f.team)
	status, wire, _ := f.call(f.owner, http.MethodPost, "/v1/services", "targetless", []byte(body))
	var service controlv1.Service
	if status != 201 || json.Unmarshal(wire, &service) != nil || service.Protocol != "http" {
		t.Fatalf("targetless HTTP metadata creation status=%d", status)
	}
	// a full app-owned declaration defers its listener; it is not a target patch.
	body = fmt.Sprintf(`{"protocol":"http","publisher_pool":false,"expected_trust_revision":%q,
		"configuration":{"target":"app","http":{"access":{"mode":"anonymous","ip":["192.0.2.9/24"]}}}}`, fmt.Sprint(service.TrustRevision))
	status, wire, _ = f.call(f.owner, http.MethodPut, "/v1/services/"+service.Id, "", []byte(body))
	if status != 200 {
		t.Fatalf("saved HTTP service rejected its complete app-owned policy: status=%d body=%s", status, wire)
	}
	saved, _, err := f.database.GetServiceConfiguration(t.Context(), service.Id, f.actor)
	if err != nil || saved == nil || saved.Target != "app" || saved.HTTP == nil || saved.HTTP.Access == nil ||
		saved.HTTP.Access.Mode != "anonymous" || len(saved.HTTP.Access.IP) != 1 || saved.HTTP.Access.IP[0] != "192.0.2.0/24" {
		t.Fatal("app-owned HTTP update lost policy or invented a concrete listener", err)
	}
}
