package routeclient

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestNewRequiresDependencies(t *testing.T) {
	control, err := controlclient.New("https://control.example", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(nil); err == nil {
		t.Fatal("New accepted a nil control client")
	}
	if _, err := New(control); err != nil {
		t.Fatal(err)
	}
}

func TestCanonicalizeIPPrefixesPreservesOmission(t *testing.T) {
	if value, err := canonicalizeIPPrefixes(nil); err != nil || value != nil {
		t.Fatalf("nil prefixes = %v, %v", value, err)
	}
	values := []string{"192.0.2.4/24"}
	canonical, err := canonicalizeIPPrefixes(&values)
	if err != nil {
		t.Fatal(err)
	}
	if canonical == nil || len(*canonical) != 1 || (*canonical)[0] != "192.0.2.0/24" {
		t.Fatalf("canonical prefixes = %#v", canonical)
	}
	duplicates := []string{"192.0.2.4/24", "192.0.2.0/24"}
	if _, err := canonicalizeIPPrefixes(&duplicates); err == nil {
		t.Fatal("canonically duplicate prefixes were accepted")
	}
	invalid := []string{"not-an-address"}
	if _, err := canonicalizeIPPrefixes(&invalid); err == nil {
		t.Fatal("invalid prefix was accepted")
	}
}

func TestUpdateRouteCanonicalizesIPPrefixes(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var body controlv1.UpdateRouteRequest
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Error(err)
		} else if len(body.AllowedIpPrefixes) != 1 || body.AllowedIpPrefixes[0] != "192.0.2.0/24" {
			t.Errorf("update body = %#v", body)
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{
			"id":"route_1","team_id":"team_1","domain_id":"domain_1",
			"canonical_hostname":"demo.example","target":"http://127.0.0.1:3000",
			"route_scope":"member","policy_revision":1,"lifecycle_state":"enabled",
			"next_route_version":1,"ephemeral":false,
			"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"
		}`))
	}))
	defer server.Close()
	control, err := controlclient.New(server.URL, server.Client(), "access")
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(control)
	if err != nil {
		t.Fatal(err)
	}
	prefixes := []string{"192.0.2.9/24"}
	if _, err := client.UpdateRoute(t.Context(), "route_1", controlv1.UpdateRouteRequest{
		Target: "http://127.0.0.1:3000", AllowedIpPrefixes: prefixes,
	}); err != nil {
		t.Fatal(err)
	}
}
