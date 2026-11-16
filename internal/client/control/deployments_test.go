package control

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestDeploymentClientRetainsIdempotencyAndStrongConditions(t *testing.T) {
	mutations := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer selected-access" || r.URL.Query().Get("team_id") != "team-selected" {
			t.Error("deployment request lost selected authentication or team")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodPost:
			if r.URL.Path != "/v1/projects/shop/deployments" || r.Header.Get("Idempotency-Key") != "original-key" {
				t.Error("creation changed its recovery key or project")
			}
			var body controlv1.CreateDeploymentRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name != "customer" || body.Targets["db"].Address != "orders.internal:5432" {
				t.Error("creation changed its original intent", err)
			}
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(controlv1.Deployment{Id: "same-deployment"})
		case http.MethodGet:
			if r.URL.Path != "/v1/projects/shop/deployments" || r.URL.Query().Get("limit") != "1" || r.URL.Query().Get("after") != "previous" {
				t.Error("list changed its captured pagination")
			}
			_ = json.NewEncoder(w).Encode(controlv1.DeploymentPage{Deployments: []controlv1.Deployment{}})
		case http.MethodPatch, http.MethodDelete:
			mutations++
			if r.URL.Path != "/v1/projects/shop/deployments/selected" || r.Header.Get("If-Match") != `"7"` {
				t.Error("mutation lost exact selection or strong condition")
			}
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(412)
			_ = json.NewEncoder(w).Encode(controlv1.Problem{Type: "https://tnl.dev/p/conflict", Title: "deployment changed", Status: 412, Code: controlv1.Conflict})
		default:
			t.Error("unexpected deployment request")
		}
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client(), "selected-access")
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		created, err := client.CreateDeployment(t.Context(), "team-selected", "shop", "original-key", controlv1.CreateDeploymentRequest{Name: "customer", Targets: map[string]controlv1.DeploymentTarget{"db": {Address: "orders.internal:5432"}}})
		if err != nil || created.Id != "same-deployment" {
			t.Fatal("lost creation response could not use original request", err)
		}
	}
	if _, err = client.ListDeployments(t.Context(), "team-selected", "shop", "previous", 1); err != nil {
		t.Fatal(err)
	}
	if _, err = client.UpdateDeployment(t.Context(), "team-selected", "shop", "selected", 7, controlv1.UpdateDeploymentRequest{Targets: map[string]controlv1.DeploymentTarget{"db": {Address: "replacement.internal:5432"}}}); !errors.Is(err, ErrStatusConflict) {
		t.Fatal("stale update lost its conflict", err)
	}
	if err = client.DeleteDeployment(t.Context(), "team-selected", "shop", "selected", 7); !errors.Is(err, ErrStatusConflict) {
		t.Fatal("stale deletion lost its conflict", err)
	}
	if mutations != 2 {
		t.Fatal("stale mutation was retried without a fresh user decision")
	}
}
