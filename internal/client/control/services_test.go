package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestServiceRunUsesSeparatePersonPublisherAndRunCredentials(t *testing.T) {
	seen := map[string]int{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Method + " " + r.URL.Path
		seen[key]++
		w.Header().Set("Content-Type", "application/json")
		switch key {
		case "POST /v1/services":
			if r.Header.Get("Authorization") != "Bearer person-token" || r.Header.Get("Idempotency-Key") != "service-once" {
				t.Error("creating a service did not use the selected person")
			}
			var body controlv1.CreateServiceRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.TeamId != "team" || body.Name != "orders" {
				t.Error("service name or team changed")
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(controlv1.Service{Id: "svc_service", TeamId: "team", Name: "orders"})
		case "GET /v1/services":
			if r.Header.Get("Authorization") != "Bearer person-token" || r.URL.Query().Get("team_id") != "team" {
				t.Error("private inventory used publisher credentials")
			}
			_ = json.NewEncoder(w).Encode(controlv1.ServicePage{Services: []controlv1.Service{{Id: "svc_service", TeamId: "team", Name: "orders"}}})
		case "GET /v1/visitor/services":
			if r.Header.Get("Authorization") != "Bearer person-token" || r.URL.Query().Has("team_id") {
				t.Error("visitor inventory used publisher scope or selected an administrator team")
			}
			_ = json.NewEncoder(w).Encode(controlv1.ServicePage{Services: []controlv1.Service{{Id: "svc_service", TeamId: "team", Name: "orders"}}})
		case "POST /v1/services/svc_service/runs":
			if r.Header.Get("Authorization") != "Bearer publisher-token" || r.Header.Get("Idempotency-Key") != "one-run" {
				t.Error("prepare used a person or run credential")
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(controlv1.ServiceRunPreparation{ServiceId: "svc_service", ServiceRunId: "srun_one", RunNumber: 1})
		case "POST /v1/services/svc_service/runs/srun_one/start":
			if r.Header.Get("Authorization") != "Bearer publisher-token" {
				t.Error("key binding used a person or run credential")
			}
			var body controlv1.StartServiceRunJSONRequestBody
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.RunNumber != 1 {
				t.Error("prepared managed run changed")
			}
			_ = json.NewEncoder(w).Encode(controlv1.ServiceRunSetup{ServiceId: "svc_service", ServiceRunId: "srun_one", RunNumber: 1, RunToken: "run-token"})
		case "POST /v1/services/svc_service/runs/srun_one":
			if r.Header.Get("Authorization") != "Bearer run-token" {
				t.Error("heartbeat used a person or publisher credential")
			}
			_ = json.NewEncoder(w).Encode(controlv1.ServiceRunState{ServiceId: "svc_service", ServiceRunId: "srun_one", RunNumber: 1, PublisherExpiresAt: time.Now().Add(time.Minute)})
		case "DELETE /v1/services/svc_service/runs/srun_one":
			if r.Header.Get("Authorization") != "Bearer run-token" {
				t.Error("close used a person or publisher credential")
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected private request: %s", key)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client(), "person-token")
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	if _, err := client.CreateService(ctx, "team", "orders", "service-once"); err != nil {
		t.Fatal(err)
	}
	if services, err := client.ListServices(ctx, "team"); err != nil || len(services) != 1 {
		t.Fatalf("list service: %+v %v", services, err)
	}
	if services, err := client.ListAvailableServices(ctx); err != nil || len(services) != 1 {
		t.Fatalf("list available services: %+v %v", services, err)
	}
	if _, err := client.PrepareServiceRun(ctx, "svc_service", "one-run", "publisher-token", controlv1.ServiceRunDeclaration{Protocol: controlv1.Tcp, TrustRevision: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.StartServiceRun(ctx, "svc_service", "srun_one", "publisher-token", 1); err != nil {
		t.Fatal(err)
	}
	if _, err := client.HeartbeatServiceRun(ctx, "svc_service", "srun_one", credentials.ServiceRunToken("run-token")); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseServiceRun(ctx, "svc_service", "srun_one", credentials.ServiceRunToken("run-token")); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 7 {
		t.Fatalf("missing a private run boundary: %+v", seen)
	}
}
