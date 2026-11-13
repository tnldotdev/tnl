package control

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestDeploymentPublisherClientCapturesEnrollmentAndExactScope(t *testing.T) {
	expires := time.Now().UTC().Add(time.Minute)
	revocations := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer selected-access" || r.URL.Query().Get("team_id") != "team-selected" {
			t.Error("deployment publisher request lost selected authority")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodPost:
			if r.URL.Path != "/v1/projects/shop/deployments/selected/publisher-enrollments" || r.Header.Get("Idempotency-Key") != "original-key" {
				t.Error("setup changed its exact selection or recovery key")
			}
			var body controlv1.CreateDeploymentPublisherEnrollmentRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Services) != 1 || body.Services[0] != "db" || body.MaxMembers == nil || *body.MaxMembers != 2 || body.ExpiresIn == nil || *body.ExpiresIn != 600 {
				t.Error("setup changed its original bounds or scope", err)
			}
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(controlv1.DeploymentPublisherEnrollment{EnrollmentId: "same-enrollment", EnrollmentKey: "same-secret", ExpiresAt: expires})
		case http.MethodGet:
			if r.URL.Path != "/v1/projects/shop/deployments/selected/publishers" || r.URL.Query().Get("after") != "previous" || r.URL.Query().Get("limit") != "1" {
				t.Error("publisher list changed selection or pagination")
			}
			_ = json.NewEncoder(w).Encode(controlv1.DeploymentPublisherPage{Publishers: []controlv1.DeploymentPublisher{}})
		case http.MethodDelete:
			revocations++
			if r.URL.Path != "/v1/projects/shop/deployments/selected/publishers/exact-publisher" {
				t.Error("revocation lost deployment ownership")
			}
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(403)
			_ = json.NewEncoder(w).Encode(controlv1.Problem{Type: "https://tnl.dev/p/forbidden", Title: "access denied", Status: 403, Code: controlv1.Forbidden})
		default:
			t.Error("unexpected request")
		}
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client(), "selected-access")
	if err != nil {
		t.Fatal(err)
	}
	members, seconds := 2, 600
	for range 2 {
		enrollment, err := client.CreateDeploymentPublisherEnrollment(t.Context(), "team-selected", "shop", "selected", "original-key", controlv1.CreateDeploymentPublisherEnrollmentRequest{Services: []string{"db"}, MaxMembers: &members, ExpiresIn: &seconds})
		if err != nil || enrollment.EnrollmentKey != "same-secret" || !enrollment.ExpiresAt.Equal(expires) {
			t.Fatal("setup recovery changed its secret or deadline", err)
		}
	}
	if _, err := client.ListDeploymentPublishers(t.Context(), "team-selected", "shop", "selected", "previous", 1); err != nil {
		t.Fatal(err)
	}
	err = client.RevokeDeploymentPublisher(t.Context(), "team-selected", "shop", "selected", "exact-publisher")
	var problem *ProblemError
	if !errors.As(err, &problem) || problem.Status != http.StatusForbidden || revocations != 1 {
		t.Fatal("denied scoped revocation was changed or retried", err)
	}
}
