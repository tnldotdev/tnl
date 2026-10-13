package adhoc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/publisherauth"
	"github.com/tnldotdev/tnl/internal/trafficlimits"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestRunCleansAllocatedURLWhenRegistrationCannotContinue(t *testing.T) {
	invocation, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		t.Fatal(err)
	}
	var allocations, deletions atomic.Int32
	access := "pta_" + strings.Repeat("a", 43)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "POST /v1/publisher/enrollments/redeem":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"client_id": "pub_0123456789abcdefghijkl", "key_id": "pik_0123456789abcdefghijkl",
				"grant_id": "pgr_0123456789abcdefghijkl", "team_id": "team_1",
				"kind": "namespace", "namespace": "example.test",
			})
		case "POST /v1/publisher/token":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": access, "token_type": "Bearer", "expires_in": 299, "scope": "pgr_0123456789abcdefghijkl",
			})
		case "POST /v1/ephemeral-public-urls":
			if r.Header.Get("Authorization") != "Bearer "+access {
				http.Error(w, "missing publisher grant", http.StatusUnauthorized)
				return
			}
			allocations.Add(1)
			var body controlv1.AllocateEphemeralPublicURLRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.InvocationId != invocation || body.Target != "http://app.internal:3000" ||
				body.Limits == nil || body.Limits.Requests == nil || *body.Limits.Requests != 1 {
				http.Error(w, "invalid allocation", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(controlv1.PublicURL{Id: "url_allocated", TeamId: "team_1", DomainId: "domain_1",
				CanonicalHostname: "eph-aaaaaaaaaaaaaaaaaaaaaaaaaa.example.test", Target: body.Target,
				Ephemeral: true, Purpose: controlv1.App, LifecycleState: controlv1.Enabled, PolicyRevision: 1})
		case "DELETE /v1/ephemeral-public-urls/url_allocated":
			if r.Header.Get("Authorization") != "Bearer "+access {
				http.Error(w, "missing publisher grant", http.StatusUnauthorized)
				return
			}
			deletions.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	control, err := controlclient.New(server.URL, server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	authority, err := authorityclient.New(server.URL, server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	owner, err := publisherauth.Redeem(t.Context(), control, authority, "one-use-key")
	if err != nil {
		t.Fatal(err)
	}
	registrationErr := errors.New("registration is no longer current")
	err = Run(context.Background(), Options{ControlURL: server.URL, State: &clientstate.Store{},
		Owner: owner, Namespace: publisherauth.Namespace{TeamID: "team_1", DomainID: "domain_1", Hostname: "example.test", Scope: controlv1.Shared},
		InvocationID: invocation, Target: "http://app.internal:3000",
		Limits: publisher.ApplicationLimits{Requests: 1}, OnAllocated: func(_ controlv1.PublicURL) error { return registrationErr },
	})
	if !errors.Is(err, registrationErr) || allocations.Load() != 1 || deletions.Load() != 1 {
		t.Fatalf("ad-hoc registration failed to clean its URL: error = %v, allocations = %d, deletions = %d", err, allocations.Load(), deletions.Load())
	}
}

func TestRunRejectsInvalidLimitsBeforeAllocating(t *testing.T) {
	invocation, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		t.Fatal(err)
	}
	err = Run(t.Context(), Options{ControlURL: "https://control.example.test", State: &clientstate.Store{},
		Owner: &publisherauth.Owner{}, InvocationID: invocation, Target: "http://127.0.0.1:3000",
		Limits: publisher.ApplicationLimits{RateRequests: 1, RatePer: -time.Second},
	})
	if err == nil {
		t.Fatal("invalid rate was accepted before publication")
	}
	invalid := -1
	err = Run(t.Context(), Options{ControlURL: "https://control.example.test", State: &clientstate.Store{},
		Owner: &publisherauth.Owner{}, InvocationID: invocation, Target: "http://127.0.0.1:3000",
		Traffic: trafficlimits.Selection{Connections: &invalid},
	})
	if err == nil {
		t.Fatal("invalid visitor connection limit was accepted before allocation")
	}
}
