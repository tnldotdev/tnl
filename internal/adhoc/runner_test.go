package adhoc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestRunCleansAllocatedURLWhenRegistrationCannotContinue(t *testing.T) {
	credential, _, _, err := credentials.NewEphemeralCredential()
	if err != nil {
		t.Fatal(err)
	}
	invocation, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		t.Fatal(err)
	}
	var allocations, deletions atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+credential.String() {
			http.Error(w, "missing scoped credential", http.StatusUnauthorized)
			return
		}
		switch r.Method + " " + r.URL.Path {
		case "POST /v1/ephemeral-public-urls":
			allocations.Add(1)
			var body controlv1.AllocateEphemeralPublicURLRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.InvocationId != invocation || body.Target != "http://127.0.0.1:3000" ||
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
			deletions.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	registrationErr := errors.New("registration is no longer current")
	err = Run(context.Background(), Options{ControlURL: server.URL, HTTPClient: server.Client(), State: &clientstate.Store{},
		Credential: credential, InvocationID: invocation, Target: "http://127.0.0.1:3000",
		Limits: publisher.ApplicationLimits{Requests: 1}, OnAllocated: func(_ controlv1.PublicURL) error { return registrationErr },
	})
	if !errors.Is(err, registrationErr) || allocations.Load() != 1 || deletions.Load() != 1 {
		t.Fatalf("ad-hoc registration failed to clean its URL: error = %v, allocations = %d, deletions = %d", err, allocations.Load(), deletions.Load())
	}
}

func TestRunRejectsInvalidLimitsBeforeAllocating(t *testing.T) {
	credential, _, _, err := credentials.NewEphemeralCredential()
	if err != nil {
		t.Fatal(err)
	}
	invocation, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		t.Fatal(err)
	}
	err = Run(t.Context(), Options{ControlURL: "https://control.example.test", State: &clientstate.Store{},
		Credential: credential, InvocationID: invocation, Target: "http://127.0.0.1:3000",
		Limits: publisher.ApplicationLimits{RateRequests: 1, RatePer: -time.Second},
	})
	if err == nil {
		t.Fatal("invalid rate was accepted before publication")
	}
}
