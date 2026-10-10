package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestScopedPublishingUsesCredentialOnlyForItsURLAndRun(t *testing.T) {
	requests := make([]string, 0, 2)
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer tnl_url_example" {
			http.Error(response, "missing scoped credential", http.StatusUnauthorized)
			return
		}
		requests = append(requests, request.Method+" "+request.URL.Path)
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1/publish-credentials/current":
			_ = json.NewEncoder(response).Encode(controlv1.PublicURL{Id: "public_url_1", TeamId: "team_1", CanonicalHostname: "app.example"})
		case "/v1/public-urls/public_url_1/publish-runs":
			response.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(response).Encode(controlv1.PublishRunSetup{})
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(server.Close)
	client, err := controlclient.New(server.URL, server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	control := &scopedPublishControl{Client: client, credential: credentials.PublicURLPublishCredential("tnl_url_example"), urlID: "public_url_1"}
	route, err := control.GetPublicURLByHostname(t.Context(), "team_1", "app.example")
	if err != nil || route.Id != "public_url_1" {
		t.Fatalf("bound route = %#v, %v", route, err)
	}
	if _, err := control.GetPublicURLByHostname(t.Context(), "team_2", "app.example"); !errors.Is(err, controlclient.ErrStatusConflict) {
		t.Fatalf("cross-team lookup: %v", err)
	}
	if _, err := control.CreatePublishRun(t.Context(), "public_url_2", "attempt"); !errors.Is(err, controlclient.ErrStatusConflict) {
		t.Fatalf("cross-URL run: %v", err)
	}
	if _, err := control.CreatePublishRun(t.Context(), "public_url_1", "run-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := control.UpdatePublicURL(context.Background(), "public_url_1", controlv1.UpdatePublicURLRequest{}); !errors.Is(err, controlclient.ErrStatusConflict) {
		t.Fatalf("credential updated URL: %v", err)
	}
	if len(requests) != 3 || requests[0] != "GET /v1/publish-credentials/current" || requests[2] != "POST /v1/public-urls/public_url_1/publish-runs" {
		t.Fatalf("scoped requests = %v", requests)
	}
}

func TestScopedCredentialRejectionHasItsOwnAction(t *testing.T) {
	err := classifyScopedPublishError(controlclient.ErrUnauthenticated)
	if reason, _, ok := failure.Describe(err); !ok || reason != failure.PublishCredentialRejected || !errors.Is(err, controlclient.ErrUnauthenticated) {
		t.Fatalf("scoped authentication error = %v", err)
	}
}

func TestScopedPublishRequiresALocalTargetOnlyWhenTheURLHasNoSavedTarget(t *testing.T) {
	for _, test := range []struct {
		name, saved, selected, want string
		reason                      failure.Reason
	}{
		{name: "targetless local target", selected: "http://app:3000", want: "http://app:3000"},
		{name: "saved default", saved: "http://app:3000", want: "http://app:3000"},
		{name: "matching saved target", saved: "http://app:3000", selected: "http://app:3000", want: "http://app:3000"},
		{name: "missing local target", reason: failure.MissingTarget},
		{name: "mismatched saved target", saved: "http://app:3000", selected: "http://app:4000", reason: failure.PublishCredentialMismatch},
	} {
		t.Run(test.name, func(t *testing.T) {
			target, err := selectScopedPublishTarget(test.saved, test.selected)
			if target != test.want {
				t.Fatalf("target = %q, want %q", target, test.want)
			}
			if test.reason != "" {
				if reason, _, ok := failure.Describe(err); !ok || reason != test.reason {
					t.Fatalf("target selection error = %v, want %q", err, test.reason)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}
