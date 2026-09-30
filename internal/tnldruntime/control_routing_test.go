package tnldruntime

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/ingressapi"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/relayapi"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/internal/tnldconfig"
)

type unusedIngressStore struct{ ingressapi.Store }
type unusedRelayStore struct{ relayapi.Store }

func TestPublicAPISurfacesFollowRegisteredRoutes(t *testing.T) {
	for _, test := range []struct {
		name, authorityEndpoint string
		identityStatus          int
		identitySurface         string
		identityOperation       string
	}{
		{name: "built-in authority", identityStatus: http.StatusUnauthorized, identitySurface: "authority", identityOperation: "GET /v1/identity"},
		{name: "external authority", authorityEndpoint: "https://authority.example.test", identityStatus: http.StatusNotFound, identitySurface: "control", identityOperation: "unmatched"},
	} {
		t.Run(test.name, func(t *testing.T) {
			metrics := observability.New("control")
			handler, err := newPublicAPIHandler(tnldconfig.Config{Role: tnldconfig.RoleControl, AuthorityEndpoint: test.authorityEndpoint},
				time.Now(), &http.Client{}, nil, metrics, &daemon{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, check := range []struct {
				method, path, surface string
				status                int
			}{
				{http.MethodGet, "/v1/health", "control", http.StatusOK},
				{http.MethodGet, "/v1/identity", test.identitySurface, test.identityStatus},
				{http.MethodPatch, "/v1/identity", test.identitySurface, http.StatusNotFound},
				{http.MethodGet, "/v1/teams-unknown", "control", http.StatusNotFound},
			} {
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, httptest.NewRequest(check.method, check.path, nil))
				if response.Code != check.status {
					t.Fatalf("%s %s status = %d, want %d", check.method, check.path, response.Code, check.status)
				}
			}
			response := httptest.NewRecorder()
			metrics.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
			if !strings.Contains(response.Body.String(), `operation="`+test.identityOperation+`",outcome="client_error",surface="`+test.identitySurface+`"`) {
				t.Fatal("identity surface missing from metrics")
			}
		})
	}
}

func TestPrivateAPISurfacesFollowTheirRouters(t *testing.T) {
	secrets, err := serviceapi.NewBearerSecrets("cluster-secret-012345678901234567890123", "")
	if err != nil {
		t.Fatal(err)
	}
	ingress, err := ingressapi.NewHandler(ingressapi.Config{Store: unusedIngressStore{}, ClusterSecrets: secrets, LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	relay, err := relayapi.NewHandler(relayapi.Config{Store: unusedRelayStore{}, ClusterSecrets: secrets, LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	metrics := observability.New("control")
	handler := privateControlHandler(ingress, relay, metrics)
	for _, test := range []struct {
		method, path, surface string
		status                int
	}{
		{http.MethodPost, "/internal/v1/ingresses/register", "private_ingress", http.StatusBadRequest},
		{http.MethodPost, "/internal/v1/relays/register", "private_relay", http.StatusBadRequest},
		{http.MethodGet, "/internal/v1/relays/register", "private_relay", http.StatusNotFound},
		{http.MethodGet, "/internal/v1/ingresses/unknown", "", http.StatusNotFound},
	} {
		request := httptest.NewRequest(test.method, test.path, strings.NewReader(`{}`))
		request.Header.Set("Authorization", "Bearer cluster-secret-012345678901234567890123")
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.status || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s %s = %d, %v; want %d and no-store", test.method, test.path, response.Code, response.Header(), test.status)
		}
	}
	unauthenticated := httptest.NewRecorder()
	handler.ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodGet, "/internal/v1/relays/register", nil))
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-method private request without a cluster secret = %d, want 401", unauthenticated.Code)
	}
	response := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	for _, test := range []struct{ operation, surface string }{
		{"POST /internal/v1/ingresses/register", "private_ingress"},
		{"POST /internal/v1/relays/register", "private_relay"},
	} {
		if !strings.Contains(response.Body.String(), `tnl_control_api_request_duration_seconds_count{operation="`+test.operation+`",outcome="client_error",surface="`+test.surface+`"}`) {
			t.Fatalf("private %s surface missing from completed request metrics", test.surface)
		}
	}
}
