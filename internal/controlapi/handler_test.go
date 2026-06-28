package controlapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

const testLoginToken = "tnl_login_AAECAwQFBgcICQoLDA0ODw.EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8"

func TestHealthAndReadiness(t *testing.T) {
	cfg := Config{ServerDomain: "example.com", ManagedDeploymentDomain: "example.com"}
	ready := new(bool)
	handler := NewHandler(cfg, nil, func(context.Context) error {
		if !*ready {
			return errors.New("database unavailable")
		}
		return nil
	})

	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/v1/health", nil))
	if health.Code != http.StatusOK {
		t.Fatalf("health status = %d", health.Code)
	}
	var healthBody controlv1.HealthResponse
	if err := json.Unmarshal(health.Body.Bytes(), &healthBody); err != nil || healthBody.Status != controlv1.HealthResponseStatusOk {
		t.Fatalf("health = %#v, %v", healthBody, err)
	}

	readiness := httptest.NewRecorder()
	handler.ServeHTTP(readiness, httptest.NewRequest(http.MethodGet, "/v1/ready", nil))
	if readiness.Code != http.StatusServiceUnavailable {
		t.Fatalf("unready status = %d", readiness.Code)
	}
	*ready = true
	readiness = httptest.NewRecorder()
	handler.ServeHTTP(readiness, httptest.NewRequest(http.MethodGet, "/v1/ready", nil))
	if readiness.Code != http.StatusOK {
		t.Fatalf("ready status = %d", readiness.Code)
	}
}

func TestUnavailableOperationsFailClosed(t *testing.T) {
	handler := NewHandler(Config{ServerDomain: "example.com", ManagedDeploymentDomain: "example.com"}, nil, func(context.Context) error { return nil })
	for _, path := range []string{"/v1/admin/status", "/v1/teams", "/not-an-api"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusServiceUnavailable && path != "/v1/teams" {
			t.Fatalf("%s status = %d", path, response.Code)
		}
		if path == "/v1/teams" && response.Code != http.StatusUnauthorized {
			t.Fatalf("%s status = %d", path, response.Code)
		}
	}
}

func TestPublisherConnectionResponsesExposeClosedSlotsAsReplacing(t *testing.T) {
	var connections [2]controlstate.PublisherConnectionPlan
	for slot := range connections {
		connections[slot] = controlstate.PublisherConnectionPlan{
			ConnectionAssignmentIdentity: controlstate.ConnectionAssignmentIdentity{
				PublisherConnectionID: "connection", RouteSessionID: "session", RouteID: "route", RouteVersion: 1,
				ConnectionSlot: slot, ConnectionAssignmentRevision: 1, RelayServiceID: "relay-service",
			},
			RelayAddress: "relay.example:443", TLSServerName: "relay.example",
			PublisherConnectionCredential: "credential", PublisherConnectionCredentialExpiresAt: time.Now().Add(time.Minute),
			State: "closed",
		}
	}
	for _, connection := range publisherConnectionResponses(connections) {
		if connection.State != controlv1.PublisherConnectionStateReplacing {
			t.Fatalf("closed publisher connection state = %q, want replacing", connection.State)
		}
	}
}

func TestControlDiscoveryAdvertisesAuthorityEndpoint(t *testing.T) {
	endpoint := "https://authority.example"
	result := controlDiscovery(Config{
		ManagedDeploymentDomain: "example",
		AuthorityEndpoint:       endpoint,
		LoginToken:              testLoginToken,
	})
	if result.ManagedDeploymentDomain != "example" || result.AuthorityEndpoint != endpoint || result.DnsAutomation {
		t.Fatalf("discovery = %#v", result)
	}
	if len(result.Authentication.Methods) != 1 || result.Authentication.Methods[0] != controlv1.LoginToken {
		t.Fatalf("authentication facts = %#v", result.Authentication)
	}
}

func TestDecodeJSONRejectsContentBeyondLimit(t *testing.T) {
	body := "{}" + strings.Repeat(" ", 64<<10-2) + "{}"
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	response := httptest.NewRecorder()
	if err := decodeJSON(response, request, &struct{}{}); err == nil {
		t.Fatal("content beyond the request limit was accepted")
	}
}
