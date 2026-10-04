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
	"github.com/tnldotdev/tnl/internal/tnldconfig"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

const testLoginToken = "tnl_login_AAECAwQFBgcICQoLDA0ODw.EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8"

func TestNewHandlerRejectsInvalidCredentials(t *testing.T) {
	if _, err := NewHandler(Config{LoginToken: "invalid"}, nil, nil, nil); err == nil {
		t.Fatal("invalid login token accepted")
	}
	if _, err := NewHandler(Config{HostedSecret: "short", AuthorityEndpoint: "https://authority.example.test"}, &publicURLMutationStoreStub{}, nil, nil); err == nil {
		t.Fatal("invalid hosted secret accepted")
	}
}

func TestGuestDemoIsDisabledInControlDiscoveryAndCreationByDefault(t *testing.T) {
	handler := testHandler(t, Config{ManagedDeploymentDomain: "example.test"}, nil, nil, func(context.Context) error { return nil })
	discovery := httptest.NewRecorder()
	handler.ServeHTTP(discovery, httptest.NewRequest(http.MethodGet, "/v1/discovery", nil))
	var facts controlv1.ControlDiscovery
	if err := json.Unmarshal(discovery.Body.Bytes(), &facts); err != nil || facts.GuestDemo {
		t.Fatalf("guest discovery = %+v, error = %v", facts, err)
	}
	created := httptest.NewRecorder()
	handler.ServeHTTP(created, httptest.NewRequest(http.MethodPost, "/v1/guest-demo", nil))
	if created.Code != http.StatusNotFound {
		t.Fatalf("guest creation without opt-in = %d, %s", created.Code, created.Body.String())
	}
}

func TestHealthAndReadiness(t *testing.T) {
	cfg := Config{
		ServerDomain: "example.com", ManagedDeploymentDomain: "example.com",
		ControlReadiness: func() error { return nil },
	}
	ready := new(bool)
	handler := testHandler(t, cfg, nil, nil, func(context.Context) error {
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
	if health.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("health content type = %q", health.Header().Get("Content-Type"))
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
	var unreadyBody controlv1.ReadinessResponse
	if err := json.Unmarshal(readiness.Body.Bytes(), &unreadyBody); err != nil ||
		unreadyBody.Checks.Database != controlv1.ReadinessResponseChecksDatabaseFailed ||
		unreadyBody.Checks.Control != controlv1.ReadinessResponseChecksControlOk {
		t.Fatalf("unready checks = %#v, %v", unreadyBody, err)
	}
	*ready = true
	readiness = httptest.NewRecorder()
	handler.ServeHTTP(readiness, httptest.NewRequest(http.MethodGet, "/v1/ready", nil))
	if readiness.Code != http.StatusOK {
		t.Fatalf("ready status = %d", readiness.Code)
	}
	var readyBody controlv1.ReadinessResponse
	if err := json.Unmarshal(readiness.Body.Bytes(), &readyBody); err != nil ||
		readyBody.Checks.Database != controlv1.ReadinessResponseChecksDatabaseOk ||
		readyBody.Checks.Control != controlv1.ReadinessResponseChecksControlOk ||
		readyBody.Checks.Ingress != nil || readyBody.Checks.Relay != nil || readyBody.Checks.Route53Credentials != nil {
		t.Fatalf("readiness without Route 53 = %#v, %v", readyBody, err)
	}
}

func TestReadinessReportsRoleFailures(t *testing.T) {
	var controlErr, ingressErr, relayErr error
	cfg := Config{
		ControlReadiness: func() error { return controlErr },
		IngressReadiness: func() error { return ingressErr },
		RelayReadiness:   func() error { return relayErr },
	}
	handler := testHandler(t, cfg, nil, nil, func(context.Context) error { return nil })
	for _, test := range []struct {
		name                             string
		controlErr, ingressErr, relayErr error
		code                             int
		control                          controlv1.ReadinessResponseChecksControl
		ingress                          controlv1.ReadinessResponseChecksIngress
		relay                            controlv1.ReadinessResponseChecksRelay
	}{
		{"ready", nil, nil, nil, http.StatusOK, "ok", "ok", "ok"},
		{"control", errors.New("private listener unavailable"), nil, nil, http.StatusServiceUnavailable, "failed", "ok", "ok"},
		{"ingress", nil, errors.New("ingress lease unavailable"), nil, http.StatusServiceUnavailable, "ok", "failed", "ok"},
		{"relay", nil, nil, errors.New("relay lease unavailable"), http.StatusServiceUnavailable, "ok", "ok", "failed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			controlErr, ingressErr, relayErr = test.controlErr, test.ingressErr, test.relayErr
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/ready", nil))
			var body controlv1.ReadinessResponse
			wantStatus := controlv1.ReadinessResponseStatusReady
			if test.code != http.StatusOK {
				wantStatus = controlv1.ReadinessResponseStatusNotReady
			}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || response.Code != test.code ||
				body.Status != wantStatus || body.Checks.Database != controlv1.ReadinessResponseChecksDatabaseOk ||
				body.Checks.Control != test.control ||
				body.Checks.Ingress == nil || *body.Checks.Ingress != test.ingress ||
				body.Checks.Relay == nil || *body.Checks.Relay != test.relay {
				t.Fatalf("role readiness: status=%d body=%#v decode=%v", response.Code, body, err)
			}
		})
	}
}

func TestReadinessRequiresControlCheck(t *testing.T) {
	handler := testHandler(t, Config{}, nil, nil, func(context.Context) error { return nil })
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/ready", nil))
	var body controlv1.ReadinessResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || response.Code != http.StatusServiceUnavailable ||
		body.Status != controlv1.ReadinessResponseStatusNotReady ||
		body.Checks.Database != controlv1.ReadinessResponseChecksDatabaseOk ||
		body.Checks.Control != controlv1.ReadinessResponseChecksControlFailed {
		t.Fatalf("missing control check: status=%d body=%#v decode=%v", response.Code, body, err)
	}
}

func TestReadinessReportsRoute53CredentialFailure(t *testing.T) {
	credentialsReady := false
	cfg := Config{
		ServerDomain: "example.com", ManagedDeploymentDomain: "example.com",
		ControlReadiness: func() error { return nil },
		Route53CredentialsReadiness: func(context.Context) error {
			if !credentialsReady {
				return errors.New("web identity credentials unavailable")
			}
			return nil
		},
	}
	handler := testHandler(t, cfg, nil, nil, func(context.Context) error { return nil })
	for _, test := range []struct {
		ready  bool
		code   int
		dns    controlv1.ReadinessResponseChecksRoute53Credentials
		status controlv1.ReadinessResponseStatus
	}{
		{code: http.StatusServiceUnavailable, dns: controlv1.ReadinessResponseChecksRoute53CredentialsFailed, status: controlv1.ReadinessResponseStatusNotReady},
		{ready: true, code: http.StatusOK, dns: controlv1.ReadinessResponseChecksRoute53CredentialsOk, status: controlv1.ReadinessResponseStatusReady},
	} {
		credentialsReady = test.ready
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/ready", nil))
		var body controlv1.ReadinessResponse
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || response.Code != test.code || body.Status != test.status ||
			body.Checks.Database != controlv1.ReadinessResponseChecksDatabaseOk || body.Checks.Control != controlv1.ReadinessResponseChecksControlOk ||
			body.Checks.Route53Credentials == nil || *body.Checks.Route53Credentials != test.dns {
			t.Fatalf("Route 53 readiness: status=%d body=%#v decode=%v", response.Code, body, err)
		}
	}
}

func TestUnknownOperationsReturnNotFound(t *testing.T) {
	handler := testHandler(t, Config{ServerDomain: "example.com", ManagedDeploymentDomain: "example.com"}, nil, nil, func(context.Context) error { return nil })
	for _, path := range []string{"/v1/teams", "/not-an-api"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNotFound || response.Header().Get("Content-Type") != "application/problem+json" || !strings.Contains(response.Body.String(), `"code":"not_found"`) {
			t.Fatalf("%s status = %d", path, response.Code)
		}
	}
}

func TestAdminOperationsRequireAuthentication(t *testing.T) {
	handler := testHandler(t, Config{ServerDomain: "example.com", ManagedDeploymentDomain: "example.com"}, nil, nil, func(context.Context) error { return nil })
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/admin/status", nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("admin status = %d: %s", response.Code, response.Body.String())
	}
}

func TestConnectionAssignmentResponsesExposeClosedSlotsAsReplacing(t *testing.T) {
	var assignments [2]controlstate.ConnectionAssignment
	for slot := range assignments {
		assignments[slot] = controlstate.ConnectionAssignment{
			ConnectionAssignmentIdentity: controlstate.ConnectionAssignmentIdentity{
				PublisherConnectionID: "connection", PublishRunID: "session", PublicURLID: "route", PublishRunNumber: 1,
				ConnectionSlot: slot, ConnectionAssignmentRevision: 1, RelayServiceID: "relay-service",
			},
			RelayAddress: "relay.example:443", TLSServerName: "relay.example",
			PublisherConnectionCredential: "credential", PublisherConnectionCredentialExpiresAt: time.Now().Add(time.Minute),
			State: "closed",
		}
	}
	connections := connectionAssignmentResponses(assignments)
	if len(connections) != len(assignments) {
		t.Fatalf("connection assignments = %d, want %d", len(connections), len(assignments))
	}
	for _, connection := range connections {
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

func TestControlDiscoveryPreservesOIDCLoginFlow(t *testing.T) {
	for _, flow := range []tnldconfig.OIDCLoginFlow{
		tnldconfig.OIDCLoginFlowDeviceCode, tnldconfig.OIDCLoginFlowAuthorizationCodePKCE,
	} {
		t.Run(string(flow), func(t *testing.T) {
			result := controlDiscovery(Config{
				Role: tnldconfig.RoleControl, OIDCIssuer: "https://issuer.example.test",
				OIDCClientID: "client_1", OIDCLoginFlow: flow,
			})
			if result.Authentication.Oidc == nil ||
				result.Authentication.Oidc.LoginFlow != controlv1.OIDCAuthenticationFactsLoginFlow(flow) {
				t.Fatalf("discovery login flow = %#v", result.Authentication.Oidc)
			}
		})
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
