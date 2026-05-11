package serverclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/protocol/serverv1"
)

func TestClientMapsProblemsAndRejectsTrailingJSON(t *testing.T) {
	access, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	session, _, _, err := credentials.NewSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1/capabilities":
			_, _ = response.Write([]byte(`{} {}`))
		case "/v1/routes/route/heartbeat":
			if request.Header.Get("Authorization") != "Bearer "+session.String() {
				t.Errorf("Authorization = %q", request.Header.Get("Authorization"))
			}
			response.Header().Set("Content-Type", "application/problem+json")
			response.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(response).Encode(serverv1.Problem{
				Type: "https://tnl.dev/problems/status-conflict", Title: "Status conflict",
				Status: http.StatusConflict, Code: serverv1.StatusConflict, RequestId: "req_test", Details: map[string]interface{}{},
			})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client(), access)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Capabilities(context.Background()); err == nil {
		t.Fatal("Capabilities accepted trailing JSON")
	}
	if _, err := client.Heartbeat(context.Background(), "route", 1, session); !errors.Is(err, ErrStatusConflict) {
		t.Fatalf("Heartbeat error = %v, want status conflict", err)
	}
}

func TestClientBoundsRequests(t *testing.T) {
	client, err := New("https://server.example", &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		<-request.Context().Done()
		return nil, request.Context().Err()
	})}, "")
	if err != nil {
		t.Fatal(err)
	}
	client.timeout = 20 * time.Millisecond
	if _, err := client.Capabilities(context.Background()); !errors.Is(err, ErrUnavailable) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Capabilities error = %v, want unavailable deadline", err)
	}
}

func TestClientSeparatesCertificatePreconditionsFromStaleSessions(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusPreconditionFailed)
		_ = json.NewEncoder(response).Encode(serverv1.Problem{Code: serverv1.PreconditionFailed})
	}))
	defer server.Close()
	access, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(server.URL, server.Client(), access)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.CertificateIssuance(context.Background(), "issuance_id", credentials.SessionToken("session"))
	if !errors.Is(err, ErrCertificateStatus) || errors.Is(err, ErrStatusConflict) {
		t.Fatalf("error = %v", err)
	}
}

func TestChallengeReadyAllowsServerValidationWindow(t *testing.T) {
	client, err := New("https://server.example", &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		deadline, ok := request.Context().Deadline()
		if !ok || time.Until(deadline) < 2*time.Minute {
			t.Errorf("challenge deadline = %v, present = %v", deadline, ok)
		}
		return &http.Response{
			StatusCode: http.StatusOK, Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader(`{}`)),
		}, nil
	})}, "")
	if err != nil {
		t.Fatal(err)
	}
	client.timeout = time.Millisecond
	if _, err := client.CertificateChallengeReady(context.Background(), "issuance_id", "session"); err != nil {
		t.Fatal(err)
	}
}

func TestRateLimitRetryAfterIsBounded(t *testing.T) {
	header := make(http.Header)
	header.Set("Retry-After", "9223372036854775807")
	err := responseError(
		http.StatusTooManyRequests, header,
		[]byte(`{"code":"rate_limited"}`),
	)
	var limited *RateLimitError
	if !errors.As(err, &limited) || limited.RetryAfter != 24*time.Hour {
		t.Fatalf("rate limit = %#v, %v", limited, err)
	}
}

func TestValidateControlSessionResponseAcceptsEqualExpirationsAndGrantSet(t *testing.T) {
	access, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	refresh, _, _, err := credentials.NewRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	expiresAt := time.Now().Add(time.Hour).UTC()
	stored, err := ValidateControlSessionResponse(serverv1.ControlSessionResponse{
		SessionId:   "control_session_0123456789abcdef0123456789abcdef",
		AccessToken: access.String(), AccessExpiresAt: expiresAt,
		RefreshToken: refresh.String(), RefreshExpiresAt: expiresAt,
		Grants: []serverv1.Grant{serverv1.Admin, serverv1.Publish},
	}, "", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if !stored.AccessExpiresAt.Equal(stored.RefreshExpiresAt) || len(stored.Grants) != 2 {
		t.Fatalf("stored session = %#v", stored)
	}
	if validGrants([]string{"publish", "publish"}) || validGrants([]string{"admin"}) {
		t.Fatal("invalid grant set accepted")
	}
}

func TestClientMapsNotFound(t *testing.T) {
	err := responseError(http.StatusNotFound, nil, []byte(`{"code":"not_found"}`))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("error = %v", err)
	}
	err = responseError(http.StatusNotImplemented, nil, []byte(`{"code":"unsupported"}`))
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unsupported error = %v", err)
	}
}

func TestAdminPageValidationRejectsNonAdvancingAndOversizedPages(t *testing.T) {
	id := serverv1.RouteID("route_00000000000000000000000000000001")
	page := serverv1.AdminRoutePage{
		Routes: []serverv1.AdminRoute{{
			Id: id, Status: serverv1.AdminRouteStatusActive, Version: 1,
		}},
		NextCursor: &id,
	}
	if err := validateAdminRoutePage(page, ""); err != nil {
		t.Fatal(err)
	}
	if err := validateAdminRoutePage(page, string(id)); err == nil {
		t.Fatal("non-advancing route page accepted")
	}
	page.Routes = make([]serverv1.AdminRoute, 101)
	if err := validateAdminRoutePage(page, ""); err == nil {
		t.Fatal("oversized route page accepted")
	}
}

func TestRequireAdministrationCapability(t *testing.T) {
	if err := RequireAdministrationCapability(serverv1.Capabilities{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("missing capability error = %v", err)
	}
	capabilities := serverv1.Capabilities{Administration: serverv1.AdministrationCapabilities{
		Version: serverv1.AdministrationCapabilitiesVersionN1,
		Operations: []serverv1.AdministrationCapabilitiesOperations{
			serverv1.ServerStatus, serverv1.Routes, serverv1.Hostnames, serverv1.Credentials,
			serverv1.ControlSessions, serverv1.OperationalSwitches,
		},
	}}
	if err := RequireAdministrationCapability(capabilities); err != nil {
		t.Fatal(err)
	}
	capabilities.Administration.Operations[5] = serverv1.Routes
	if err := RequireAdministrationCapability(capabilities); err == nil || errors.Is(err, ErrUnsupported) {
		t.Fatalf("duplicate capability error = %v", err)
	}
}

func TestClientPaginatesHostnames(t *testing.T) {
	var requests int
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests++
		response.Header().Set("Content-Type", "application/json")
		cursor := request.URL.Query().Get("cursor")
		if cursor == "" {
			next := "hostname_00000000000000000000000000000001"
			_ = json.NewEncoder(response).Encode(serverv1.HostnamePage{
				Hostnames: []serverv1.Hostname{
					{Id: "hostname_00000000000000000000000000000000"},
					{Id: next},
				},
				NextCursor: &next,
			})
			return
		}
		if cursor != "hostname_00000000000000000000000000000001" {
			t.Errorf("cursor = %q", cursor)
		}
		_ = json.NewEncoder(response).Encode(serverv1.HostnamePage{Hostnames: []serverv1.Hostname{{
			Id: "hostname_00000000000000000000000000000002",
		}}})
	}))
	defer server.Close()
	access, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(server.URL, server.Client(), access)
	if err != nil {
		t.Fatal(err)
	}
	hostnames, err := client.ListHostnames(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(hostnames) != 3 || requests != 2 {
		t.Fatalf("hostnames = %d, requests = %d", len(hostnames), requests)
	}
}

func TestClientOIDCAndRelayRequests(t *testing.T) {
	access, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	refresh, _, _, err := credentials.NewRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	accessExpiresAt := time.Now().Add(time.Hour).UTC()
	refreshExpiresAt := time.Now().Add(24 * time.Hour).UTC()
	const sessionID = "control_session_0123456789abcdef0123456789abcdef"
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.Method + " " + request.URL.Path {
		case "GET /v1/transport/relay-map":
			_, _ = response.Write([]byte(`{"Regions":{"1":{"RegionID":1}}}`))
		case "POST /v1/auth/oidc":
			var body serverv1.OIDCTokenExchangeRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if body.IdToken != "id-token" {
				t.Errorf("ID token = %q", body.IdToken)
			}
			_ = json.NewEncoder(response).Encode(serverv1.ControlSessionResponse{
				SessionId: sessionID, AccessToken: access.String(), AccessExpiresAt: accessExpiresAt,
				RefreshToken: refresh.String(), RefreshExpiresAt: refreshExpiresAt,
				Grants: []serverv1.Grant{serverv1.Publish},
			})
		case "POST /v1/auth/logout":
			if request.Header.Get("Authorization") != "Bearer "+access.String() {
				t.Errorf("authorization = %q", request.Header.Get("Authorization"))
			}
			response.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client(), access)
	if err != nil {
		t.Fatal(err)
	}
	relayMap, err := client.RelayMap(context.Background())
	if err != nil || string(relayMap) != `{"Regions":{"1":{"RegionID":1}}}` {
		t.Fatalf("relay map = %s, error = %v", relayMap, err)
	}
	issued, err := client.ExchangeOIDC(context.Background(), "id-token")
	if err != nil || issued.AccessToken != access.String() || issued.SessionId != sessionID {
		t.Fatalf("issued = %#v, error = %v", issued, err)
	}
	if err := client.Logout(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestClientCertificateLifecycleRequests(t *testing.T) {
	session, _, _, err := credentials.NewSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	paths := make(chan string, 5)
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+session.String() {
			t.Errorf("Authorization = %q", request.Header.Get("Authorization"))
		}
		paths <- request.Method + " " + request.URL.Path
		if request.URL.Path == "/v1/certificate-issuances" {
			var body serverv1.CreateCertificateIssuanceRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if body.Csr != base64.RawURLEncoding.EncodeToString([]byte("csr")) || body.AcmeProfile != "tlsserver" {
				t.Errorf("create body = %#v", body)
			}
		}
		if strings.Contains(request.URL.Path, "challenge-ready") || request.URL.Path == "/v1/certificate-issuances" ||
			request.Method == http.MethodGet {
			_ = json.NewEncoder(response).Encode(serverv1.CertificateIssuance{Id: "issuance_id"})
			return
		}
		response.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.CreateCertificateIssuance(context.Background(), "route", 1, session, "tlsserver", []byte("csr")); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CertificateIssuance(context.Background(), "issuance_id", session); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CertificateChallengeReady(context.Background(), "issuance_id", session); err != nil {
		t.Fatal(err)
	}
	if err := client.CertificateChallengeRemoved(context.Background(), "issuance_id", session); err != nil {
		t.Fatal(err)
	}
	if err := client.CertificateInstalled(context.Background(), "route", 1, "issuance_id", session); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"POST /v1/certificate-issuances", "GET /v1/certificate-issuances/issuance_id", "POST /v1/certificate-issuances/issuance_id/challenge-ready",
		"POST /v1/certificate-issuances/issuance_id/challenge-removed", "POST /v1/routes/route/certificate-installed",
	}
	for _, expected := range want {
		if got := <-paths; got != expected {
			t.Fatalf("request = %q, want %q", got, expected)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
