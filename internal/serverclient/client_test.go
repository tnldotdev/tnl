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

	"github.com/0xcadams/tnl/internal/credentials"
	"github.com/0xcadams/tnl/pkg/protocol/serverv1"
)

func TestClientMapsProblemsAndRejectsTrailingJSON(t *testing.T) {
	access, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	lease, _, _, err := credentials.NewLeaseToken()
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1/capabilities":
			_, _ = response.Write([]byte(`{} {}`))
		case "/v1/routes/route/heartbeat":
			if request.Header.Get("Authorization") != "Bearer "+lease.String() {
				t.Errorf("Authorization = %q", request.Header.Get("Authorization"))
			}
			response.Header().Set("Content-Type", "application/problem+json")
			response.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(response).Encode(serverv1.Problem{
				Type: "https://tnl.dev/problems/state-conflict", Title: "State conflict",
				Status: http.StatusConflict, Code: serverv1.StateConflict, RequestId: "req_test", Details: map[string]interface{}{},
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
	if _, err := client.Heartbeat(context.Background(), "route", 1, lease); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("Heartbeat error = %v, want state conflict", err)
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

func TestClientSeparatesCertificatePreconditionsFromStaleLeases(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusPreconditionFailed)
		_ = json.NewEncoder(response).Encode(serverv1.Problem{Code: serverv1.PreconditionFailed})
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.CertificateOrder(context.Background(), "cert_id", credentials.LeaseToken("lease"))
	if !errors.Is(err, ErrCertificateState) || errors.Is(err, ErrStateConflict) {
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
	if _, err := client.CertificateChallengeReady(context.Background(), "cert_id", "lease"); err != nil {
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

func TestClientMapsNotFound(t *testing.T) {
	err := responseError(http.StatusNotFound, nil, []byte(`{"code":"not_found"}`))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("error = %v", err)
	}
}

func TestClientPaginatesHostnameClaims(t *testing.T) {
	var requests int
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests++
		response.Header().Set("Content-Type", "application/json")
		cursor := request.URL.Query().Get("cursor")
		if cursor == "" {
			next := "claim_00000000000000000000000000000001"
			_ = json.NewEncoder(response).Encode(serverv1.HostnameClaimPage{
				Claims: []serverv1.HostnameClaim{
					{Id: "claim_00000000000000000000000000000000"},
					{Id: next},
				},
				NextCursor: &next,
			})
			return
		}
		if cursor != "claim_00000000000000000000000000000001" {
			t.Errorf("cursor = %q", cursor)
		}
		_ = json.NewEncoder(response).Encode(serverv1.HostnameClaimPage{Claims: []serverv1.HostnameClaim{{
			Id: "claim_00000000000000000000000000000002",
		}}})
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := client.ListHostnameClaims(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(claims) != 3 || requests != 2 {
		t.Fatalf("claims = %d, requests = %d", len(claims), requests)
	}
}

func TestClientOIDCAndRelayRequests(t *testing.T) {
	access, credentialID, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	expiresAt := time.Now().Add(time.Hour).UTC()
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
			_ = json.NewEncoder(response).Encode(serverv1.TokenExchangeResponse{
				AccessToken: access.String(), CredentialId: credentialID.String(),
				ExpiresAt: expiresAt, TokenType: serverv1.Bearer,
			})
		case "DELETE /v1/auth/credentials/" + credentialID.String():
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
	if err != nil || issued.AccessToken != access.String() || issued.CredentialId != credentialID.String() {
		t.Fatalf("issued = %#v, error = %v", issued, err)
	}
	if err := client.RevokeAccessCredential(context.Background(), credentialID.String()); err != nil {
		t.Fatal(err)
	}
}

func TestClientCertificateLifecycleRequests(t *testing.T) {
	lease, _, _, err := credentials.NewLeaseToken()
	if err != nil {
		t.Fatal(err)
	}
	paths := make(chan string, 5)
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+lease.String() {
			t.Errorf("Authorization = %q", request.Header.Get("Authorization"))
		}
		paths <- request.Method + " " + request.URL.Path
		if request.URL.Path == "/v1/certs/orders" {
			var body serverv1.CreateCertificateOrderRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if body.Csr != base64.RawURLEncoding.EncodeToString([]byte("csr")) || body.Profile != "tlsserver" {
				t.Errorf("create body = %#v", body)
			}
		}
		if strings.Contains(request.URL.Path, "challenge-ready") || request.URL.Path == "/v1/certs/orders" ||
			request.Method == http.MethodGet {
			_ = json.NewEncoder(response).Encode(serverv1.CertificateOrder{Id: "cert_id"})
			return
		}
		response.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.CreateCertificateOrder(context.Background(), "route", 1, lease, "tlsserver", []byte("csr")); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CertificateOrder(context.Background(), "cert_id", lease); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CertificateChallengeReady(context.Background(), "cert_id", lease); err != nil {
		t.Fatal(err)
	}
	if err := client.CertificateChallengeRemoved(context.Background(), "cert_id", lease); err != nil {
		t.Fatal(err)
	}
	if err := client.CertificateInstalled(context.Background(), "route", 1, "cert_id", lease); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"POST /v1/certs/orders", "GET /v1/certs/orders/cert_id", "POST /v1/certs/orders/cert_id/challenge-ready",
		"POST /v1/certs/orders/cert_id/challenge-removed", "POST /v1/routes/route/certificate-installed",
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
