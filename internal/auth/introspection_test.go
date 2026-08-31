package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/0xcadams/tnl/internal/credentials"
)

func TestIntrospectionVerifierUsesWorkloadAuthentication(t *testing.T) {
	workload, _, err := credentials.NewWorkloadToken()
	if err != nil {
		t.Fatal(err)
	}
	expiresAt := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.Header.Get("Authorization") != "Bearer "+workload.String() {
			t.Errorf("request = %s, authorization = %q", request.Method, request.Header.Get("Authorization"))
		}
		if request.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("content type = %q", request.Header.Get("Content-Type"))
		}
		if err := request.ParseForm(); err != nil {
			t.Error(err)
		}
		if request.Form.Get("token") != "external-session" {
			t.Errorf("token = %q", request.Form.Get("token"))
		}
		_ = json.NewEncoder(response).Encode(map[string]any{
			"active": true, "iss": server.URL, "sub": "user-123",
			"username": "Example User", "email": "user@example.com", "scope": "openid tnl:core",
			"exp": expiresAt.Unix(),
		})
	}))
	defer server.Close()

	verifier, err := NewIntrospectionVerifier(IntrospectionConfig{
		URL: server.URL, Issuer: server.URL, RequiredScope: "tnl:core",
		WorkloadToken: workload, HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := verifier.Verify(context.Background(), "external-session")
	if err != nil {
		t.Fatal(err)
	}
	if identity.Subject != "user-123" || !identity.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("identity = %#v", identity)
	}
}

func TestIntrospectionVerifierRejectsUntrustedClaims(t *testing.T) {
	workload, _, err := credentials.NewWorkloadToken()
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(response).Encode(map[string]any{
			"active": true, "iss": "https://other.example", "sub": "user-123",
			"scope": "tnl:core", "exp": time.Now().Add(time.Hour).Unix(),
		})
	}))
	defer server.Close()
	verifier, err := NewIntrospectionVerifier(IntrospectionConfig{
		URL: server.URL, Issuer: server.URL, RequiredScope: "tnl:core",
		WorkloadToken: workload, HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(context.Background(), "external-session"); err != ErrUnauthenticated {
		t.Fatalf("error = %v, want unauthenticated", err)
	}
}
