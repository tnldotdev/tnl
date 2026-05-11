package authorityclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestOAuthRefreshAndRevokeUseDiscoveredMetadata(t *testing.T) {
	var refreshCalls, revokeCalls int
	var provider *httptest.Server
	provider = httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(response).Encode(map[string]any{
				"issuer": provider.URL, "token_endpoint": provider.URL + "/oauth/token",
				"revocation_endpoint": provider.URL + "/oauth/revoke", "extra_supported_metadata": true,
			})
		case "/oauth/token":
			refreshCalls++
			if authorization := request.Header.Get("Authorization"); authorization != "" {
				t.Errorf("token Authorization = %q", authorization)
			}
			if err := request.ParseForm(); err != nil {
				t.Error(err)
			}
			if request.Form.Get("grant_type") != "refresh_token" || request.Form.Get("client_id") != "tnl-cli" ||
				request.Form.Get("refresh_token") != "opaque-refresh" {
				t.Errorf("refresh form = %v", request.Form)
			}
			_ = json.NewEncoder(response).Encode(map[string]any{
				"access_token": "rotated-access", "token_type": "bearer", "expires_in": 300,
				"refresh_token_expires_in": 3600, "session_id": "provider-session", "provider_extension": "ignored",
			})
		case "/oauth/revoke":
			revokeCalls++
			if err := request.ParseForm(); err != nil {
				t.Error(err)
			}
			if request.Form.Get("token") != "opaque-refresh" || request.Form.Get("token_type_hint") != "refresh_token" ||
				request.Form.Get("client_id") != "tnl-cli" {
				t.Errorf("revoke form = %v", request.Form)
			}
			response.WriteHeader(http.StatusOK)
		default:
			http.NotFound(response, request)
		}
	}))
	defer provider.Close()

	client, err := New(provider.URL, provider.Client())
	if err != nil {
		t.Fatal(err)
	}
	before := time.Now()
	tokens, err := client.RefreshOAuth(context.Background(), provider.URL, "tnl-cli", "opaque-refresh")
	if err != nil {
		t.Fatal(err)
	}
	if tokens.AccessToken != "rotated-access" || tokens.RefreshToken != "opaque-refresh" ||
		tokens.SessionID != "provider-session" || !tokens.AccessExpiresAt.After(before) ||
		!tokens.RefreshExpiresAt.After(tokens.AccessExpiresAt) {
		t.Fatalf("tokens = %#v", tokens)
	}
	if err := client.RevokeOAuth(context.Background(), provider.URL, "tnl-cli", "opaque-refresh"); err != nil {
		t.Fatal(err)
	}
	if refreshCalls != 1 || revokeCalls != 1 {
		t.Fatalf("refresh calls = %d, revoke calls = %d", refreshCalls, revokeCalls)
	}
}

func TestClientBoundsOAuthResponses(t *testing.T) {
	var provider *httptest.Server
	provider = httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if strings.HasSuffix(request.URL.Path, "openid-configuration") {
			_ = json.NewEncoder(response).Encode(map[string]any{
				"issuer": provider.URL, "token_endpoint": provider.URL + "/token",
			})
			return
		}
		_, _ = response.Write(make([]byte, maxResponseBytes+1))
	}))
	defer provider.Close()
	client, err := New(provider.URL, provider.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.RefreshOAuth(context.Background(), provider.URL, "tnl-cli", "refresh"); err == nil ||
		!strings.Contains(err.Error(), "exceeds limit") {
		t.Fatalf("oversized response error = %v", err)
	}
}
