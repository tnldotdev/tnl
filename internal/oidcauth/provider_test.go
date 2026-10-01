package oidcauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/testutil/oidctest"
)

type testProvider struct {
	issuer string
	client *http.Client
	signer *oidctest.Signer
	mux    *http.ServeMux
}

func newTestProvider(t *testing.T, issuerPath string) *testProvider {
	t.Helper()
	p := &testProvider{signer: oidctest.NewSigner(t), mux: http.NewServeMux()}
	p.mux.HandleFunc(issuerPath+"/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		origin := "https://" + r.Host
		writeProviderJSON(t, w, map[string]any{
			"issuer": origin + issuerPath, "jwks_uri": origin + "/jwks",
			"authorization_endpoint": origin + "/authorize", "token_endpoint": origin + "/token",
			"device_authorization_endpoint": origin + "/device",
		})
	})
	jwk := p.signer.JWK("key-1")
	p.mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		writeProviderJSON(t, w, map[string]any{"keys": []any{jwk}})
	})
	server := httptest.NewTLSServer(p.mux)
	t.Cleanup(server.Close)
	p.issuer, p.client = server.URL+issuerPath, server.Client()
	p.client.Timeout = 3 * time.Second
	return p
}

// handlers report errors without calling FailNow on an HTTP server goroutine.
func writeProviderJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Error(err)
	}
}

func loginTestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}
