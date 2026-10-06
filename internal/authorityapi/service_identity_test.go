package authorityapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
)

type websiteStoreStub struct {
	Store
	identity controlstate.OIDCIdentity
	calls    int
}

func (s *websiteStoreStub) EnsureServiceIdentity(_ context.Context, _ string, identity controlstate.OIDCIdentity, _ time.Time) (controlstate.IdentityContext, error) {
	s.identity = identity
	s.calls++
	return controlstate.IdentityContext{Identity: controlstate.Identity{ID: "ident_web", DisplayName: identity.DisplayName}, PersonalTeamID: "tm_personal"}, nil
}

func TestWebsiteIdentityIsScopedToConfiguredIssuerWithoutCredentials(t *testing.T) {
	const secret = "website-service-secret-012345678901"
	store := new(websiteStoreStub)
	h := testHandler(t, Config{OIDCIssuer: "https://account.example", WebServiceSecret: secret}, store)
	for _, test := range []struct {
		token, body string
		status      int
	}{
		{"", `{"subject":"sam","display_name":"Sam"}`, 401},
		{"wrong", `{"subject":"sam","display_name":"Sam"}`, 401},
		{secret, `{"subject":"sam","display_name":"Sam","issuer":"https://evil.example"}`, 400},
		{secret, `{"subject":"sam","display_name":"Sam"}`, 200},
	} {
		r := httptest.NewRequest(http.MethodPost, "/v1/service/identity-context", strings.NewReader(test.body))
		r.Header.Set("Authorization", "Bearer "+test.token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != test.status {
			t.Fatalf("identity status=%d: %s", w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "access_token") || strings.Contains(w.Body.String(), "refresh_token") {
			t.Fatal("website identity returned credentials")
		}
	}
	if store.calls != 1 || store.identity.Issuer != "https://account.example" {
		t.Fatalf("website identity=%+v calls=%d", store.identity, store.calls)
	}
	for _, path := range []string{"/v1/teams", "/v1/auth/logout"} {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		if path == "/v1/teams" {
			r.Method = http.MethodGet
		}
		r.Header.Set("Authorization", "Bearer "+secret)
		// use a store that rejects service credentials on the normal user path.
		w := httptest.NewRecorder()
		testHandler(t, Config{}, &controlAuthenticationStoreStub{authenticationErr: controlstate.ErrControlAuthentication}).ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("service token accessed %s: %d", path, w.Code)
		}
	}
}
