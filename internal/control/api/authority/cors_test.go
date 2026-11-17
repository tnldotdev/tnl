package authority

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	controlpublic "github.com/tnldotdev/tnl/internal/control/api/public"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

type corsPublisherExchangeStore struct {
	Store
	public ed25519.PublicKey
	calls  int
}

func (s *corsPublisherExchangeStore) ExchangePublisherAssertion(_ context.Context, client, grant, audience, assertion, source string, now time.Time) (controlstate.PublisherAccess, error) {
	s.calls++
	if audience != "https://control.example/v1/publisher-token" || source != "192.0.2.1/32" {
		panic("CORS changed the assertion audience or trusted source")
	}
	if client != "pub_selected" || grant != "pgr_selected" {
		return controlstate.PublisherAccess{}, controlstate.ErrPublisherIdentity
	}
	if _, err := publisherproof.Verify(assertion, client, "key_selected", grant, audience, s.public, now); err != nil {
		return controlstate.PublisherAccess{}, controlstate.ErrPublisherIdentity
	}
	return controlstate.PublisherAccess{Token: "pta_explicit-short-lived-token", Until: now.Add(time.Minute)}, nil
}

func TestPortableCORSPublisherExchangeRetainsSignedAuthentication(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	assertion, err := publisherproof.Sign("pub_selected", "key_selected", "pgr_selected", "https://control.example/v1/publisher-token", private, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, proof, grant, grantType string
		status, calls                 int
	}{
		{"signed proof", assertion, "pgr_selected", publisherproof.GrantType, 200, 1},
		{"invalid proof", "private-invalid-assertion", "pgr_selected", publisherproof.GrantType, 401, 1},
		{"other grant", assertion, "pgr_other", publisherproof.GrantType, 401, 1},
		{"missing proof", "", "pgr_selected", publisherproof.GrantType, 401, 1},
		{"cookie cannot choose grant type", "", "pgr_selected", "", 400, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &corsPublisherExchangeStore{public: private.Public().(ed25519.PublicKey)}
			mux, err := controlpublic.NewHandler(controlpublic.Config{}, controlpublic.Stores{}, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			routes, err := Register(mux, Config{ControlURL: "https://control.example"}, store)
			if err != nil {
				t.Fatal(err)
			}
			if !routes.Matches("OPTIONS /v1/publisher-token") {
				t.Fatal("exchange preflight lost its authority serving owner")
			}
			preflight := httptest.NewRequest(http.MethodOptions, "/v1/publisher-token", nil)
			preflight.Header.Set("Origin", "https://arbitrary.example")
			preflight.Header.Set("Access-Control-Request-Method", "POST")
			preflight.Header.Set("Access-Control-Request-Headers", "content-type")
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, preflight)
			if w.Code != 204 || store.calls != 0 || w.Body.Len() != 0 || w.Header().Get("Access-Control-Allow-Origin") != "*" ||
				w.Header().Get("Access-Control-Allow-Headers") != "Content-Type" || w.Header().Get("Access-Control-Allow-Credentials") != "" {
				t.Fatal("preflight entered the exchange or widened credentials", w.Code, w.Header())
			}
			wire, err := json.Marshal(map[string]string{"client_id": "pub_selected", "grant_id": test.grant,
				"client_assertion": test.proof, "client_assertion_type": publisherproof.AssertionType, "grant_type": test.grantType})
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodPost, "/v1/publisher-token", bytes.NewReader(wire))
			r.Header.Set("Origin", "https://arbitrary.example")
			r.Header.Set("Content-Type", "application/json")
			r.AddCookie(&http.Cookie{Name: "__Host-tnl-browser", Value: "ambient-cookie-secret"})
			w = httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			if w.Code != test.status || store.calls != test.calls || w.Header().Get("Access-Control-Allow-Origin") != "*" ||
				w.Header().Get("Access-Control-Allow-Credentials") != "" || w.Header().Get("Cache-Control") != "no-store" ||
				w.Header().Get("Set-Cookie") != "" {
				t.Fatal("CORS changed signed exchange authentication", w.Code, w.Header(), w.Body.String())
			}
			if test.status == 200 {
				var result authorityv1.PublisherTokenResponse
				if json.Unmarshal(w.Body.Bytes(), &result) != nil || result.AccessToken != "pta_explicit-short-lived-token" ||
					result.TokenType != "Bearer" || result.GrantId != "pgr_selected" || result.ExpiresIn < 1 || result.ExpiresIn > 60 {
					t.Fatal("exchange lost its existing short-lived credential response")
				}
			} else if strings.Contains(w.Body.String(), "pta_explicit-short-lived-token") {
				t.Fatal("rejected exchange disclosed an access token")
			}
			for _, secret := range []string{assertion, "ambient-cookie-secret", "private-invalid-assertion"} {
				if strings.Contains(w.Body.String(), secret) {
					t.Fatal("exchange reflected an authentication secret")
				}
			}
		})
	}
}

func TestPortableCORSAuthorityExcludesCookieAndOtherAuthOperations(t *testing.T) {
	h := testHandler(t, Config{}, nil)
	for _, test := range []struct {
		path, method, headers string
	}{
		{"/v1/publisher-token", "GET", ""},
		{"/v1/publisher-token", "POST", "content-type, authorization"},
		{"/v1/publisher-token", "POST", "content-type, x-tnl-actor-token"},
		{"/v1/auth/device", "POST", "content-type"},
		{"/v1/auth/refresh", "POST", "content-type"},
		{"/v1/auth/logout", "POST", "authorization"},
		{"/v1/auth/device/callback", "GET", ""},
		{"/v1/publisher-enrollments/redeem", "POST", "content-type"},
		{"/v1/publisher-keys/rotate", "POST", "authorization, content-type"},
		{"/v1/teams", "GET", "authorization"},
		{"/v1/workload-token", "POST", "content-type"},
	} {
		t.Run(test.method+" "+test.path+" "+test.headers, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodOptions, test.path, nil)
			r.Header.Set("Origin", "https://arbitrary.example")
			r.Header.Set("Access-Control-Request-Method", test.method)
			r.Header.Set("Access-Control-Request-Headers", test.headers)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code < 400 || w.Header().Get("Access-Control-Allow-Origin") != "" || w.Header().Get("Access-Control-Allow-Credentials") != "" {
				t.Fatal("unselected authority operation exposed cross-origin access", w.Code, w.Header())
			}
		})
	}
	for _, path := range []string{"/v1/auth/refresh", "/v1/auth/logout", "/v1/auth/device/callback", "/v1/teams"} {
		r := httptest.NewRequest(http.MethodPost, path, nil)
		r.Header.Set("Origin", "https://arbitrary.example")
		r.AddCookie(&http.Cookie{Name: "__Host-tnl-browser", Value: "ambient-cookie-secret"})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Header().Get("Access-Control-Allow-Origin") != "" || w.Header().Get("Access-Control-Allow-Credentials") != "" {
			t.Fatal("ordinary authority response acquired CORS", path, w.Header())
		}
	}
}
