package authorityapi

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/publisheridentity"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

type publisherAuthorityStore struct {
	Store
	redeemedKey ed25519.PublicKey
	audience    string
	assertion   string
}

func (s *publisherAuthorityStore) RedeemPublisherEnrollment(_ context.Context, _ string, public ed25519.PublicKey, _ time.Time) (controlstate.PublisherIdentity, error) {
	s.redeemedKey = public
	return controlstate.PublisherIdentity{ID: "pub_client", KeyID: "pik_key", GrantID: "pgr_grant",
		Scope: controlstate.PublisherScope{TeamID: "tm_team", Kind: "saved_url", PublicURLID: "url_saved"}}, nil
}

func (s *publisherAuthorityStore) ExchangePublisherAssertion(_ context.Context, _, _, audience, assertion string, now time.Time) (controlstate.PublisherAccess, error) {
	s.audience, s.assertion = audience, assertion
	return controlstate.PublisherAccess{PublisherIdentity: controlstate.PublisherIdentity{GrantID: "pgr_grant"},
		Token: "scoped-secret", Until: now.Add(time.Minute)}, nil
}

func (s *publisherAuthorityStore) RotatePublisherKey(context.Context, string, string, string, ed25519.PublicKey, string, time.Time) error {
	return nil
}

func TestPublisherAuthorityRoutesKeepEnrollmentAndOAuthSeparate(t *testing.T) {
	store := &publisherAuthorityStore{}
	handler := testHandler(t, Config{ControlURL: "https://control.example"}, store)
	public := make([]byte, ed25519.PublicKeySize)
	request := httptest.NewRequest(http.MethodPost, "/v1/publisher/enrollments/redeem", strings.NewReader(`{"enrollment_key":"one-use-key","public_key":"`+base64.RawURLEncoding.EncodeToString(public)+`"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var result authorityv1.PublisherEnrollmentResult
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil || result.GrantId != "pgr_grant" ||
		string(store.redeemedKey) != string(public) || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("enrollment result = %d %q", response.Code, response.Body.String())
	}
	form := url.Values{
		"grant_type": {publisheridentity.GrantType}, "client_assertion_type": {publisheridentity.AssertionType},
		"client_id": {"pub_client"}, "client_assertion": {"signed-jwt"}, "scope": {"pgr_grant"},
	}
	request = httptest.NewRequest(http.MethodPost, "/v1/publisher/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var token authorityv1.PublisherTokenResponse
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &token) != nil || token.AccessToken != "scoped-secret" ||
		token.Scope != "pgr_grant" || token.TokenType != "Bearer" || store.audience != "https://control.example/v1/publisher/token" ||
		store.assertion != "signed-jwt" || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("token response = %d %q, audience = %q", response.Code, response.Body.String(), store.audience)
	}
	form.Add("scope", "pgr_another")
	request = httptest.NewRequest(http.MethodPost, "/v1/publisher/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("ambiguous scope accepted: %d %q", response.Code, response.Body.String())
	}
}
