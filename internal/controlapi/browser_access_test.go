package controlapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/oidcauth"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/testutil/oidctest"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type browserFlowStore struct {
	BrowserAccessStore
	login    controlstate.BrowserLoginAttempt
	issued   controlstate.BrowserAccessSession
	consumed bool
	binding  []byte
}

func (s *browserFlowStore) BeginBrowserLogin(_ context.Context, previewID, publicURLID, path, nonce, verifier string, binding []byte, _ time.Time) (string, error) {
	s.login = controlstate.BrowserLoginAttempt{PreviewID: previewID, PublicURLID: publicURLID, ReturnPath: path, Nonce: nonce, Verifier: verifier}
	s.binding = bytes.Clone(binding)
	return "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", nil
}

func (s *browserFlowStore) ConsumeBrowserLogin(_ context.Context, state string, binding []byte, _ time.Time) (controlstate.BrowserLoginAttempt, error) {
	if state != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" || !bytes.Equal(binding, s.binding) || s.consumed {
		return controlstate.BrowserLoginAttempt{}, controlstate.ErrPreviewAccess
	}
	s.consumed = true
	return s.login, nil
}

func (s *browserFlowStore) IssueBrowserHandoff(_ context.Context, _ controlstate.BrowserLoginAttempt, session controlstate.BrowserAccessSession, _ time.Time) (controlstate.BrowserHandoff, error) {
	s.issued = session
	return controlstate.BrowserHandoff{Token: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"}, nil
}

func TestBrowserOIDCLoginBindsCodeNonceAndPreviewReturn(t *testing.T) {
	signer := oidctest.NewSigner(t)
	var provider *httptest.Server
	var nonce string
	var signedToken string
	store := &browserFlowStore{}
	provider = httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/.well-known/openid-configuration":
			writeJSON(response, http.StatusOK, map[string]any{
				"issuer": provider.URL, "authorization_endpoint": provider.URL + "/authorize",
				"token_endpoint": provider.URL + "/token", "jwks_uri": provider.URL + "/jwks",
				"response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/jwks":
			writeJSON(response, http.StatusOK, map[string]any{"keys": []any{signer.JWK("browser-test")}})
		case "/token":
			if err := request.ParseForm(); err != nil || request.Form.Get("grant_type") != "authorization_code" ||
				request.Form.Get("code") != "one-use-code" || request.Form.Get("code_verifier") != store.login.Verifier {
				http.Error(response, "invalid authorization code", http.StatusBadRequest)
				return
			}
			writeJSON(response, http.StatusOK, map[string]any{
				"access_token": "oidc-access-token", "token_type": "Bearer", "expires_in": 300,
				"id_token": signedToken,
			})
		default:
			http.NotFound(response, request)
		}
	}))
	defer provider.Close()
	verifier, err := oidcauth.NewVerifier(oidcauth.VerifierConfig{Issuer: provider.URL, ClientID: "tnl-browser", HTTPClient: provider.Client()})
	if err != nil {
		t.Fatal(err)
	}
	access, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	refresh, _, _, err := credentials.NewRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	sessionID, err := opaqueid.New(opaqueid.ControlSessionPrefix)
	if err != nil {
		t.Fatal(err)
	}
	authority := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/auth/browser" {
			http.NotFound(response, request)
			return
		}
		var body authorityv1.OIDCTokenExchangeRequest
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil || body.IdToken == "" {
			http.Error(response, "invalid assertion", http.StatusBadRequest)
			return
		}
		writeJSON(response, http.StatusOK, authorityv1.ControlSessionResponse{
			SessionId: sessionID, AccessToken: access.String(), RefreshToken: refresh.String(),
			AccessExpiresAt: time.Now().Add(time.Hour), RefreshExpiresAt: time.Now().Add(24 * time.Hour),
			Identity: authorityv1.IdentityContext{Identity: authorityv1.Identity{Id: "identity_1", DisplayName: "Sam"},
				PersonalTeamId: "team_1", Memberships: []authorityv1.Membership{}},
		})
	}))
	defer authority.Close()
	authorityClient, err := authorityclient.New(authority.URL, authority.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	h := &handler{
		config: Config{OIDCIssuer: provider.URL, BrowserOIDCClientID: "tnl-browser", ServerDomain: "example.test", HTTPClient: provider.Client()},
		store:  &shareRoutesStub{}, previews: &previewStoreStub{preview: controlstate.Preview{
			ID: "pv_0123456789abcdefghijkl", TeamID: "team_1", PublicURLIDs: []string{"url_0123456789abcdefghijkl"},
		}},
		browserAccess: store, browserVerifier: verifier, browserAuthority: authorityClient,
		authorizer: &selectiveShareAuthorizer{principal: publicURLReadPrincipal{identityID: "identity_1", displayName: "Sam"}},
	}
	start := httptest.NewRecorder()
	h.BeginPreviewBrowserLogin(start, httptest.NewRequest(http.MethodGet, "/v1/browser/login", nil), controlv1.BeginPreviewBrowserLoginParams{
		PreviewId: "pv_0123456789abcdefghijkl", PublicUrlId: "url_0123456789abcdefghijkl", ReturnPath: "/settings?tab=profile",
	})
	if start.Code != http.StatusFound {
		t.Fatalf("browser login = %d %s", start.Code, start.Body.String())
	}
	authorize, err := url.Parse(start.Header().Get("Location"))
	if err != nil || authorize.Host != newURLHost(t, provider.URL) || authorize.Query().Get("code_challenge_method") != "S256" ||
		authorize.Query().Get("nonce") != store.login.Nonce || authorize.Query().Get("redirect_uri") != "https://control.example.test/v1/browser/callback" {
		t.Fatalf("OIDC redirect does not bind the browser state: %q, %v", start.Header().Get("Location"), err)
	}
	nonce = authorize.Query().Get("nonce")
	if nonce == "" {
		t.Fatal("browser OIDC nonce is missing")
	}
	signedToken = signer.Token(t, "browser-test", map[string]any{
		"iss": provider.URL, "aud": "tnl-browser", "sub": "identity_1", "name": "Sam",
		"nonce": nonce, "iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(),
	})
	if len(start.Result().Cookies()) != 1 {
		t.Fatal("browser login binding cookie is missing")
	}
	bindingCookie := start.Result().Cookies()[0]
	invalid := httptest.NewRecorder()
	invalidRequest := httptest.NewRequest(http.MethodGet, "/v1/browser/callback", nil)
	invalidRequest.AddCookie(bindingCookie)
	h.CompletePreviewBrowserLogin(invalid, invalidRequest, controlv1.CompletePreviewBrowserLoginParams{State: "wrong-state", Code: "one-use-code"})
	if invalid.Code != http.StatusForbidden {
		t.Fatalf("invalid state callback = %d", invalid.Code)
	}
	complete := httptest.NewRecorder()
	completeRequest := httptest.NewRequest(http.MethodGet, "/v1/browser/callback", nil)
	completeRequest.AddCookie(bindingCookie)
	h.CompletePreviewBrowserLogin(complete, completeRequest, controlv1.CompletePreviewBrowserLoginParams{State: authorize.Query().Get("state"), Code: "one-use-code"})
	if complete.Code != http.StatusSeeOther || complete.Header().Get("Location") != "https://web.example.test/__tnl/team/handoff/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" ||
		store.issued.IdentityID != "identity_1" || store.issued.DisplayName != "Sam" || store.issued.AccessToken != access.String() {
		t.Fatalf("browser callback = %d %q identity=%q", complete.Code, complete.Header().Get("Location"), store.issued.IdentityID)
	}
	resend := httptest.NewRecorder()
	resendRequest := httptest.NewRequest(http.MethodGet, "/v1/browser/callback", nil)
	resendRequest.AddCookie(bindingCookie)
	h.CompletePreviewBrowserLogin(resend, resendRequest, controlv1.CompletePreviewBrowserLoginParams{State: authorize.Query().Get("state"), Code: "one-use-code"})
	if resend.Code != http.StatusForbidden {
		t.Fatalf("replayed callback = %d", resend.Code)
	}
	store.consumed = false
	secondStart := httptest.NewRecorder()
	h.BeginPreviewBrowserLogin(secondStart, httptest.NewRequest(http.MethodGet, "/v1/browser/login", nil), controlv1.BeginPreviewBrowserLoginParams{
		PreviewId: "pv_0123456789abcdefghijkl", PublicUrlId: "url_0123456789abcdefghijkl", ReturnPath: "/",
	})
	wrongNonce := signer.Token(t, "browser-test", map[string]any{
		"iss": provider.URL, "aud": "tnl-browser", "sub": "identity_1", "name": "Sam",
		"nonce": "incorrect-nonce-for-this-login", "iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(),
	})
	signedToken = wrongNonce
	wrong := httptest.NewRecorder()
	wrongRequest := httptest.NewRequest(http.MethodGet, "/v1/browser/callback", nil)
	wrongRequest.AddCookie(secondStart.Result().Cookies()[0])
	h.CompletePreviewBrowserLogin(wrong, wrongRequest, controlv1.CompletePreviewBrowserLoginParams{State: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Code: "one-use-code"})
	if wrong.Code != http.StatusUnauthorized {
		t.Fatalf("wrong OIDC nonce reached preview handoff: %d", wrong.Code)
	}
}

func newURLHost(t *testing.T, value string) string {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.Host
}

type failingBrowserPreviewStore struct {
	PreviewStore
	err error
}

func (s failingBrowserPreviewStore) GetPreview(context.Context, string) (controlstate.Preview, error) {
	return controlstate.Preview{}, s.err
}

type failingBrowserVerifier struct{ err error }

func (v failingBrowserVerifier) Verify(context.Context, string) (oidcauth.Identity, error) {
	return oidcauth.Identity{}, v.err
}

func TestBrowserLoginDoesNotHideStorageFailureAsNotFound(t *testing.T) {
	for _, test := range []struct {
		err    error
		status int
		code   string
	}{
		{controlstate.ErrPreviewNotFound, http.StatusNotFound, "not_found"},
		{errors.New("database password private-test-secret"), http.StatusInternalServerError, "internal"},
	} {
		h := &handler{config: Config{ServerDomain: "example.test"}, browserAccess: &browserFlowStore{}, browserVerifier: failingBrowserVerifier{}, browserAuthority: &authorityclient.Client{}, previews: failingBrowserPreviewStore{err: test.err}}
		response := httptest.NewRecorder()
		h.BeginPreviewBrowserLogin(response, httptest.NewRequest(http.MethodGet, "/v1/browser/login", nil), controlv1.BeginPreviewBrowserLoginParams{PreviewId: "pv_example", PublicUrlId: "url_example", ReturnPath: "/"})
		var body struct {
			Code      string `json:"code"`
			RequestID string `json:"request_id"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if response.Code != test.status || body.Code != test.code || !strings.HasPrefix(body.RequestID, "req_") || strings.Contains(response.Body.String(), "private-test-secret") {
			t.Fatalf("browser failure = %d %s", response.Code, response.Body.String())
		}
	}
}

func TestBrowserSessionPreservesAuthorizationAvailabilityFailure(t *testing.T) {
	cause := errors.Join(authorization.ErrUnavailable, errors.New("private authority failure"))
	h := &handler{browserAccess: browserSessionStoreStub{}, authorizer: failingBrowserAuthorizer{err: cause}}
	_, _, _, err := h.browserSessionAccess(httptest.NewRequest(http.MethodGet, "/", nil), controlstate.PublishRunAuthentication{}, "cookie")
	if !errors.Is(err, authorization.ErrUnavailable) {
		t.Fatalf("authorization failure became an expired session: %v", err)
	}
}

type browserSessionStoreStub struct{ BrowserAccessStore }

type failingBrowserAuthorizer struct {
	publicURLAuthorizer
	err error
}

func (a failingBrowserAuthorizer) AuthorizePublicURLReads(context.Context, string) (publicURLReadPrincipal, error) {
	return publicURLReadPrincipal{}, a.err
}

func (browserSessionStoreStub) BrowserSession(context.Context, string, string, time.Time) (controlstate.BrowserAccessSession, error) {
	return controlstate.BrowserAccessSession{AccessExpiresAt: time.Now().Add(time.Hour)}, nil
}
