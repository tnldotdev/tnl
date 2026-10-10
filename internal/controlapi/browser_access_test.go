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
		PreviewId: new("pv_0123456789abcdefghijkl"), PublicUrlId: "url_0123456789abcdefghijkl", ReturnPath: "/settings?tab=profile",
	})
	if start.Code != http.StatusFound {
		t.Fatalf("browser login = %d %s", start.Code, start.Body.String())
	}
	authorize, err := url.Parse(start.Header().Get("Location"))
	if err != nil || authorize.Host != newURLHost(t, provider.URL) || authorize.Query().Get("code_challenge_method") != "S256" ||
		authorize.Query().Get("nonce") != store.login.Nonce || authorize.Query().Get("redirect_uri") != "https://control.example.test/v1/browser/callback" || authorize.Query().Has("prompt") {
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
		PublicUrlId: "url_0123456789abcdefghijkl", ReturnPath: "/", Prompt: new(controlv1.SelectAccount),
	})
	if secondStart.Code != http.StatusFound || store.login.PreviewID != "" {
		t.Fatalf("URL-only login = %d preview=%q", secondStart.Code, store.login.PreviewID)
	}
	switchAuthorization, err := url.Parse(secondStart.Header().Get("Location"))
	if err != nil || switchAuthorization.Query().Get("prompt") != "select_account" || switchAuthorization.Query().Get("code_challenge_method") != "S256" || switchAuthorization.Query().Get("nonce") != store.login.Nonce {
		t.Fatalf("account switch authorization = %q, %v", secondStart.Header().Get("Location"), err)
	}
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
		h.BeginPreviewBrowserLogin(response, httptest.NewRequest(http.MethodGet, "/v1/browser/login", nil), controlv1.BeginPreviewBrowserLoginParams{PreviewId: new("pv_example"), PublicUrlId: "url_example", ReturnPath: "/"})
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
	_, _, err := h.browserSessionIdentity(httptest.NewRequest(http.MethodGet, "/", nil), controlstate.PublishRunAuthentication{}, "cookie")
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

type browserAuthorizationStoreStub struct {
	BrowserAccessStore
	auth   controlstate.PublishRunAuthentication
	cookie string
	err    error
}

func (s *browserAuthorizationStoreStub) BrowserSession(context.Context, string, string, time.Time) (controlstate.BrowserAccessSession, error) {
	return controlstate.BrowserAccessSession{IdentityID: "identity_1", AccessExpiresAt: time.Now().Add(time.Hour)}, nil
}

func (*browserAuthorizationStoreStub) RequireBrowserAccess(context.Context, controlstate.PublishRunAuthentication, time.Time) error {
	return nil
}

func (s *browserAuthorizationStoreStub) BrowserAuthorizationForRun(_ context.Context, auth controlstate.PublishRunAuthentication, cookie string, _ time.Time) (controlstate.BrowserAuthorization, error) {
	s.auth, s.cookie = auth, cookie
	return controlstate.BrowserAuthorization{Identity: controlstate.BrowserIdentity{IdentityID: "identity_1", DisplayName: "current saved name"}}, s.err
}

func TestBrowserAccessResponseKeepsIdentityWithoutVisitPermission(t *testing.T) {
	store := &browserAuthorizationStoreStub{}
	// a previous identity read's memberships and name do not supply visit permission.
	authorizer := &recordingAuthorizer{principal: publicURLReadPrincipal{
		identityID: "identity_1", displayName: "older name", teamIDs: map[string]struct{}{"team_1": {}},
	}}
	h := &handler{browserAccess: store, browserAuthority: &authorityclient.Client{}, authorizer: authorizer, store: &feedbackAuthStoreStub{auth: controlstate.PublishRunAuthentication{
		PublicURLID: "url_1", PublishRunID: "pr_1", PublishRunNumber: 1,
	}}}
	request := httptest.NewRequest(http.MethodPost, "/v1/publish-runs/pr_1/browser-access",
		strings.NewReader(`{"publish_run_number":1,"cookie_secret":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`))
	request.Header.Set("Authorization", "Bearer publisher-token")
	response := httptest.NewRecorder()
	h.CheckPreviewBrowserAccess(response, request, "pr_1")
	var body controlv1.BrowserAccessResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || body.IdentityId != "identity_1" || body.DisplayName != "current saved name" || body.VisitAllowed ||
		!strings.Contains(response.Body.String(), `"visit_allowed":false`) || strings.Contains(response.Body.String(), "team_member") ||
		store.auth.PublicURLID != "url_1" || store.auth.PublishRunID != "pr_1" || store.auth.PublishRunNumber != 1 || store.cookie != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" || len(authorizer.requests) != 0 {
		t.Fatalf("browser identity/visit response = %d %s", response.Code, response.Body.String())
	}
}

type pausedBrowserAuthorizer struct {
	publicURLAuthorizer
	entered chan struct{}
	resume  chan struct{}
}

func (a pausedBrowserAuthorizer) AuthorizePublicURLReads(ctx context.Context, _ string) (publicURLReadPrincipal, error) {
	close(a.entered)
	select {
	case <-a.resume:
		return publicURLReadPrincipal{identityID: "identity_1"}, nil
	case <-ctx.Done():
		return publicURLReadPrincipal{}, ctx.Err()
	}
}

func TestBrowserAccessResponseRejectsRunChangedDuringAuthorityIO(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	store := &browserAuthorizationStoreStub{}
	auth := controlstate.PublishRunAuthentication{PublicURLID: "url_1", PublishRunID: "pr_1", PublishRunNumber: 7, PublishRunToken: "publisher-token"}
	authorizer := pausedBrowserAuthorizer{entered: make(chan struct{}), resume: make(chan struct{})}
	h := &handler{browserAccess: store, browserAuthority: &authorityclient.Client{}, authorizer: authorizer, store: &feedbackAuthStoreStub{auth: auth}}
	request := httptest.NewRequest(http.MethodPost, "/v1/publish-runs/pr_1/browser/access", strings.NewReader(`{"publish_run_number":7,"cookie_secret":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`)).WithContext(ctx)
	request.Header.Set("Authorization", "Bearer publisher-token")
	response := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { defer close(done); h.CheckPreviewBrowserAccess(response, request, "pr_1") }()
	t.Cleanup(func() { cancel(); <-done })
	select {
	case <-authorizer.entered:
	case <-ctx.Done():
		t.Fatal("browser request did not reach authority I/O")
	}
	// the capability preflight succeeded, but its run is stale at the final check.
	store.err = controlstate.ErrPublishRunStale
	close(authorizer.resume)
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("browser request did not finish")
	}
	if response.Code != http.StatusConflict || store.auth != auth || strings.Contains(response.Body.String(), "visit_allowed") {
		t.Fatalf("stale run browser response = %d %s", response.Code, response.Body.String())
	}
}

type browserCapabilityStoreStub struct {
	BrowserAccessStore
	auth controlstate.PublishRunAuthentication
	err  error
}

func (s *browserCapabilityStoreStub) EnableBrowserAccess(_ context.Context, auth controlstate.PublishRunAuthentication, _ time.Time) error {
	s.auth = auth
	return s.err
}

type browserRunAuthStoreStub struct {
	PublicURLStore
	auth   controlstate.PublishRunAuthentication
	err    error
	id     string
	number uint64
	token  credentials.PublishRunToken
}

func (s *browserRunAuthStoreStub) PublishRunAuthentication(_ context.Context, id string, number uint64, token credentials.PublishRunToken) (controlstate.PublishRunAuthentication, error) {
	s.id, s.number, s.token = id, number, token
	return s.auth, s.err
}

func TestBrowserCapabilityEndpointAuthenticatesExactRunBeforeRegistration(t *testing.T) {
	for _, test := range []struct {
		name                     string
		authErr, registrationErr error
		available                bool
		status                   int
	}{
		{name: "registered", available: true, status: http.StatusNoContent},
		{name: "invalid token", available: true, authErr: controlstate.ErrPublishRunCredential, status: http.StatusUnauthorized},
		{name: "stale run", available: true, registrationErr: controlstate.ErrPublishRunStale, status: http.StatusConflict},
		{name: "specialized URL", available: true, registrationErr: controlstate.ErrPreviewAccess, status: http.StatusForbidden},
		{name: "browser login disabled", status: http.StatusServiceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			auth := controlstate.PublishRunAuthentication{PublishRunID: "pr_current", PublicURLID: "url_current", PublishRunNumber: 7, PublishRunToken: "current-token"}
			store := &browserRunAuthStoreStub{auth: auth, err: test.authErr}
			capability := &browserCapabilityStoreStub{err: test.registrationErr}
			h := &handler{store: store, browserAccess: capability, config: Config{ServerDomain: "example.test"}}
			if test.available {
				h.browserAuthority, h.browserVerifier = &authorityclient.Client{}, failingBrowserVerifier{}
			}
			request := httptest.NewRequest(http.MethodPost, "/v1/publish-runs/pr_current/browser/capability", strings.NewReader(`{"publish_run_number":7}`))
			request.Header.Set("Authorization", "Bearer current-token")
			response := httptest.NewRecorder()
			h.EnableBrowserAccess(response, request, "pr_current")
			if response.Code != test.status || store.id != "pr_current" || store.number != 7 || store.token != auth.PublishRunToken {
				t.Fatalf("capability authentication = %d %s", response.Code, response.Body.String())
			}
			if test.available && test.authErr == nil {
				if capability.auth != auth {
					t.Fatal("registration did not receive authenticated run association")
				}
			} else if capability.auth.PublishRunID != "" {
				t.Fatal("registration preceded authentication or browser login setup")
			}
		})
	}
}

func TestBrowserLoginRejectsUnsafeReturnOrUnsupportedPromptBeforeProviderIO(t *testing.T) {
	for _, test := range []struct {
		path   string
		prompt *controlv1.BeginPreviewBrowserLoginParamsPrompt
	}{
		{path: "//other.example"}, {path: "/%2Fother.example"}, {path: "/%5Cother.example"}, {path: "/%0D%0Aheader"}, {path: "/bad path"},
		{path: "/", prompt: new(controlv1.BeginPreviewBrowserLoginParamsPrompt("login"))},
		{path: "/", prompt: new(controlv1.BeginPreviewBrowserLoginParamsPrompt(""))},
	} {
		h := &handler{config: Config{ServerDomain: "example.test"}, browserAccess: &browserFlowStore{}, browserVerifier: failingBrowserVerifier{}, browserAuthority: &authorityclient.Client{}}
		response := httptest.NewRecorder()
		h.BeginPreviewBrowserLogin(response, httptest.NewRequest("GET", "/v1/browser/login", nil), controlv1.BeginPreviewBrowserLoginParams{PublicUrlId: "url_app", ReturnPath: test.path, Prompt: test.prompt})
		if response.Code != http.StatusBadRequest || response.Header().Get("Location") != "" {
			t.Fatalf("unsafe browser login reached identity provider: %d %s", response.Code, response.Body.String())
		}
	}
	if !validBrowserReturnPath("/settings?next=%2Ffoo%3Fa%3D1&tab=profile%26name") {
		t.Fatal("control rejected a safe encoded return query")
	}
}
