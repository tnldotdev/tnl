package clientauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/zalando/go-keyring"
)

const testControlOrigin = "https://control.example"

// MockInit replaces a process-global keyring. hold this for the entire fixture,
// including database cleanup and all joined refresh goroutines.
var keyringTestMu sync.Mutex

type recordedRequest struct {
	method, url, body string
	header            http.Header
}

type recordingTransport struct {
	mu       sync.Mutex
	requests []recordedRequest
	respond  func(*http.Request) (*http.Response, error)
}

func (r *recordingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	var payload []byte
	if request.Body != nil {
		defer request.Body.Close()
		var err error
		payload, err = io.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}
	}
	r.mu.Lock()
	r.requests = append(r.requests, recordedRequest{request.Method, request.URL.String(), string(payload), request.Header.Clone()})
	r.mu.Unlock()
	return r.respond(request)
}

func (r *recordingTransport) snapshot() []recordedRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]recordedRequest(nil), r.requests...)
}

func jsonResponse(status int, value any) *http.Response {
	payload, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(string(payload)))}
}

func problemResponse(status int, code string) *http.Response {
	return jsonResponse(status, map[string]any{"code": code, "title": "test failure", "status": status})
}

func issuedSession(t *testing.T) authorityv1.ControlSessionResponse {
	t.Helper()
	access, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	refresh, _, _, err := credentials.NewRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	return authorityv1.ControlSessionResponse{
		SessionId:   "cs_0123456789abcdefghijkl",
		AccessToken: access.String(), RefreshToken: refresh.String(),
		AccessExpiresAt: now.Add(time.Hour), RefreshExpiresAt: now.Add(24 * time.Hour),
	}
}

func storedSession(issued authorityv1.ControlSessionResponse) clientstate.ControlSession {
	return clientstate.ControlSession{
		SessionID:   issued.SessionId,
		AccessToken: issued.AccessToken, RefreshToken: issued.RefreshToken,
		AccessExpiresAt: issued.AccessExpiresAt, RefreshExpiresAt: issued.RefreshExpiresAt,
	}
}

type authFixture struct {
	config    Config
	store     *clientstate.Store
	transport *recordingTransport
	root      string
}

func newAuthFixture(t *testing.T, respond func(*http.Request) (*http.Response, error)) *authFixture {
	t.Helper()
	keyringTestMu.Lock()
	t.Cleanup(keyringTestMu.Unlock)
	keyring.MockInit()
	root := filepath.Join(t.TempDir(), "state")
	db, err := clientstate.Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	store, err := db.Server(t.Context(), testControlOrigin)
	if err != nil {
		t.Fatal(err)
	}
	transport := &recordingTransport{respond: func(request *http.Request) (*http.Response, error) {
		if request.URL.String() == testControlOrigin+"/v1/discovery" {
			return jsonResponse(http.StatusOK, controlv1.ControlDiscovery{
				Authentication: controlv1.AuthenticationFacts{Methods: []controlv1.AuthenticationFactsMethods{controlv1.LoginToken}},
			}), nil
		}
		return respond(request)
	}}
	return &authFixture{
		config: Config{ServerEndpoint: testControlOrigin, State: db, Diagnostics: io.Discard, HTTPClient: &http.Client{Transport: transport}},
		store:  store, transport: transport, root: root,
	}
}

func (f *authFixture) save(t *testing.T, session clientstate.ControlSession) {
	t.Helper()
	if err := f.store.SaveControlSession(t.Context(), session); err != nil {
		t.Fatal(err)
	}
}

func (f *authFixture) assertSession(t *testing.T, want clientstate.ControlSession) {
	t.Helper()
	got, found, err := f.store.ControlSession(t.Context())
	if err != nil || !found || !reflect.DeepEqual(got, want) {
		t.Fatalf("saved session changed unexpectedly: found=%v, error=%v, matches=%v", found, err, reflect.DeepEqual(got, want))
	}
}

func (f *authFixture) source(t *testing.T) *tokenSource {
	t.Helper()
	resolved, err := resolveControl(t.Context(), f.config.ServerEndpoint, f.config.HTTPClient)
	if err != nil {
		t.Fatal(err)
	}
	return &tokenSource{control: resolved, config: f.config, store: f.store}
}

func assertAuthRequest(t *testing.T, got recordedRequest, method, url, token string, body any) {
	t.Helper()
	wantAuth := ""
	if token != "" {
		wantAuth = "Bearer " + token
	}
	if got.method != method || got.url != url || got.header.Get("Authorization") != wantAuth || got.header.Get("Accept") != "application/json, application/problem+json" {
		t.Errorf("request method/origin/path/auth/accept mismatch: %s %s", got.method, got.url)
	}
	if body != nil {
		want, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(got.body) != string(want) || got.header.Get("Content-Type") != "application/json" {
			t.Error("request JSON body or content type mismatch")
		}
	} else if got.body != "" {
		t.Error("unexpected request body")
	}
}

func TestAuthenticateRefreshRejectionVersusTransientFailure(t *testing.T) {
	transportFailure := errors.New("connection lost")
	for _, test := range []struct {
		name    string
		status  int
		code    string
		failure error
		login   bool
	}{
		{"unauthenticated", 401, "unauthenticated", nil, true},
		{"bad request", 400, "invalid_request", nil, true},
		{"unavailable", 503, "unavailable", nil, false},
		{"rate limited", 429, "rate_limited", nil, false},
		{"forbidden", 403, "forbidden", nil, false},
		{"transport", 0, "", transportFailure, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			old := storedSession(issuedSession(t))
			old.AccessExpiresAt = time.Now().UTC().Add(-time.Hour)
			issued := issuedSession(t)
			issued.SessionId = "cs_abcdefghijkl0123456789"
			f := newAuthFixture(t, func(request *http.Request) (*http.Response, error) {
				switch request.URL.Path {
				case "/v1/auth/refresh":
					if test.failure != nil {
						return nil, test.failure
					}
					return problemResponse(test.status, test.code), nil
				case "/v1/auth/token":
					return jsonResponse(200, issued), nil
				case "/v1/auth/logout":
					return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody}, nil
				default:
					return nil, errors.New("unexpected request")
				}
			})
			f.save(t, old)
			logins := 0
			f.config.LoginToken = func() (credentials.LoginToken, error) { logins++; return "login-input", nil }
			client, err := Authenticate(t.Context(), f.config)
			requests := f.transport.snapshot()
			if test.login {
				if err != nil || client == nil || logins != 1 || len(requests) != 4 {
					t.Fatalf("login=%d requests=%d error=%v", logins, len(requests), err)
				}
				f.assertSession(t, storedSession(issued))
				assertAuthRequest(t, requests[2], http.MethodPost, testControlOrigin+"/v1/auth/token", "", authorityv1.LoginTokenExchangeRequest{LoginToken: "login-input"})
				assertAuthRequest(t, requests[3], http.MethodPost, testControlOrigin+"/v1/auth/logout", old.AccessToken, nil)
			} else {
				if err == nil || client != nil || logins != 0 || len(requests) != 2 {
					t.Fatalf("login=%d requests=%d error=%v", logins, len(requests), err)
				}
				if test.failure != nil && !errors.Is(err, test.failure) {
					t.Fatalf("lost transport cause: %v", err)
				}
				f.assertSession(t, old)
			}
			assertAuthRequest(t, requests[0], http.MethodGet, testControlOrigin+"/v1/discovery", "", nil)
			assertAuthRequest(t, requests[1], http.MethodPost, testControlOrigin+"/v1/auth/refresh", "", authorityv1.RefreshControlSessionRequest{RefreshToken: old.RefreshToken})
			selected, found, selectErr := f.config.State.SavedServer(t.Context())
			if selectErr != nil || found != test.login || found && selected != testControlOrigin {
				t.Fatalf("selected server=%q found=%v error=%v", selected, found, selectErr)
			}
		})
	}
}

func TestAuthenticateRejectedRefreshDoesNotRetryItDuringOldSessionRevocation(t *testing.T) {
	old := storedSession(issuedSession(t))
	old.AccessExpiresAt = time.Now().UTC().Add(-time.Hour)
	issued := issuedSession(t)
	issued.SessionId = "cs_abcdefghijkl0123456789"
	refreshes, issuedLogouts := 0, 0
	f := newAuthFixture(t, func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/v1/auth/refresh":
			refreshes++
			return problemResponse(http.StatusBadRequest, "invalid_request"), nil
		case "/v1/auth/token":
			return jsonResponse(http.StatusOK, issued), nil
		case "/v1/auth/logout":
			if request.Header.Get("Authorization") == "Bearer "+old.AccessToken {
				return problemResponse(http.StatusUnauthorized, "unauthenticated"), nil
			}
			issuedLogouts++
			return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody}, nil
		default:
			return nil, errors.New("unexpected request: " + request.URL.Path)
		}
	})
	f.save(t, old)
	f.config.LoginToken = func() (credentials.LoginToken, error) { return "login-input", nil }
	client, err := Authenticate(t.Context(), f.config)
	if err != nil || client == nil || refreshes != 1 || issuedLogouts != 0 {
		t.Fatalf("replacement login = %v, refreshes = %d, issued logouts = %d", err, refreshes, issuedLogouts)
	}
	f.assertSession(t, storedSession(issued))
}

func TestSavedSessionForAnotherServerDoesNotSendCredentials(t *testing.T) {
	for _, logout := range []bool{false, true} {
		t.Run(map[bool]string{false: "authenticate", true: "logout"}[logout], func(t *testing.T) {
			f := newAuthFixture(t, func(*http.Request) (*http.Response, error) { return nil, errors.New("credentials escaped") })
			old := storedSession(issuedSession(t))
			other, err := f.config.State.Server(t.Context(), "https://other-control.example")
			if err != nil {
				t.Fatal(err)
			}
			if err := other.SaveControlSession(t.Context(), old); err != nil {
				t.Fatal(err)
			}
			if logout {
				err = Logout(t.Context(), f.config)
			} else {
				_, err = Authenticate(t.Context(), f.config)
			}
			if err == nil || len(f.transport.snapshot()) != 1 {
				t.Fatalf("mismatch: requests=%d error=%v", len(f.transport.snapshot()), err)
			}
			got, found, err := other.ControlSession(t.Context())
			if err != nil || !found || !reflect.DeepEqual(got, old) {
				t.Fatal("another server's login changed")
			}
		})
	}
}

func TestLogoutRefreshRecoveryAndFailurePersistence(t *testing.T) {
	for _, test := range []struct {
		name                     string
		first, refresh, last     int
		wantError, keep, rotated bool
	}{
		{"revoked", 204, 0, 0, false, false, false},
		{"transient revocation", 503, 0, 0, true, true, false},
		{"refresh and revoke", 401, 200, 204, false, false, true},
		{"already revoked", 401, 401, 0, false, false, false},
		{"transient refresh", 401, 503, 0, true, true, false},
		{"retry revocation later", 401, 200, 503, true, true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			old := storedSession(issuedSession(t))
			rotated := issuedSession(t)
			rotated.RefreshExpiresAt = old.RefreshExpiresAt
			recovered := false
			f := newAuthFixture(t, func(request *http.Request) (*http.Response, error) {
				if request.URL.Path == "/v1/auth/refresh" {
					if test.refresh == 200 {
						return jsonResponse(200, rotated), nil
					}
					return problemResponse(test.refresh, "unauthenticated"), nil
				}
				if request.URL.Path != "/v1/auth/logout" {
					return nil, errors.New("unexpected request")
				}
				status := test.first
				if request.Header.Get("Authorization") == "Bearer "+rotated.AccessToken {
					status = test.last
				}
				if recovered {
					status = http.StatusNoContent
				}
				if status == http.StatusNoContent {
					return &http.Response{StatusCode: status, Body: http.NoBody}, nil
				}
				return problemResponse(status, "unauthenticated"), nil
			})
			f.save(t, old)
			err := Logout(t.Context(), f.config)
			if (err != nil) != test.wantError {
				t.Fatalf("Logout error=%v", err)
			}
			if test.keep {
				want := old
				if test.rotated {
					want = storedSession(rotated)
				}
				f.assertSession(t, want)
			} else if _, found, err := f.store.ControlSession(t.Context()); found || err != nil {
				t.Fatalf("session retained: found=%v error=%v", found, err)
			}
			requests := f.transport.snapshot()
			wantCount := 2
			if test.refresh != 0 {
				wantCount++
			}
			if test.last != 0 {
				wantCount++
			}
			if len(requests) != wantCount {
				t.Fatalf("requests=%d want=%d", len(requests), wantCount)
			}
			assertAuthRequest(t, requests[1], http.MethodPost, testControlOrigin+"/v1/auth/logout", old.AccessToken, nil)
			if test.refresh != 0 {
				assertAuthRequest(t, requests[2], http.MethodPost, testControlOrigin+"/v1/auth/refresh", "", authorityv1.RefreshControlSessionRequest{RefreshToken: old.RefreshToken})
			}
			if test.last != 0 {
				assertAuthRequest(t, requests[3], http.MethodPost, testControlOrigin+"/v1/auth/logout", rotated.AccessToken, nil)
			}
			if test.last == http.StatusServiceUnavailable {
				// a later invocation must revoke using the saved rotated access
				// token, without trying the obsolete refresh credential again.
				recovered = true
				if err := Logout(t.Context(), f.config); err != nil {
					t.Fatalf("retry logout: %v", err)
				}
				requests = f.transport.snapshot()
				if len(requests) != 6 {
					t.Fatalf("recovery requests=%d", len(requests))
				}
				assertAuthRequest(t, requests[5], http.MethodPost, testControlOrigin+"/v1/auth/logout", rotated.AccessToken, nil)
				if _, found, err := f.store.ControlSession(t.Context()); found || err != nil {
					t.Fatalf("recovery retained session: found=%v error=%v", found, err)
				}
			}
		})
	}
}

func TestForceLoginRevocationFailureCleansUpIssuedSession(t *testing.T) {
	old := storedSession(issuedSession(t))
	issued := issuedSession(t)
	issued.SessionId = "cs_abcdefghijkl0123456789"
	f := newAuthFixture(t, func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/v1/auth/token" {
			return jsonResponse(200, issued), nil
		}
		if request.URL.Path == "/v1/auth/logout" {
			if request.Header.Get("Authorization") == "Bearer "+old.AccessToken {
				return problemResponse(503, "unavailable"), nil
			}
			return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody}, nil
		}
		return nil, errors.New("unexpected request")
	})
	f.save(t, old)
	f.config.ForceLogin = true
	f.config.LoginToken = func() (credentials.LoginToken, error) { return "replacement-login", nil }
	client, err := Authenticate(t.Context(), f.config)
	if client != nil || !errors.Is(err, authorityclient.ErrUnavailable) {
		t.Fatalf("Authenticate error=%v", err)
	}
	f.assertSession(t, old)
	requests := f.transport.snapshot()
	if len(requests) != 4 {
		t.Fatalf("requests=%d", len(requests))
	}
	assertAuthRequest(t, requests[2], http.MethodPost, testControlOrigin+"/v1/auth/logout", old.AccessToken, nil)
	assertAuthRequest(t, requests[3], http.MethodPost, testControlOrigin+"/v1/auth/logout", issued.AccessToken, nil)
}

func TestIssuedSessionCleanupSurvivesParentCancellation(t *testing.T) {
	type contextKey struct{}
	old := storedSession(issuedSession(t))
	issued := issuedSession(t)
	issued.SessionId = "cs_abcdefghijkl0123456789"
	cleanupCalled := false
	cleanupContextValid := true
	ctx := context.WithValue(t.Context(), contextKey{}, "cleanup-value")
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	f := newAuthFixture(t, func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/v1/auth/token":
			return jsonResponse(http.StatusOK, issued), nil
		case "/v1/auth/logout":
			switch request.Header.Get("Authorization") {
			case "Bearer " + old.AccessToken:
				cancel()
				return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody}, nil
			case "Bearer " + issued.AccessToken:
				cleanupCalled = true
				deadline, bounded := request.Context().Deadline()
				cleanupContextValid = request.Context().Err() == nil &&
					request.Context().Value(contextKey{}) == "cleanup-value" && bounded &&
					time.Until(deadline) > 0 && time.Until(deadline) <= issuedSessionCleanupTimeout
				return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody}, nil
			}
		}
		return nil, errors.New("unexpected request")
	})
	f.save(t, old)
	f.config.ForceLogin = true
	f.config.LoginToken = func() (credentials.LoginToken, error) { return "replacement-login", nil }
	client, err := Authenticate(ctx, f.config)
	if client != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("Authenticate error = %v", err)
	}
	if !cleanupCalled || !cleanupContextValid {
		t.Fatalf("cleanup called = %v, context valid = %v", cleanupCalled, cleanupContextValid)
	}
	f.assertSession(t, old)
}

func TestIssuedSessionCleanupFailureIsJoined(t *testing.T) {
	old := storedSession(issuedSession(t))
	issued := issuedSession(t)
	issued.SessionId = "cs_abcdefghijkl0123456789"
	primaryFailure := errors.New("previous revocation failed")
	cleanupFailure := errors.New("issued revocation failed")
	f := newAuthFixture(t, func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/v1/auth/token":
			return jsonResponse(http.StatusOK, issued), nil
		case "/v1/auth/logout":
			if request.Header.Get("Authorization") == "Bearer "+old.AccessToken {
				return nil, primaryFailure
			}
			return nil, cleanupFailure
		default:
			return nil, errors.New("unexpected request")
		}
	})
	f.save(t, old)
	f.config.ForceLogin = true
	f.config.LoginToken = func() (credentials.LoginToken, error) { return "replacement-login", nil }
	client, err := Authenticate(t.Context(), f.config)
	if client != nil || !errors.Is(err, primaryFailure) || !errors.Is(err, cleanupFailure) {
		t.Fatalf("Authenticate error = %v", err)
	}
	f.assertSession(t, old)
}

func TestAuthenticateReusesOrRefreshesSavedSessionForControlRequests(t *testing.T) {
	for _, refresh := range []bool{false, true} {
		name := "reuse fresh session"
		if refresh {
			name = "refresh within safety margin"
		}
		t.Run(name, func(t *testing.T) {
			old := storedSession(issuedSession(t))
			issued := issuedSession(t)
			issued.RefreshExpiresAt = old.RefreshExpiresAt
			want := old
			if refresh {
				old.AccessExpiresAt = time.Now().UTC().Add(15 * time.Second)
				want = storedSession(issued)
			}
			f := newAuthFixture(t, func(request *http.Request) (*http.Response, error) {
				switch request.URL.Path {
				case "/v1/auth/refresh":
					return jsonResponse(200, issued), nil
				case "/v1/public-urls/public_url_1":
					return jsonResponse(200, controlv1.PublicURL{Id: "public_url_1", CanonicalHostname: "demo.example", Target: "http://127.0.0.1:3000"}), nil
				case "/v1/identity":
					return jsonResponse(200, authorityv1.IdentityContext{Identity: authorityv1.Identity{Id: "identity_1", DisplayName: "Test"}, PersonalTeamId: "team_1"}), nil
				default:
					return nil, errors.New("unexpected authentication request")
				}
			})
			f.save(t, old)
			client, err := Authenticate(t.Context(), f.config)
			if err != nil {
				t.Fatal(err)
			}
			route, err := client.Control.GetPublicURL(t.Context(), "public_url_1")
			if err != nil || route.Id != "public_url_1" || route.CanonicalHostname != "demo.example" || route.Target != "http://127.0.0.1:3000" {
				t.Fatalf("authenticated public_url: %#v, %v", route, err)
			}
			identity, err := client.Authority.IdentityContext(t.Context())
			if err != nil || identity.Identity.Id != "identity_1" || identity.PersonalTeamId != "team_1" {
				t.Fatalf("authenticated identity: %#v, %v", identity, err)
			}
			requests := f.transport.snapshot()
			count := 3
			if refresh {
				count++
			}
			if len(requests) != count {
				t.Fatalf("requests=%d want=%d", len(requests), count)
			}
			assertAuthRequest(t, requests[count-2], http.MethodGet, testControlOrigin+"/v1/public-urls/public_url_1", want.AccessToken, nil)
			assertAuthRequest(t, requests[count-1], http.MethodGet, testControlOrigin+"/v1/identity", want.AccessToken, nil)
			if refresh {
				assertAuthRequest(t, requests[1], http.MethodPost, testControlOrigin+"/v1/auth/refresh", "", authorityv1.RefreshControlSessionRequest{RefreshToken: old.RefreshToken})
			}
			f.assertSession(t, want)
			if f.config.HTTPClient.Transport != f.transport {
				t.Fatal("authentication mutated the caller's HTTP client")
			}
		})
	}
}

func TestAuthenticateReusingSessionPreservesSelectedServer(t *testing.T) {
	old := storedSession(issuedSession(t))
	f := newAuthFixture(t, func(request *http.Request) (*http.Response, error) {
		return nil, errors.New("unexpected request: " + request.URL.Path)
	})
	f.save(t, old)
	const selected = "https://previous-control.example"
	if err := f.config.State.SaveServer(t.Context(), selected); err != nil {
		t.Fatal(err)
	}
	if _, err := Authenticate(t.Context(), f.config); err != nil {
		t.Fatal(err)
	}
	got, found, err := f.config.State.SavedServer(t.Context())
	if err != nil || !found || got != selected {
		t.Fatalf("selected server changed on session reuse: %q, %t, %v", got, found, err)
	}
}

func TestLoginFailurePreservesSavedSessionAndServerSelection(t *testing.T) {
	promptFailure := errors.New("login prompt canceled")
	for _, name := range []string{"prompt", "exchange", "invalid issued session"} {
		t.Run(name, func(t *testing.T) {
			old := storedSession(issuedSession(t))
			invalid := issuedSession(t)
			invalid.RefreshToken = "invalid"
			f := newAuthFixture(t, func(request *http.Request) (*http.Response, error) {
				if request.URL.Path != "/v1/auth/token" {
					return nil, errors.New("unexpected revocation or refresh")
				}
				if name == "invalid issued session" {
					return jsonResponse(200, invalid), nil
				}
				return problemResponse(401, "unauthenticated"), nil
			})
			f.save(t, old)
			const selected = "https://previous-control.example"
			if err := f.config.State.SaveServer(t.Context(), selected); err != nil {
				t.Fatal(err)
			}
			f.config.ForceLogin = true
			f.config.LoginToken = func() (credentials.LoginToken, error) {
				if name == "prompt" {
					return "", promptFailure
				}
				return "login-input", nil
			}
			client, err := Authenticate(t.Context(), f.config)
			if err == nil || client != nil || name == "prompt" && !errors.Is(err, promptFailure) {
				t.Fatalf("failed login: %v", err)
			}
			f.assertSession(t, old)
			got, found, err := f.config.State.SavedServer(t.Context())
			if err != nil || !found || got != selected {
				t.Fatalf("selection changed: %q found=%v error=%v", got, found, err)
			}
			count := 2
			if name == "prompt" {
				count = 1
			}
			if len(f.transport.snapshot()) != count {
				t.Fatal("failed login attempted refresh or revocation")
			}
		})
	}
}

func TestExplicitAccessTokenDoesNotUseOrChangeSavedLogin(t *testing.T) {
	for _, valid := range []bool{false, true} {
		name := "invalid format"
		if valid {
			name = "valid token"
		}
		t.Run(name, func(t *testing.T) {
			old := storedSession(issuedSession(t))
			explicit := issuedSession(t).AccessToken
			f := newAuthFixture(t, func(request *http.Request) (*http.Response, error) {
				if request.URL.Path != "/v1/public-urls/public_url_1" {
					return nil, errors.New("unexpected authentication request")
				}
				return jsonResponse(200, controlv1.PublicURL{Id: "public_url_1"}), nil
			})
			f.save(t, old)
			config := f.config
			config.State = nil
			config.AccessToken = explicit
			if !valid {
				config.AccessToken = "not-an-access-token"
			}
			client, err := Authenticate(t.Context(), config)
			if !valid {
				if err == nil || client != nil || len(f.transport.snapshot()) != 1 {
					t.Fatalf("invalid token: %v", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				route, err := client.Control.GetPublicURL(t.Context(), "public_url_1")
				if err != nil || route.Id != "public_url_1" {
					t.Fatalf("explicit authenticated public_url: %v", err)
				}
				requests := f.transport.snapshot()
				if len(requests) != 2 {
					t.Fatalf("requests=%d", len(requests))
				}
				assertAuthRequest(t, requests[1], http.MethodGet, testControlOrigin+"/v1/public-urls/public_url_1", explicit, nil)
			}
			f.assertSession(t, old)
			if _, found, err := f.config.State.SavedServer(t.Context()); found || err != nil {
				t.Fatalf("explicit token changed selection: found=%v error=%v", found, err)
			}
		})
	}
}
