package publisher

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type browserAccessStub struct {
	PublicURLControlClient
	visitAllowed bool
	err          error
	next         string
	bridge       bool
	response     *controlv1.BrowserAccessResponse
}

func (*browserAccessStub) EnableBrowserAccess(context.Context, string, uint64, credentials.PublishRunToken) error {
	return nil
}

func (s *browserAccessStub) RedeemBrowserHandoff(context.Context, string, uint64, string, credentials.PublishRunToken) (controlv1.BrowserHandoffResponse, error) {
	response := controlv1.BrowserHandoffResponse{CookieSecret: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", ReturnPath: "/settings", ExpiresAt: time.Now().Add(time.Hour)}
	if s.next != "" {
		response.NextUrl = &s.next
		response.Bridge = &s.bridge
	}
	return response, nil
}

func (s *browserAccessStub) CheckBrowserAccess(_ context.Context, _ string, _ uint64, secret string, _ credentials.PublishRunToken) (controlv1.BrowserAccessResponse, error) {
	if s.err != nil {
		return controlv1.BrowserAccessResponse{}, s.err
	}
	if s.response != nil {
		return *s.response, nil
	}
	if secret != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
		return controlv1.BrowserAccessResponse{}, errors.New("invalid browser cookie")
	}
	return controlv1.BrowserAccessResponse{IdentityId: "user-one", DisplayName: "Sam", VisitAllowed: s.visitAllowed}, nil
}

func TestBrowserAccessForAppRunsDoesNotRequirePreviewOrShares(t *testing.T) {
	for _, previewID := range []string{"", "pv_0123456789abcdefghijkl"} {
		for _, purpose := range []controlv1.PublicURLPurpose{controlv1.App, controlv1.Alias, controlv1.Demo, controlv1.Oauth, controlv1.Webhooks} {
			config := Config{Control: &browserAccessStub{}, ControlURL: "https://control.example.test", BrowserLoginAvailable: true, PreviewID: previewID, Purpose: purpose}
			setup := controlv1.PublishRunSetup{PublicUrl: controlv1.PublicURL{Purpose: purpose, Id: "url_app"}, PublishRun: controlv1.PublishRun{Id: "pr_app", PublishRunNumber: 7}}
			access := browserAccessForRun(config, setup, "token", nil)
			if (access != nil) != (purpose == controlv1.App) {
				t.Fatalf("browser capability for preview=%q purpose=%q = %t", previewID, purpose, access != nil)
			}
			if access == nil {
				continue
			}
			response := httptest.NewRecorder()
			access.handle(response, httptest.NewRequest(http.MethodGet, "/__tnl/team/login", nil))
			redirect, err := url.Parse(response.Header().Get("Location"))
			if err != nil || response.Code != http.StatusSeeOther || redirect.Query().Get("preview_id") != previewID || redirect.Query().Get("public_url_id") != "url_app" || (previewID == "" && redirect.Query().Has("preview_id")) {
				t.Fatalf("browser login scope = %d %q", response.Code, response.Header().Get("Location"))
			}
			for _, disabled := range []string{"demo", "login unavailable", "HTTP control", "invalid control URL", "different purpose"} {
				candidate, candidateSetup := config, setup
				switch disabled {
				case "demo":
					candidate.Demo = true
				case "login unavailable":
					candidate.BrowserLoginAvailable = false
				case "HTTP control":
					candidate.ControlURL = "http://control.example.test"
				case "invalid control URL":
					candidate.ControlURL = "https:///control.example.test"
				case "different purpose":
					candidateSetup.PublicUrl.Purpose = controlv1.Oauth
				}
				if browserAccessForRun(candidate, candidateSetup, "token", nil) != nil {
					t.Fatalf("browser access accepted %s", disabled)
				}
			}
		}
	}
}

type browserCapabilityControl struct {
	*certificateTestControl
	browserAccessClient
	enable func(string, uint64, credentials.PublishRunToken) error
}

func (c *browserCapabilityControl) EnableBrowserAccess(_ context.Context, runID string, number uint64, token credentials.PublishRunToken) error {
	return c.enable(runID, number, token)
}

func TestAppRunRegistersBrowserCapabilityBeforeReady(t *testing.T) {
	for _, registrationFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "registered", true: "failed"}[registrationFails], func(t *testing.T) {
			control := newCertificateTestControl(t, "route.example", publicURLCertificateTestPlan())
			control.store = certificateTestStore(t, filepath.Join(t.TempDir(), "state"))
			config := startCertificateTLSYamuxHarness(t, control)
			registered, ready := false, false
			registrationFailure := errors.New("registration failed")
			reachedReady := errors.New("reached ready")
			config.Control = &browserCapabilityControl{certificateTestControl: control, browserAccessClient: &browserAccessStub{}, enable: func(id string, number uint64, token credentials.PublishRunToken) error {
				if id != control.setup.PublishRun.Id || number != 1 || token.String() != control.setup.PublishRunToken || ready {
					t.Fatal("browser registration did not identify the current run before ready")
				}
				if registrationFails {
					return registrationFailure
				}
				registered = true
				return nil
			}}
			config.ControlURL, config.BrowserLoginAvailable = "https://control.example.test", true
			control.ready = func() error {
				ready = true
				if !registered {
					t.Error("ready preceded browser registration")
				}
				return reachedReady
			}
			err := runCertificateSessionTest(t, config)
			if registrationFails {
				if !errors.Is(err, registrationFailure) || ready {
					t.Fatalf("failed registration reached ready: %v", err)
				}
			} else if !errors.Is(err, reachedReady) || !ready {
				t.Fatalf("registered run did not reach ready: %v", err)
			}
		})
	}
}

func (*browserAccessStub) RevokeBrowserAccess(context.Context, string, uint64, string, credentials.PublishRunToken) error {
	return nil
}

func TestBrowserTeamAccessIsAdditiveAndKeepsCookiesOutOfTheLocalService(t *testing.T) {
	cookies := make(chan string, 4)
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		cookies <- request.Header.Get("Cookie")
		response.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	shares := &shareAccess{confirmed: time.Now(), teamAccessEnabled: true, shares: map[string]cachedShare{}}
	client := &browserAccessStub{visitAllowed: true}
	access := &browserAccess{client: client, previewID: "pv_0123456789abcdefghijkl", publicURLID: "url_0123456789abcdefghijkl",
		runID: "pr_0123456789abcdefghijkl", version: 1, controlURL: "https://control.example.test", shares: shares}
	server, err := NewPublicURLServer(PublicURLServerConfig{Hostname: "route.example", Target: upstream.URL, ShareAccess: shares, BrowserAccess: access})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	serve := func(path, cookie string, denied bool) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Host = "route.example"
		request.TLS = &tls.ConnectionState{ServerName: "route.example"}
		request = request.WithContext(context.WithValue(request.Context(), denialContextKey{}, denied))
		if cookie != "" {
			request.Header.Set("Cookie", cookie)
		}
		response := httptest.NewRecorder()
		server.http.Handler.ServeHTTP(response, request)
		return response
	}
	if response := serve("/settings", "", true); response.Code != http.StatusForbidden {
		t.Fatalf("visitor without access = %d", response.Code)
	}
	navigation := httptest.NewRequest(http.MethodGet, "/settings?tab=profile", nil)
	navigation.Host = "route.example"
	navigation.TLS = &tls.ConnectionState{ServerName: "route.example"}
	navigation.Header.Set("Accept", "text/html")
	navigation = navigation.WithContext(context.WithValue(navigation.Context(), denialContextKey{}, true))
	redirect := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(redirect, navigation)
	if redirect.Code != http.StatusSeeOther || redirect.Header().Get("Location") != "/__tnl/team/login?return=%2Fsettings%3Ftab%3Dprofile" {
		t.Fatalf("unallowed browser navigation = %d %q", redirect.Code, redirect.Header().Get("Location"))
	}
	login := serve("/__tnl/team/login?return=%2Fsettings", "", true)
	if login.Code != http.StatusSeeOther || !strings.HasPrefix(login.Header().Get("Location"), "https://control.example.test/v1/browser/login?") {
		t.Fatalf("team login redirect = %d %q", login.Code, login.Header().Get("Location"))
	}
	handoff := serve("/__tnl/team/handoff/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", true)
	if handoff.Code != http.StatusSeeOther || handoff.Header().Get("Location") != "/settings" || len(handoff.Result().Cookies()) != 1 {
		t.Fatalf("browser handoff = %d %q", handoff.Code, handoff.Header().Get("Location"))
	}
	client.next, client.bridge = "https://api.example.test/__tnl/team/handoff/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", true
	bridge := serve("/__tnl/team/handoff/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", true)
	if bridge.Code != http.StatusOK || !strings.Contains(bridge.Body.String(), "http-equiv=\"refresh\"") ||
		!strings.Contains(bridge.Body.String(), client.next) || bridge.Header().Get("Content-Security-Policy") != "default-src 'none'; base-uri 'none'" {
		t.Fatalf("cross-host bridge = %d, %q", bridge.Code, bridge.Header().Get("Content-Security-Policy"))
	}
	visitorCookie := "app_session=ok; " + browserAccessCookieName + "=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if response := serve("/settings", visitorCookie, true); response.Code != http.StatusOK {
		t.Fatalf("signed-in team member = %d", response.Code)
	}
	if got := <-cookies; got != "app_session=ok" {
		t.Fatalf("local app received browser credential: %q", got)
	}
	client.err = controlclient.ErrUnavailable
	if response := serve("/settings", visitorCookie, true); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("browser authority failure became denial = %d", response.Code)
	}
	if response := serve("/__tnl/team/session", visitorCookie, true); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("browser authority failure became signed out = %d", response.Code)
	}
	client.err = &controlclient.ProblemError{Status: http.StatusForbidden, Problem: controlv1.Problem{Code: controlv1.Forbidden}}
	if response := serve("/settings", visitorCookie, true); response.Code != http.StatusForbidden {
		t.Fatalf("expired browser session = %d", response.Code)
	}
	client.err = nil
	client.visitAllowed = false
	session := serve("/__tnl/team/session", visitorCookie, true)
	if session.Code != http.StatusOK || !strings.Contains(session.Body.String(), `"signed_in":true`) ||
		!strings.Contains(session.Body.String(), `"visit_allowed":false`) || strings.Contains(session.Body.String(), "team_member") {
		t.Fatalf("signed-in identity without visit permission = %d %s", session.Code, session.Body.String())
	}
	if response := serve("/settings", visitorCookie, true); response.Code != http.StatusForbidden {
		t.Fatalf("nonmember without share or IP = %d", response.Code)
	}
	if response := serve("/settings", visitorCookie, false); response.Code != http.StatusOK {
		t.Fatalf("nonmember allowed by IP = %d", response.Code)
	}
	if got := <-cookies; got != "app_session=ok" {
		t.Fatalf("local app received browser credential: %q", got)
	}
	shares.teamAccessEnabled = false
	if response := serve("/__tnl/team/login", "", true); response.Code != http.StatusSeeOther {
		t.Fatalf("owner sign-in without team grant = %d", response.Code)
	}
	if response := serve("/__tnl/team/login", "", false); response.Code != http.StatusSeeOther {
		t.Fatalf("optional sign-in for allowed IP = %d", response.Code)
	}
}

func TestBrowserAccessCheckOnlySuppressesExpectedForbidden(t *testing.T) {
	for _, test := range []struct {
		name     string
		code     controlv1.ProblemCode
		expected bool
	}{
		{name: "expired browser session", code: controlv1.Forbidden, expected: true},
		{name: "missing code"},
		{name: "unknown code", code: "unknown_browser_failure"},
		{name: "unrelated code", code: controlv1.GuestDemoOnly},
	} {
		t.Run(test.name, func(t *testing.T) {
			cause := failure.Wrap("check browser access", failure.ServerDenied, &controlclient.ProblemError{
				Status: http.StatusForbidden, Problem: controlv1.Problem{Code: test.code, Detail: "private provider failure"},
			})
			access := &browserAccess{client: &browserAccessStub{err: cause}}
			request := httptest.NewRequest(http.MethodGet, "/__tnl/team/session", nil)
			request.Host = "route.example"
			request.TLS = &tls.ConnectionState{ServerName: "route.example"}
			request.AddCookie(&http.Cookie{Name: browserAccessCookieName, Value: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"})
			if _, signedIn, err := access.check(request); signedIn || test.expected && err != nil || !test.expected && !errors.Is(err, cause) {
				t.Fatalf("403 classification = signed in %t, %v", signedIn, err)
			}
			response := httptest.NewRecorder()
			access.handle(response, request)
			want := http.StatusServiceUnavailable
			if test.expected {
				want = http.StatusOK
			}
			if response.Code != want || strings.Contains(response.Body.String(), "private provider failure") || !test.expected && strings.Contains(response.Body.String(), `"signed_in":false`) {
				t.Fatalf("403 session response = %d %s", response.Code, response.Body.String())
			}
			server, err := NewPublicURLServer(PublicURLServerConfig{Hostname: "route.example", BrowserAccess: access, Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("rejected browser reached local service") })})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			request.URL.Path = "/settings"
			request = request.WithContext(context.WithValue(request.Context(), denialContextKey{}, true))
			response = httptest.NewRecorder()
			server.http.Handler.ServeHTTP(response, request)
			if test.expected {
				want = http.StatusForbidden
			}
			if response.Code != want || strings.Contains(response.Body.String(), "private provider failure") {
				t.Fatalf("403 admission response = %d %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestBrowserAccessInvalidIdentityResponseHasOwnedFailure(t *testing.T) {
	for _, result := range []controlv1.BrowserAccessResponse{{}, {IdentityId: "identity_1"}, {DisplayName: "Sam"}} {
		access := &browserAccess{client: &browserAccessStub{response: &result}}
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.AddCookie(&http.Cookie{Name: browserAccessCookieName, Value: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"})
		_, signedIn, err := access.check(request)
		reason, _ := failure.ReasonOf(err)
		if signedIn || !errors.Is(err, errBrowserAccessResponseInvalid) || reason != failure.ServerResponseInvalid {
			t.Fatalf("invalid identity response = signed in %t, reason %q, %v", signedIn, reason, err)
		}
	}
}
