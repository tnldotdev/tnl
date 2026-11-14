package publisher

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type browserAccessStub struct {
	member  bool
	invited bool
	next    string
	bridge  bool
}

func (s *browserAccessStub) RedeemBrowserHandoff(context.Context, string, uint64, string, string, string, credentials.PublishRunToken) (controlv1.BrowserHandoffResponse, error) {
	response := controlv1.BrowserHandoffResponse{CookieSecret: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", ReturnPath: "/settings", ExpiresAt: time.Now().Add(time.Hour),
		Permission: controlv1.VisitorTokenResponse{VisitorToken: "signed-browser-permission", ExpiresAt: time.Now().Add(5 * time.Minute)}}
	if s.next != "" {
		response.NextUrl = &s.next
		response.Bridge = &s.bridge
	}
	return response, nil
}

func (s *browserAccessStub) CheckBrowserAccess(_ context.Context, _ string, _ uint64, secret string, _ credentials.PublishRunToken) (controlv1.BrowserAccessResponse, error) {
	if secret != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
		return controlv1.BrowserAccessResponse{}, errors.New("invalid browser cookie")
	}
	return controlv1.BrowserAccessResponse{IdentityId: "user-one", DisplayName: "Sam", TeamMember: s.member, VisitAllowed: s.member || s.invited}, nil
}

func (*browserAccessStub) RevokeBrowserAccess(context.Context, string, uint64, string, credentials.PublishRunToken) error {
	return nil
}

func TestBrowserAccessForRunControlOrigins(t *testing.T) {
	for _, test := range []struct {
		origin string
		want   string
	}{
		{"https://control.example.test", "https://control.example.test"},
		{"https://CONTROL.example.test:443/", "https://control.example.test"},
		{"http://localhost:8445", "http://localhost:8445"},
		{"http://LOCALHOST:8445/", "http://localhost:8445"},
		{"http://127.0.0.1:8445", "http://127.0.0.1:8445"},
		{"http://[::1]:8445", "http://[::1]:8445"},
		{"http://control.example.test", ""},
		{"http://192.168.1.1:8445", ""},
		{"http://0.0.0.0:8445", ""},
		{"http://localhost.example.test:8445", ""},
		{"http://127.0.0.1.example.test:8445", ""},
		{"http://user@localhost:8445", ""},
		{"http://localhost:8445/path", ""},
		{"http://localhost:8445?query", ""},
		{"http://localhost:8445#fragment", ""},
		{"http://localhost:65536", ""},
		{"https://user@control.example.test", ""},
		{"https://control.example.test/path", ""},
		{"", ""},
	} {
		t.Run(test.origin, func(t *testing.T) {
			client := &clientcontrol.Client{}
			config := Config{ControlURL: test.origin, BrowserControl: client, PreviewID: "pv_0123456789abcdefghijkl"}
			setup := controlv1.PublishRunSetup{
				PublicUrl:  controlv1.PublicURL{Id: certificateTestPublicURLID, ServiceProtocol: controlv1.Http},
				PublishRun: controlv1.PublishRun{Id: "pr_0123456789abcdefghijkl", PublishRunNumber: 1},
			}
			access := browserAccessForRun(config, setup, "fixture-run-token")
			if test.want == "" {
				if access != nil {
					t.Fatal("invalid control origin enabled browser access")
				}
				return
			}
			if access == nil {
				t.Fatal("valid control origin disabled browser access")
			}
			if access.ControlURL != test.want || access.Client != client || access.PublicURLID != setup.PublicUrl.Id ||
				access.PreviewID != config.PreviewID || access.RunID != setup.PublishRun.Id || access.Number != 1 || access.Token != "fixture-run-token" {
				t.Fatal("browser access lost its control origin or publish run binding")
			}
			navigation := httptest.NewRequest(http.MethodGet, "https://web.example.test/settings?tab=profile", nil)
			navigation.Header.Set("Sec-Fetch-Mode", "navigate")
			navigation.Header.Set("Sec-Fetch-Dest", "document")
			redirect := httptest.NewRecorder()
			if !access.RedirectRestricted(redirect, navigation, true) || redirect.Code != http.StatusSeeOther {
				t.Fatal("restricted browser navigation did not start sign-in")
			}
			login := httptest.NewRequest(http.MethodGet, redirect.Header().Get("Location"), nil)
			response := httptest.NewRecorder()
			if !access.Handle(response, login) || response.Code != http.StatusSeeOther {
				t.Fatal("browser sign-in did not redirect to control")
			}
			location, err := url.Parse(response.Header().Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			query := location.Query()
			location.RawQuery = ""
			if location.String() != test.want+"/v1/browser/login" || query.Get("preview_id") != config.PreviewID ||
				query.Get("public_url_id") != setup.PublicUrl.Id || query.Get("return_path") != "/settings?tab=profile" {
				t.Fatalf("browser sign-in redirect = %q", response.Header().Get("Location"))
			}
			cookies := response.Result().Cookies()
			if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].Domain != "" {
				t.Fatal("browser sign-in weakened the visitor cookie")
			}
		})
	}
}

func TestBrowserAccessForRunRequiresHTTPAndClient(t *testing.T) {
	setup := controlv1.PublishRunSetup{PublicUrl: controlv1.PublicURL{ServiceProtocol: controlv1.Http}}
	config := Config{Control: &clientcontrol.Client{}, ControlURL: "http://localhost:8445"}
	if browserAccessForRun(config, setup, "fixture-run-token") != nil {
		t.Fatal("browser access enabled without a browser-capable control client")
	}
	config.BrowserControl = &clientcontrol.Client{}
	setup.PublicUrl.ServiceProtocol = controlv1.PublicURLServiceProtocol("tcp")
	if browserAccessForRun(config, setup, "fixture-run-token") != nil {
		t.Fatal("browser access enabled for a TCP public URL")
	}
}

func TestBrowserTeamAccessIsAdditiveAndKeepsCookiesOutOfTheLocalService(t *testing.T) {
	cookies := make(chan string, 4)
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		cookies <- request.Header.Get("Cookie")
		response.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	client := &browserAccessStub{member: true}
	access := &httpaccess.Browser{Client: client, PreviewID: "pv_0123456789abcdefghijkl", PublicURLID: "url_0123456789abcdefghijkl",
		RunID: "pr_0123456789abcdefghijkl", Number: 1, ControlURL: "https://control.example.test"}
	authority := &liveHTTPControl{check: func(visitorfixture.HTTPSource) (visitorfixture.HTTPDecision, error) {
		return visitorfixture.HTTPDecision{VisitAllowed: client.member || client.invited, ValidUntil: new(time.Now().Add(5 * time.Minute))}, nil
	}}
	prepareLiveHTTPControl(t, authority)
	server, err := NewPublicURLServer(PublicURLServerConfig{Hostname: "route.example", Port: 443, PublicURLID: access.PublicURLID, Target: upstream.URL,
		BrowserAccess: access, BrowserLoginAvailable: true, VisitorPolicy: authority.policy.Lease(), VisitorTokens: authority.tokens})
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
		serveTestPublicRequest(t, server, response, request)
		return response
	}
	if response := serve("/settings", "", true); response.Code != http.StatusForbidden {
		t.Fatalf("visitor without access = %d", response.Code)
	}
	navigation := httptest.NewRequest(http.MethodGet, "/settings?tab=profile", nil)
	navigation.Host = "route.example"
	navigation.TLS = &tls.ConnectionState{ServerName: "route.example"}
	navigation.Header.Set("Accept", "text/html")
	navigation.Header.Set("Sec-Fetch-Mode", "navigate")
	navigation.Header.Set("Sec-Fetch-Dest", "document")
	navigation = navigation.WithContext(context.WithValue(navigation.Context(), denialContextKey{}, true))
	redirect := httptest.NewRecorder()
	serveTestPublicRequest(t, server, redirect, navigation)
	if redirect.Code != http.StatusSeeOther || redirect.Header().Get("Location") != "/__tnl/team/login?return=%2Fsettings%3Ftab%3Dprofile" {
		t.Fatalf("unallowed browser navigation = %d %q", redirect.Code, redirect.Header().Get("Location"))
	}
	login := serve("/__tnl/team/login?return=%2Fsettings", "", true)
	if login.Code != http.StatusSeeOther || !strings.HasPrefix(login.Header().Get("Location"), "https://control.example.test/v1/browser/login?") {
		t.Fatalf("team login redirect = %d %q", login.Code, login.Header().Get("Location"))
	}
	handoff := serve("/__tnl/team/handoff/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", true)
	if handoff.Code != http.StatusSeeOther || handoff.Header().Get("Location") != "/settings" || len(handoff.Result().Cookies()) != 2 {
		t.Fatalf("browser handoff = %d %q", handoff.Code, handoff.Header().Get("Location"))
	}
	client.next, client.bridge = "https://api.example.test/__tnl/team/handoff/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", true
	bridge := serve("/__tnl/team/handoff/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", true)
	if bridge.Code != http.StatusOK || !strings.Contains(bridge.Body.String(), "http-equiv=\"refresh\"") ||
		!strings.Contains(bridge.Body.String(), client.next) || bridge.Header().Get("Content-Security-Policy") != "default-src 'none'; base-uri 'none'" {
		t.Fatalf("cross-host bridge = %d, %q", bridge.Code, bridge.Header().Get("Content-Security-Policy"))
	}
	visitorCookie := "app_session=ok; " + httpaccess.VisitorTokenCookie + "=" + authority.Credential(t, liveBrowserCookie, false)
	if response := serve("/settings", visitorCookie, true); response.Code != http.StatusOK {
		t.Fatalf("signed-in team member = %d", response.Code)
	}
	if got := <-cookies; got != "app_session=ok" {
		t.Fatalf("local app received browser credential: %q", got)
	}
	authority.Mu.Lock()
	client.member = false
	authority.Mu.Unlock()
	if err := authority.policy.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	if response := serve("/settings", visitorCookie, true); response.Code != http.StatusForbidden {
		t.Fatalf("nonmember without share or IP = %d", response.Code)
	}
	authority.Mu.Lock()
	client.invited = true
	authority.Mu.Unlock()
	if err := authority.policy.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	visitorCookie = "app_session=ok; " + httpaccess.VisitorTokenCookie + "=" + authority.Credential(t, "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA", false)
	if response := serve("/settings", visitorCookie, true); response.Code != http.StatusOK {
		t.Fatalf("invited identity outside the team = %d", response.Code)
	}
	if got := <-cookies; got != "app_session=ok" {
		t.Fatalf("local app received visitor credential: %q", got)
	}
	authority.Mu.Lock()
	client.invited = false
	authority.Mu.Unlock()
	if err := authority.policy.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	if response := serve("/settings", visitorCookie, false); response.Code != http.StatusForbidden {
		t.Fatalf("source IP bypassed visitor access: %d", response.Code)
	}
	if response := serve("/__tnl/team/login", "", true); response.Code != http.StatusSeeOther {
		t.Fatalf("identity sign-in without a preview team grant = %d", response.Code)
	}
	if response := serve("/__tnl/team/login", "", false); response.Code != http.StatusSeeOther {
		t.Fatalf("optional sign-in for allowed IP = %d", response.Code)
	}
}

func TestBrowserSessionRenewalIsIndependentOfRevokedShare(t *testing.T) {
	var shareRevoked atomic.Bool
	var unavailable atomic.Bool
	control := &liveHTTPControl{check: func(input visitorfixture.HTTPSource) (visitorfixture.HTTPDecision, error) {
		if unavailable.Load() {
			return visitorfixture.HTTPDecision{}, clientcontrol.ErrUnavailable
		}
		if input.ShareId != nil && shareRevoked.Load() {
			return visitorfixture.HTTPDecision{}, clientcontrol.ErrUnauthenticated
		}
		return liveHTTPAllowed(time.Now().Add(2 * time.Minute))
	}}
	prepareLiveHTTPControl(t, control)
	_ = control.Credential(t, liveBrowserCookie, false)
	_ = control.Credential(t, liveBrowserCookie, true)
	issuer := &visitorfixture.TokenClient{Issue: control.IssueVisitorToken}
	tokens, err := httpaccess.StartTokens(t.Context(), issuer, control.policy.Lease(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tokens.Close)
	access := &httpaccess.Browser{Subject: visitorscope.Scope{Kind: visitorscope.PublicURL, ID: certificateTestPublicURLID}, Client: control,
		Policy: control.policy, Tokens: tokens}
	for _, revoked := range []bool{false, true} {
		shareRevoked.Store(revoked)
		r := httptest.NewRequest(http.MethodGet, "/__tnl/team/renew?return=%2Fsettings", nil)
		r.AddCookie(&http.Cookie{Name: httpaccess.ShareCookieName, Value: "shr_0123456789abcdefghijkl." + liveBrowserCookie})
		r.AddCookie(&http.Cookie{Name: httpaccess.BrowserCookieName, Value: liveBrowserCookie})
		w := httptest.NewRecorder()
		if !access.Handle(w, r) || w.Code != http.StatusSeeOther || len(w.Result().Cookies()) != 1 {
			t.Fatal("independent session could not prepare visitor access", revoked, w.Code, w.Body.String())
		}
		view, _, _ := control.policy.Lease().Current()
		permission, err := visitortoken.VerifyBearer(visitortoken.Token(w.Result().Cookies()[0].Value), view, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		_, browser := permission.Facts().Subject.(visitortoken.Browser)
		if browser != revoked {
			t.Fatal("renewal did not retain share access or select independent browser access", revoked)
		}
	}
	unavailable.Store(true)
	before := issuer.Calls.Load()
	r := httptest.NewRequest(http.MethodGet, "/__tnl/team/renew?return=%2Fsettings", nil)
	r.AddCookie(&http.Cookie{Name: httpaccess.ShareCookieName, Value: "shr_0123456789abcdefghijkl." + liveBrowserCookie})
	r.AddCookie(&http.Cookie{Name: httpaccess.BrowserCookieName, Value: liveBrowserCookie})
	w := httptest.NewRecorder()
	if !access.Handle(w, r) || w.Code != http.StatusServiceUnavailable || len(w.Result().Cookies()) != 0 || issuer.Calls.Load() != before+1 {
		t.Fatal("issuer outage triggered another credential exchange or issued a visitor cookie", w.Code, issuer.Calls.Load()-before)
	}
}

type reviewerHandoffClient struct {
	*liveHTTPControl
	t *testing.T
}

func (c reviewerHandoffClient) RedeemBrowserHandoff(_ context.Context, _ string, _ uint64, _, shareID, secret string, _ credentials.PublishRunToken) (controlv1.BrowserHandoffResponse, error) {
	if shareID != "shr_0123456789abcdefghijkl" || secret != liveBrowserCookie {
		c.t.Error("publisher lost the share session at sign-in")
	}
	return controlv1.BrowserHandoffResponse{CookieSecret: liveBrowserCookie, ReturnPath: "/settings", ExpiresAt: time.Now().Add(time.Hour),
		Permission: c.Permission(c.t, secret, true)}, nil
}

func TestBrowserHandoffRetainsShareVisitorPermissionForSignedInReviewer(t *testing.T) {
	control := &liveHTTPControl{check: func(visitorfixture.HTTPSource) (visitorfixture.HTTPDecision, error) {
		return liveHTTPAllowed(time.Now().Add(2 * time.Minute))
	}}
	prepareLiveHTTPControl(t, control)
	access := &httpaccess.Browser{Subject: visitorscope.Scope{Kind: visitorscope.PublicURL, ID: certificateTestPublicURLID},
		Client: reviewerHandoffClient{liveHTTPControl: control, t: t}, Tokens: control.tokens, Policy: control.policy}
	r := httptest.NewRequest(http.MethodGet, "/__tnl/team/handoff/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", nil)
	r.AddCookie(&http.Cookie{Name: httpaccess.ShareCookieName, Value: "shr_0123456789abcdefghijkl." + liveBrowserCookie})
	w := httptest.NewRecorder()
	if !access.Handle(w, r) || w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/settings" {
		t.Fatal("share reviewer could not finish identity handoff", w.Code, w.Body.String())
	}
	var token string
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == httpaccess.VisitorTokenCookie {
			token = cookie.Value
		}
	}
	view, _, _ := control.policy.Lease().Current()
	permission, err := visitortoken.VerifyBearer(visitortoken.Token(token), view, time.Now())
	if err != nil || permission.Facts().Subject != (visitortoken.Share{ShareID: "shr_0123456789abcdefghijkl"}) {
		t.Fatal("sign-in replaced share-backed visitor access", err)
	}
}
