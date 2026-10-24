package publisher

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type browserAccessStub struct {
	member  bool
	invited bool
	next    string
	bridge  bool
}

func (s *browserAccessStub) RedeemBrowserHandoff(context.Context, string, uint64, string, credentials.PublishRunToken) (controlv1.BrowserHandoffResponse, error) {
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

func TestBrowserTeamAccessIsAdditiveAndKeepsCookiesOutOfTheLocalService(t *testing.T) {
	cookies := make(chan string, 4)
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		cookies <- request.Header.Get("Cookie")
		response.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	client := &browserAccessStub{member: true}
	access := &browserAccess{client: client, previewID: "pv_0123456789abcdefghijkl", publicURLID: "url_0123456789abcdefghijkl",
		runID: "pr_0123456789abcdefghijkl", version: 1, controlURL: "https://control.example.test"}
	authority := &liveHTTPControl{check: func(controlv1.HTTPVisitorRequest) (controlv1.HTTPVisitorResponse, error) {
		return controlv1.HTTPVisitorResponse{VisitAllowed: client.member || client.invited, ValidUntil: new(time.Now().Add(5 * time.Minute))}, nil
	}}
	prepareLiveHTTPControl(t, authority)
	server, err := NewPublicURLServer(PublicURLServerConfig{Hostname: "route.example", PublicURLID: access.publicURLID, Target: upstream.URL,
		BrowserAccess: access, BrowserLoginAvailable: true, VisitorPolicy: authority.policy.Lease, VisitorTokens: authority.tokens})
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
	navigation.Header.Set("Sec-Fetch-Mode", "navigate")
	navigation.Header.Set("Sec-Fetch-Dest", "document")
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
	if handoff.Code != http.StatusSeeOther || handoff.Header().Get("Location") != "/settings" || len(handoff.Result().Cookies()) != 2 {
		t.Fatalf("browser handoff = %d %q", handoff.Code, handoff.Header().Get("Location"))
	}
	client.next, client.bridge = "https://api.example.test/__tnl/team/handoff/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", true
	bridge := serve("/__tnl/team/handoff/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", true)
	if bridge.Code != http.StatusOK || !strings.Contains(bridge.Body.String(), "http-equiv=\"refresh\"") ||
		!strings.Contains(bridge.Body.String(), client.next) || bridge.Header().Get("Content-Security-Policy") != "default-src 'none'; base-uri 'none'" {
		t.Fatalf("cross-host bridge = %d, %q", bridge.Code, bridge.Header().Get("Content-Security-Policy"))
	}
	visitorCookie := "app_session=ok; " + visitorTokenCookie + "=" + authority.credential(t, liveBrowserCookie, false)
	if response := serve("/settings", visitorCookie, true); response.Code != http.StatusOK {
		t.Fatalf("signed-in team member = %d", response.Code)
	}
	if got := <-cookies; got != "app_session=ok" {
		t.Fatalf("local app received browser credential: %q", got)
	}
	authority.mu.Lock()
	client.member = false
	authority.mu.Unlock()
	if err := authority.policy.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	authority.tokens.refresh(t.Context(), nil)
	if response := serve("/settings", visitorCookie, true); response.Code != http.StatusForbidden {
		t.Fatalf("nonmember without share or IP = %d", response.Code)
	}
	authority.mu.Lock()
	client.invited = true
	authority.mu.Unlock()
	if err := authority.policy.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	visitorCookie = "app_session=ok; " + visitorTokenCookie + "=" + authority.credential(t, "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA", false)
	if response := serve("/settings", visitorCookie, true); response.Code != http.StatusOK {
		t.Fatalf("invited identity outside the team = %d", response.Code)
	}
	if got := <-cookies; got != "app_session=ok" {
		t.Fatalf("local app received visitor credential: %q", got)
	}
	authority.mu.Lock()
	client.invited = false
	authority.mu.Unlock()
	if err := authority.policy.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	authority.tokens.refresh(t.Context(), nil)
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
