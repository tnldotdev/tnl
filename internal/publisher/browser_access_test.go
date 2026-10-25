package publisher

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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

func TestBrowserAndShareSessionsReprepareWithoutExpiredVisitorCookie(t *testing.T) {
	for _, share := range []bool{false, true} {
		name := "browser"
		if share {
			name = "share"
		}
		t.Run(name, func(t *testing.T) {
			var revoked atomic.Bool
			var unavailable atomic.Bool
			var deadline atomic.Int64
			deadline.Store(time.Now().Add(45 * time.Second).UnixNano())
			control := &liveHTTPControl{check: func(controlv1.HTTPVisitorRequest) (controlv1.HTTPVisitorResponse, error) {
				if unavailable.Load() {
					return controlv1.HTTPVisitorResponse{}, clientcontrol.ErrUnavailable
				}
				if revoked.Load() {
					return controlv1.HTTPVisitorResponse{}, clientcontrol.ErrUnauthenticated
				}
				return liveHTTPAllowed(time.Unix(0, deadline.Load()))
			}}
			prepareLiveHTTPControl(t, control)
			access := &browserAccess{subject: visitorscope.Scope{Kind: visitorscope.PublicURL, ID: certificateTestPublicURLID}, client: control,
				policy: control.policy, tokens: control.tokens}
			server, err := NewPublicURLServer(PublicURLServerConfig{Hostname: "route.example", PublicURLID: certificateTestPublicURLID,
				Handler:       http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
				BrowserAccess: access, BrowserLoginAvailable: true, VisitorPolicy: control.policy.Lease, VisitorTokens: control.tokens})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = server.Close() })
			secret := liveBrowserCookie
			cookie := browserAccessCookieName + "=" + secret
			if share {
				cookie = shareCookieName + "=shr_0123456789abcdefghijkl." + secret
			}
			_ = control.credential(t, secret, share)
			control.tokens.mu.Lock()
			for _, source := range control.tokens.sources {
				source.used = time.Now().Add(-6 * time.Minute)
			}
			control.tokens.mu.Unlock()
			control.tokens.refresh(t.Context(), nil)
			serve := func(path, cookies string, navigate bool) *httptest.ResponseRecorder {
				r := httptest.NewRequest(http.MethodGet, path, nil)
				r.Host = "route.example"
				r.TLS = &tls.ConnectionState{ServerName: "route.example"}
				r.Header.Set("Cookie", cookies)
				if navigate {
					r.Header.Set("Sec-Fetch-Mode", "navigate")
					r.Header.Set("Sec-Fetch-Dest", "document")
				}
				r = r.WithContext(context.WithValue(r.Context(), denialContextKey{}, true))
				w := httptest.NewRecorder()
				server.http.Handler.ServeHTTP(w, r)
				return w
			}
			if denied := serve("/settings", cookie, false); denied.Code != http.StatusForbidden {
				t.Fatal("session cookie bypassed missing visitor permission", denied.Code)
			}
			redirect := serve("/settings", cookie, true)
			if redirect.Code != http.StatusSeeOther || redirect.Header().Get("Location") != "/__tnl/team/renew?return=%2Fsettings" {
				t.Fatal("top-level visit did not offer session re-preparation", redirect.Code, redirect.Header().Get("Location"))
			}
			renewed := serve("/__tnl/team/renew?return=%2Fsettings", cookie, false)
			if renewed.Code != http.StatusSeeOther || renewed.Header().Get("Location") != "/settings" || len(renewed.Result().Cookies()) != 1 || renewed.Result().Cookies()[0].Name != visitorTokenCookie {
				t.Fatal("valid session was not exchanged for a visitor cookie", renewed.Code, renewed.Body.String())
			}
			visitor := cookie + "; " + visitorTokenCookie + "=" + renewed.Result().Cookies()[0].Value
			if allowed := serve("/settings", visitor, false); allowed.Code != http.StatusOK {
				t.Fatal("prepared visitor was denied", allowed.Code)
			}
			deadline.Store(time.Now().Add(2 * time.Minute).UnixNano())
			control.tokens.refresh(t.Context(), nil)
			control.tokens.mu.Lock()
			var extended bool
			for _, source := range control.tokens.sources {
				extended = source.reprepared && source.parentDeadline.After(renewed.Result().Cookies()[0].Expires)
			}
			control.tokens.mu.Unlock()
			if !extended {
				t.Fatal("re-prepared session did not keep renewing beyond its first short token")
			}
			unavailable.Store(true)
			if unavailableResponse := serve("/__tnl/team/renew?return=%2Fsettings", cookie, false); unavailableResponse.Code != http.StatusServiceUnavailable || len(unavailableResponse.Result().Cookies()) != 0 {
				t.Fatal("issuer outage looked like session revocation", unavailableResponse.Code)
			}
			unavailable.Store(false)
			revoked.Store(true)
			if rejected := serve("/__tnl/team/renew?return=%2Fsettings", cookie, false); rejected.Code != http.StatusForbidden || len(rejected.Result().Cookies()) != 0 {
				t.Fatal("revoked parent renewed visitor permission", rejected.Code)
			}
		})
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
		Permission: c.permission(c.t, secret, true)}, nil
}

func TestBrowserHandoffRetainsShareVisitorPermissionForSignedInReviewer(t *testing.T) {
	control := &liveHTTPControl{check: func(controlv1.HTTPVisitorRequest) (controlv1.HTTPVisitorResponse, error) {
		return liveHTTPAllowed(time.Now().Add(2 * time.Minute))
	}}
	prepareLiveHTTPControl(t, control)
	access := &browserAccess{subject: visitorscope.Scope{Kind: visitorscope.PublicURL, ID: certificateTestPublicURLID},
		client: reviewerHandoffClient{liveHTTPControl: control, t: t}, tokens: control.tokens, policy: control.policy}
	r := httptest.NewRequest(http.MethodGet, "/__tnl/team/handoff/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", nil)
	r.AddCookie(&http.Cookie{Name: shareCookieName, Value: "shr_0123456789abcdefghijkl." + liveBrowserCookie})
	w := httptest.NewRecorder()
	if !access.handle(w, r) || w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/settings" {
		t.Fatal("share reviewer could not finish identity handoff", w.Code, w.Body.String())
	}
	var token string
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == visitorTokenCookie {
			token = cookie.Value
		}
	}
	view, _, _ := control.policy.Lease.Current()
	permission, err := visitortoken.VerifyBearer(visitortoken.Token(token), view, time.Now())
	if err != nil || permission.Subject != (visitortoken.Share{ShareID: "shr_0123456789abcdefghijkl"}) {
		t.Fatal("sign-in replaced share-backed visitor access", err)
	}
}
