package httpaccess

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/browserpage"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type browserHandoffClient struct {
	BrowserClient
	redeem func(context.Context, string, string, credentials.ServiceRunToken, controlv1.ServiceBrowserRequest) (controlv1.BrowserHandoffResponse, error)
}

func (c browserHandoffClient) RedeemServiceBrowserHandoff(ctx context.Context, service, run string, token credentials.ServiceRunToken, request controlv1.ServiceBrowserRequest) (controlv1.BrowserHandoffResponse, error) {
	return c.redeem(ctx, service, run, token, request)
}

func prepareBrowserSessions(t *testing.T, control *visitorfixture.HTTPControl) (*Browser, *visitorfixture.TokenClient) {
	t.Helper()
	control.Init()
	secret, shareID := visitorfixture.BrowserCookie, "shr_0123456789abcdefghijkl"
	control.Sources["browser_session::"+secret] = visitorfixture.HTTPSource{BrowserCookieSecret: &secret}
	control.Sources["share_session:"+shareID+":"+secret] = visitorfixture.HTTPSource{ShareId: &shareID, ShareCookieSecret: &secret}
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: "svc_0123456789abcdefghijkl"}
	runID := "srun_0123456789abcdefghijkl"
	policy, err := PreparePolicy(t.Context(), control, scope, runID, 7, "run-secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(policy.Close)
	issuer := &visitorfixture.TokenClient{Issue: control.IssueVisitorToken}
	tokens, err := StartTokens(t.Context(), issuer, policy.Lease(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tokens.Close)
	return &Browser{Subject: scope, Client: &clientcontrol.Client{}, PreviewID: "pv_0123456789abcdefghijkl",
		RunID: runID, Number: 7, Token: credentials.ServiceRunToken("run-secret"), ControlURL: "https://control.example.test",
		Policy: policy, Tokens: tokens}, issuer
}

func TestBrowserLoginKeepsPreviewAndServiceBinding(t *testing.T) {
	control := &visitorfixture.HTTPControl{Check: func(visitorfixture.HTTPSource) (visitorfixture.HTTPDecision, error) {
		return sessionAllowed(time.Now().Add(2 * time.Minute))
	}}
	access, _ := prepareBrowserSessions(t, control)
	request := httptest.NewRequest(http.MethodGet, "/__tnl/team/login?return=%2Fsettings%3Ftab%3Dprofile", nil)
	response := httptest.NewRecorder()
	if !access.Handle(response, request) || response.Code != http.StatusSeeOther {
		t.Fatal("browser sign-in did not redirect to control", response.Code, response.Body.String())
	}
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	query := location.Query()
	location.RawQuery = ""
	if location.String() != access.ControlURL+"/v1/browser/service-login" || query.Get("preview_id") != access.PreviewID ||
		query.Get("service_id") != access.Subject.ID || query.Get("return_path") != "/settings?tab=profile" || query.Has("public_url_id") {
		t.Fatalf("browser sign-in redirect = %q", response.Header().Get("Location"))
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != LoginAttemptCookieName || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].Domain != "" {
		t.Fatal("browser sign-in weakened the host-bound visitor cookie")
	}
}

func TestBrowserHandoffInstallsHostBoundCookiesAndBridges(t *testing.T) {
	control := &visitorfixture.HTTPControl{Check: func(visitorfixture.HTTPSource) (visitorfixture.HTTPDecision, error) {
		return sessionAllowed(time.Now().Add(2 * time.Minute))
	}}
	access, _ := prepareBrowserSessions(t, control)
	var next string
	expires := time.Now().Add(time.Hour)
	access.Client = browserHandoffClient{redeem: func(ctx context.Context, service, run string, token credentials.ServiceRunToken, request controlv1.ServiceBrowserRequest) (controlv1.BrowserHandoffResponse, error) {
		if service != access.Subject.ID || run != access.RunID || token != access.Token || request.RunNumber != access.Number ||
			request.Secret != visitorfixture.BrowserCookie || request.ShareId != nil || request.ShareCookieSecret != nil {
			t.Fatal("browser handoff lost its exact service run or acquired a share")
		}
		permission, err := control.IssueVisitorToken(ctx, controlv1.VisitorTokenRequest{
			Resource: controlv1.VisitorResourceScope{Kind: "service", Id: service}, Source: visitorfixture.BrowserSource(visitorfixture.BrowserCookie),
		})
		result := controlv1.BrowserHandoffResponse{CookieSecret: visitorfixture.BrowserCookie, ReturnPath: "/settings",
			ExpiresAt: expires, Permission: &permission}
		if next != "" {
			result.NextUrl, result.Bridge = &next, new(true)
		}
		return result, err
	}}
	serve := func() *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, "/__tnl/team/handoff/"+visitorfixture.BrowserCookie, nil)
		response := httptest.NewRecorder()
		if !access.Handle(response, request) {
			t.Fatal("browser handoff was not handled")
		}
		return response
	}
	response := serve()
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/settings" || len(response.Result().Cookies()) != 2 {
		t.Fatal("browser handoff did not install both visitor and browser cookies", response.Code, response.Body.String())
	}
	for _, cookie := range response.Result().Cookies() {
		if !cookie.Secure || !cookie.HttpOnly || cookie.Domain != "" || cookie.Path != "/" {
			t.Fatal("browser handoff weakened its host-bound cookie", cookie.Name)
		}
	}
	next = "https://api.example.test/__tnl/team/handoff/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	bridge := serve()
	if bridge.Code != http.StatusOK || !strings.Contains(bridge.Body.String(), `http-equiv="refresh"`) ||
		!strings.Contains(bridge.Body.String(), next) || bridge.Header().Get("Content-Security-Policy") != browserpage.ContentSecurityPolicy ||
		!strings.Contains(bridge.Body.String(), "data:font/woff2;base64,") {
		t.Fatal("cross-host browser bridge changed", bridge.Code, bridge.Header(), bridge.Body.String())
	}
}

func TestBrowserHandoffErrorsNegotiatePresentation(t *testing.T) {
	for _, accept := range []string{"", "text/html"} {
		request := httptest.NewRequest(http.MethodGet, "/__tnl/team/handoff/invalid", nil)
		request.Header.Set("Accept", accept)
		response := httptest.NewRecorder()
		if !(&Browser{}).Handle(response, request) || response.Code != http.StatusServiceUnavailable {
			t.Fatal("unavailable browser sign-in changed its status")
		}
		if accept == "" {
			if response.Body.String() != "browser sign-in is unavailable\n" {
				t.Fatal("plain browser failure changed")
			}
		} else if !strings.Contains(response.Body.String(), "<h1>service unavailable</h1>") ||
			response.Header().Get("Content-Security-Policy") != browserpage.ContentSecurityPolicy {
			t.Fatal("browser failure is not styled")
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/__tnl/team/session", nil)
	request.Header.Set("Accept", "text/html")
	response := httptest.NewRecorder()
	(&Browser{}).Handle(response, request)
	if response.Header().Get("Content-Type") != "text/plain; charset=utf-8" ||
		response.Body.String() != "browser sign-in is unavailable\n" {
		t.Fatal("browser session API negotiated HTML")
	}
}

func TestBrowserIdentityOnlyHandoffDoesNotGrantVisitorPermission(t *testing.T) {
	control := &visitorfixture.HTTPControl{Check: func(visitorfixture.HTTPSource) (visitorfixture.HTTPDecision, error) {
		return visitorfixture.HTTPDecision{}, nil
	}}
	access, issuer := prepareBrowserSessions(t, control)
	expires := time.Now().Add(time.Hour).Truncate(time.Second)
	access.Client = browserHandoffClient{redeem: func(_ context.Context, service, run string, token credentials.ServiceRunToken, request controlv1.ServiceBrowserRequest) (controlv1.BrowserHandoffResponse, error) {
		if service != access.Subject.ID || run != access.RunID || token != access.Token || request.RunNumber != access.Number ||
			request.Secret != visitorfixture.BrowserCookie || request.ShareId != nil || request.ShareCookieSecret != nil {
			t.Fatal("identity-only handoff changed the service run or acquired a share")
		}
		return controlv1.BrowserHandoffResponse{CookieSecret: visitorfixture.BrowserCookie, ReturnPath: "/settings", ExpiresAt: expires}, nil
	}}
	request := httptest.NewRequest(http.MethodGet, "/__tnl/team/handoff/"+visitorfixture.BrowserCookie, nil)
	request.AddCookie(&http.Cookie{Name: VisitorTokenCookie, Value: "obsolete-visitor-permission"})
	response := httptest.NewRecorder()
	if !access.Handle(response, request) || response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/settings" {
		t.Fatal("identity-only browser sign-in did not finish", response.Code, response.Body.String())
	}
	var identity, clearedVisitor *http.Cookie
	cookies := response.Result().Cookies()
	for _, cookie := range cookies {
		switch cookie.Name {
		case BrowserCookieName:
			identity = cookie
		case VisitorTokenCookie:
			clearedVisitor = cookie
		}
	}
	if len(cookies) != 2 || identity == nil || identity.Value != visitorfixture.BrowserCookie || !identity.Expires.Equal(expires) ||
		!identity.Secure || !identity.HttpOnly || identity.Path != "/" || identity.Domain != "" || identity.SameSite != http.SameSiteLaxMode {
		t.Fatal("identity-only handoff did not install a secure host-bound browser session", cookies)
	}
	if clearedVisitor == nil || clearedVisitor.Value != "" || clearedVisitor.MaxAge >= 0 || issuer.Calls.Load() != 0 {
		t.Fatal("identity-only handoff retained or issued visitor permission", clearedVisitor, issuer.Calls.Load())
	}
	view, _, _ := access.Policy.Lease().Current()
	visit := visitorfixture.Request()
	visit.Host, visit.TLS.ServerName = view.Hostname, view.Hostname
	visit.AddCookie(identity)
	_, guard, _, err := AuthorizeRequest(httptest.NewRecorder(), visit, access.Policy.Lease(), access.Tokens)
	if guard != nil {
		guard.Finish()
	}
	if !errors.Is(err, visitortoken.ErrToken) {
		t.Fatal("browser identity alone authorized a restricted service", err)
	}
}

func TestBrowserSessionRenewalIsIndependentOfRevokedShare(t *testing.T) {
	var shareRevoked, unavailable atomic.Bool
	control := &visitorfixture.HTTPControl{Check: func(input visitorfixture.HTTPSource) (visitorfixture.HTTPDecision, error) {
		if unavailable.Load() {
			return visitorfixture.HTTPDecision{}, clientcontrol.ErrUnavailable
		}
		if input.ShareId != nil && shareRevoked.Load() {
			return visitorfixture.HTTPDecision{}, clientcontrol.ErrUnauthenticated
		}
		return sessionAllowed(time.Now().Add(2 * time.Minute))
	}}
	access, issuer := prepareBrowserSessions(t, control)
	renew := func() *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, "/__tnl/team/renew?return=%2Fsettings", nil)
		request.AddCookie(&http.Cookie{Name: ShareCookieName, Value: "shr_0123456789abcdefghijkl." + visitorfixture.BrowserCookie})
		request.AddCookie(&http.Cookie{Name: BrowserCookieName, Value: visitorfixture.BrowserCookie})
		response := httptest.NewRecorder()
		if !access.Handle(response, request) {
			t.Fatal("browser session renewal was not handled")
		}
		return response
	}
	for _, revoked := range []bool{false, true} {
		shareRevoked.Store(revoked)
		response := renew()
		cookies := response.Result().Cookies()
		if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/settings" || len(cookies) != 1 || cookies[0].Name != VisitorTokenCookie {
			t.Fatal("independent browser session could not prepare visitor access", revoked, response.Code, response.Body.String())
		}
		view, _, _ := access.Policy.Lease().Current()
		permission, err := visitortoken.VerifyBearer(visitortoken.Token(cookies[0].Value), view, time.Now())
		if err != nil || permission.Facts().Scope != access.Subject {
			t.Fatal("session renewal changed the service binding", err)
		}
		if revoked {
			if _, browser := permission.Facts().Subject.(visitortoken.Browser); !browser {
				t.Fatal("revoked share blocked the independent browser session")
			}
		} else if permission.Facts().Subject != (visitortoken.Share{ShareID: "shr_0123456789abcdefghijkl"}) {
			t.Fatal("renewal replaced a current share session with browser identity")
		}
	}
	unavailable.Store(true)
	before := issuer.Calls.Load()
	response := renew()
	if response.Code != http.StatusServiceUnavailable || len(response.Result().Cookies()) != 0 || issuer.Calls.Load() != before+1 {
		t.Fatal("issuer outage tried another credential or issued a visitor cookie", response.Code, issuer.Calls.Load()-before)
	}
}

func TestBrowserHandoffRetainsShareVisitorPermissionForSignedInReviewer(t *testing.T) {
	control := &visitorfixture.HTTPControl{Check: func(visitorfixture.HTTPSource) (visitorfixture.HTTPDecision, error) {
		return sessionAllowed(time.Now().Add(2 * time.Minute))
	}}
	access, issuer := prepareBrowserSessions(t, control)
	shareID := "shr_0123456789abcdefghijkl"
	access.Client = browserHandoffClient{redeem: func(ctx context.Context, service, run string, token credentials.ServiceRunToken, request controlv1.ServiceBrowserRequest) (controlv1.BrowserHandoffResponse, error) {
		if service != access.Subject.ID || run != access.RunID || token != access.Token || request.RunNumber != access.Number ||
			request.Secret != visitorfixture.BrowserCookie || request.ShareId == nil || *request.ShareId != shareID ||
			request.ShareCookieSecret == nil || *request.ShareCookieSecret != visitorfixture.BrowserCookie {
			t.Fatal("publisher lost the service run or reviewer's share session at sign-in")
		}
		source, err := json.Marshal(controlv1.VisitorTokenShareSessionSource{Kind: controlv1.VisitorTokenShareSession, ShareId: shareID, Secret: *request.ShareCookieSecret})
		if err != nil {
			t.Fatal(err)
		}
		permission, err := control.IssueVisitorToken(ctx, controlv1.VisitorTokenRequest{
			Resource: controlv1.VisitorResourceScope{Kind: "service", Id: service}, Source: source,
		})
		return controlv1.BrowserHandoffResponse{CookieSecret: visitorfixture.BrowserCookie, ReturnPath: "/settings",
			ExpiresAt: time.Now().Add(time.Hour), Permission: &permission}, err
	}}
	request := httptest.NewRequest(http.MethodGet, "/__tnl/team/handoff/"+visitorfixture.BrowserCookie, nil)
	request.AddCookie(&http.Cookie{Name: ShareCookieName, Value: shareID + "." + visitorfixture.BrowserCookie})
	response := httptest.NewRecorder()
	if !access.Handle(response, request) || response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/settings" {
		t.Fatal("share reviewer could not finish identity handoff", response.Code, response.Body.String())
	}
	var token string
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == VisitorTokenCookie {
			token = cookie.Value
		}
	}
	view, _, _ := access.Policy.Lease().Current()
	permission, err := visitortoken.VerifyBearer(visitortoken.Token(token), view, time.Now())
	if err != nil || permission.Facts().Scope != access.Subject || permission.Facts().Subject != (visitortoken.Share{ShareID: shareID}) || issuer.Calls.Load() != 0 {
		t.Fatal("sign-in replaced share-backed visitor permission", err, issuer.Calls.Load())
	}
}
