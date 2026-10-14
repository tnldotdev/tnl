package publisher

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/proxyproto"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func restrictedRequest(server *PublicURLServer, method, path, accept, dest, mode, cookie string, denied bool) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, nil)
	request.Host = "route.example"
	request.TLS = &tls.ConnectionState{ServerName: "route.example"}
	request.Header.Set("Accept", accept)
	request.Header.Set("Sec-Fetch-Dest", dest)
	request.Header.Set("Sec-Fetch-Mode", mode)
	request.Header.Set("Cookie", cookie)
	request = request.WithContext(context.WithValue(request.Context(), denialContextKey{}, denied))
	response := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(response, request)
	return response
}

func TestRestrictedBrowserDocumentKeeps403AndOffersOnlyAvailableAction(t *testing.T) {
	const path = "/settings?next=%2Ffoo%3Fa%3D1&tab=profile%26name%3Cok%3E"
	for _, test := range []struct {
		name              string
		runtime, signedIn bool
		err               error
		status            int
		action            string
	}{
		{name: "signed out", runtime: true, status: 303},
		{name: "wrong account", runtime: true, signedIn: true, status: 403, action: "switch account"},
		{name: "no OIDC runtime", status: 403},
		{name: "authority unavailable", runtime: true, signedIn: true, err: controlclient.ErrUnavailable, status: 503},
		{name: "unknown forbidden", runtime: true, signedIn: true, err: &controlclient.ProblemError{Status: 403, Problem: controlv1.Problem{Code: "unknown"}}, status: 503},
	} {
		t.Run(test.name, func(t *testing.T) {
			var browser *browserAccess
			if test.runtime {
				browser = &browserAccess{client: &browserAccessStub{err: test.err}}
			}
			server, err := NewPublicURLServer(PublicURLServerConfig{Hostname: "route.example", BrowserAccess: browser, Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("denied document reached local service") })})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			cookie := ""
			if test.signedIn {
				cookie = browserAccessCookieName + "=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
			}
			response := restrictedRequest(server, "GET", path, "text/html", "document", "navigate", cookie, true)
			body := response.Body.String()
			if response.Code != test.status || strings.Contains(body, "http-equiv") || strings.Contains(body, "<script") {
				t.Fatalf("restricted document = %d %s", response.Code, body)
			}
			if test.status == 303 {
				want := "/__tnl/team/login?automatic=1&return=" + url.QueryEscape(path)
				if response.Header().Get("Location") != want || response.Header().Get("Cache-Control") != "no-store" {
					t.Fatalf("missing automatic sign-in: %#v", response.Header())
				}
				return
			}
			if response.Header().Get("Location") != "" {
				t.Fatalf("denial redirected: %#v", response.Header())
			}
			if test.status == 403 && (response.Header().Get("Tnl-Error-Code") != string(diagnostic.IPPolicyDenied) || !strings.Contains(body, diagnostic.HelpURL(diagnostic.IPPolicyDenied))) {
				t.Fatal("restricted document lost its diagnostic code or help URL")
			}
			if strings.Contains(body, `class="secondary"`) != (test.action != "") || strings.Contains(body, "Sam") || strings.Contains(body, "user-one") {
				t.Fatalf("incorrect or identifying secondary action: %s", body)
			}
			if test.action != "" {
				if !strings.Contains(body, "this public url is restricted") || !strings.Contains(body, test.action) {
					t.Fatalf("missing generic action: %s", body)
				}
				want := "/__tnl/team/login?return=" + url.QueryEscape(path)
				if test.signedIn {
					want = "/__tnl/team/switch-account?return=" + url.QueryEscape(path)
				}
				if !strings.Contains(html.UnescapeString(body), want) {
					t.Fatalf("return path was changed: %s", body)
				}
			}
		})
	}
}

func TestRestrictedAssetsAndAPINeverStartBrowserSignIn(t *testing.T) {
	server, err := NewPublicURLServer(PublicURLServerConfig{Hostname: "route.example", BrowserAccess: &browserAccess{client: &browserAccessStub{}}, Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("denied asset reached local service") })})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	for _, test := range []struct{ method, path, accept, dest, mode string }{
		{"GET", "/api/data", "application/json", "", "cors"},
		{"GET", "/app.js", "text/html", "script", "no-cors"},
		{"GET", "/app.css", "*/*", "style", "no-cors"},
		{"GET", "/fetch", "text/html", "", "cors"},
		{"POST", "/api/action", "text/html", "document", "navigate"},
		{"HEAD", "/", "text/html", "document", "navigate"},
	} {
		response := restrictedRequest(server, test.method, test.path, test.accept, test.dest, test.mode, "", true)
		if response.Code != 403 || response.Header().Get("Location") != "" || strings.Contains(response.Body.String(), "/__tnl/team/") {
			t.Fatalf("asset/API got sign-in action: %s %s %d %s", test.method, test.path, response.Code, response.Body.String())
		}
	}
	websocket := httptest.NewRequest(http.MethodGet, "/live", nil)
	websocket.Host = "route.example"
	websocket.TLS = &tls.ConnectionState{ServerName: "route.example"}
	websocket.Header.Set("Accept", "text/html")
	websocket.Header.Set("Sec-Fetch-Dest", "document")
	websocket.Header.Set("Sec-Fetch-Mode", "navigate")
	websocket.Header.Set("Upgrade", "websocket")
	websocket = websocket.WithContext(context.WithValue(websocket.Context(), denialContextKey{}, true))
	response := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(response, websocket)
	if response.Code != 403 || response.Header().Get("Location") != "" {
		t.Fatalf("websocket handshake redirected to sign-in: %d %#v", response.Code, response.Header())
	}
}

func TestAutomaticBrowserReturnChecksPermissionOnce(t *testing.T) {
	const original = "/settings?next=%2Ffoo%3Fa%3D1&tab=profile%26name"
	path := "/__tnl/team/return?to=" + url.QueryEscape(original)
	access := &browserAccessStub{visitAllowed: true}
	server, err := NewPublicURLServer(PublicURLServerConfig{Hostname: "route.example", BrowserAccess: &browserAccess{client: access},
		Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("internal return path reached app") })})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	for _, test := range []struct {
		name, cookie string
		allowed      bool
		status       int
	}{
		{name: "cookie did not stick", status: 403},
		{name: "permitted identity", cookie: browserAccessCookieName + "=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", allowed: true, status: 303},
		{name: "wrong identity", cookie: browserAccessCookieName + "=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", status: 403},
	} {
		t.Run(test.name, func(t *testing.T) {
			access.visitAllowed = test.allowed
			response := restrictedRequest(server, "GET", path, "text/html", "document", "navigate", test.cookie, true)
			if response.Code != test.status {
				t.Fatalf("automatic return = %d %s", response.Code, response.Body.String())
			}
			if test.allowed {
				if response.Header().Get("Location") != original {
					t.Fatalf("original path changed: %q", response.Header().Get("Location"))
				}
			} else if response.Header().Get("Location") != "" || !strings.Contains(response.Body.String(), "this public url is restricted") {
				t.Fatalf("denied return restarted sign-in: %d %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestAuthorizedBrowserIPAndShareStillProxyNormally(t *testing.T) {
	cookieSecret := strings.Repeat("s", 32)
	shareID := "shr_0123456789abcdefghijkl"
	shareDigest := sha256.Sum256([]byte(cookieSecret))
	for _, admission := range []string{"browser owner", "IP", "share"} {
		t.Run(admission, func(t *testing.T) {
			forwarded := make(chan string, 1)
			upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				forwarded <- request.URL.RequestURI() + " " + request.Header.Get("Cookie")
				response.WriteHeader(200)
			}))
			defer upstream.Close()
			shares := &shareAccess{confirmed: time.Now(), shares: map[string]cachedShare{shareID: {expiresAt: time.Now().Add(time.Hour), cookies: map[[32]byte]struct{}{shareDigest: {}}}}}
			browser := &browserAccess{client: &browserAccessStub{visitAllowed: admission == "browser owner"}}
			server, err := NewPublicURLServer(PublicURLServerConfig{Hostname: "route.example", Target: upstream.URL, BrowserAccess: browser, ShareAccess: shares})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			cookie := "app_session=ok; " + browserAccessCookieName + "=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
			if admission == "share" {
				cookie += "; " + shareCookieName + "=" + shareID + "." + base64.RawURLEncoding.EncodeToString([]byte(cookieSecret))
			}
			response := restrictedRequest(server, "GET", "/settings?tab=profile", "text/html", "document", "navigate", cookie, admission != "IP")
			if response.Code != 200 || response.Header().Get("Location") != "" {
				t.Fatalf("authorized visit did not proxy: %d", response.Code)
			}
			if got := awaitPublisherTest(t, forwarded); got != "/settings?tab=profile app_session=ok" {
				t.Fatalf("local service got changed URL or browser credential: %q", got)
			}
		})
	}
}

type browserTLSFlowClient struct {
	PublicURLControlClient
	allowed    atomic.Bool
	revoked    atomic.Bool
	returnPath string
}

func (*browserTLSFlowClient) EnableBrowserAccess(context.Context, string, uint64, credentials.PublishRunToken) error {
	return nil
}
func (c *browserTLSFlowClient) RedeemBrowserHandoff(context.Context, string, uint64, string, credentials.PublishRunToken) (controlv1.BrowserHandoffResponse, error) {
	c.revoked.Store(false)
	return controlv1.BrowserHandoffResponse{CookieSecret: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", ReturnPath: c.returnPath, ExpiresAt: time.Now().Add(time.Hour)}, nil
}
func (c *browserTLSFlowClient) CheckBrowserAccess(context.Context, string, uint64, string, credentials.PublishRunToken) (controlv1.BrowserAccessResponse, error) {
	if c.revoked.Load() {
		return controlv1.BrowserAccessResponse{}, &controlclient.ProblemError{Status: 403, Problem: controlv1.Problem{Code: controlv1.Forbidden}}
	}
	return controlv1.BrowserAccessResponse{IdentityId: "identity_private", DisplayName: "private account name", VisitAllowed: c.allowed.Load()}, nil
}
func (c *browserTLSFlowClient) RevokeBrowserAccess(context.Context, string, uint64, string, credentials.PublishRunToken) error {
	c.revoked.Store(true)
	return nil
}

func TestRestrictedBrowserSignInAndSwitchAccountOverRealTLS(t *testing.T) {
	const path = "/settings?next=%2Ffoo%3Fa%3D1&tab=profile"
	forwarded := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		forwarded <- request.URL.RequestURI() + " " + request.Header.Get("Cookie")
		response.WriteHeader(200)
	}))
	defer upstream.Close()
	control := &browserTLSFlowClient{returnPath: path}
	control.allowed.Store(true)
	setup := controlv1.PublishRunSetup{PublicUrl: controlv1.PublicURL{Id: "url_app", Purpose: controlv1.App, PublicUrlScope: controlv1.Member}, PublishRun: controlv1.PublishRun{Id: "pr_app", PublishRunNumber: 1}}
	browser := browserAccessForRun(Config{Control: control, ControlURL: "https://control.example", BrowserLoginAvailable: true, Purpose: controlv1.App}, setup, "publisher-token")
	if browser == nil {
		t.Fatal("ordinary app publish has no browser runtime")
	}
	server, err := NewPublicURLServer(PublicURLServerConfig{Hostname: "route.example", Target: upstream.URL, BrowserAccess: browser, Certificate: publicURLTestCertificate(t, "route.example")})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ingress, publisher := net.Pipe()
	tracked := &shareDeadlineConn{Conn: publisher}
	_ = ingress.SetDeadline(time.Now().Add(10 * time.Second))
	done := make(chan struct{})
	go func() { defer close(done); server.handleVisitor(tracked, true) }()
	defer func() { _ = ingress.Close(); awaitPublisherTest(t, done) }()
	header, err := proxyproto.Encode(proxyproto.Header{Source: netip.MustParseAddrPort("192.0.2.10:1234"), Destination: netip.MustParseAddrPort("127.0.0.1:443")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ingress.Write(header); err != nil {
		t.Fatal(err)
	}
	visitor := tls.Client(ingress, &tls.Config{ServerName: "route.example", InsecureSkipVerify: true}) // the fixture certificate is self-signed.
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if err := visitor.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(visitor)
	exchange := func(method, path, cookie, origin string) (*http.Response, string) {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, method, "https://route.example"+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Accept", "text/html")
		request.Header.Set("Sec-Fetch-Dest", "document")
		request.Header.Set("Sec-Fetch-Mode", "navigate")
		request.Header.Set("Cookie", cookie)
		if origin != "" {
			request.Header.Set("Origin", origin)
		}
		if err := request.Write(visitor); err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(reader, request)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		return response, string(body)
	}
	response, _ := exchange("GET", path, "", "")
	login := "/__tnl/team/login?automatic=1&return=" + url.QueryEscape(path)
	if response.StatusCode != 303 || response.Header.Get("Location") != login {
		t.Fatalf("TLS document did not start sign-in: %d %q", response.StatusCode, response.Header.Get("Location"))
	}
	response, _ = exchange("GET", login, "", "")
	authorize, err := url.Parse(response.Header.Get("Location"))
	automaticReturn := "/__tnl/team/return?to=" + url.QueryEscape(path)
	if err != nil || response.StatusCode != 303 || authorize.Host != "control.example" || authorize.Query().Get("return_path") != automaticReturn || authorize.Query().Has("preview_id") {
		t.Fatalf("ordinary publish login scope = %d %q", response.StatusCode, response.Header.Get("Location"))
	}
	control.returnPath = automaticReturn
	response, _ = exchange("GET", "/__tnl/team/handoff/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", "")
	if response.StatusCode != 303 || response.Header.Get("Location") != automaticReturn || len(response.Cookies()) != 1 || !tracked.deadlineIsClear() {
		t.Fatal("handoff did not install a host-bound cookie and clear the denied TLS deadline")
	}
	cookie := "app_session=ok; " + response.Cookies()[0].Name + "=" + response.Cookies()[0].Value
	response, _ = exchange("GET", automaticReturn, cookie, "")
	if response.StatusCode != 303 || response.Header.Get("Location") != path {
		t.Fatalf("authorized handoff did not return to original path: %d %q", response.StatusCode, response.Header.Get("Location"))
	}
	response, _ = exchange("GET", path, cookie, "")
	if response.StatusCode != 200 {
		t.Fatalf("owner browser did not reach app: %d", response.StatusCode)
	}
	if got := awaitPublisherTest(t, forwarded); got != path+" app_session=ok" {
		t.Fatalf("app received changed URL or browser secret: %q", got)
	}
	control.allowed.Store(false)
	response, body := exchange("GET", automaticReturn, cookie, "")
	if response.StatusCode != 403 || response.Header.Get("Location") != "" || !strings.Contains(body, "switch account") {
		t.Fatalf("denied handoff looped to app: %d %s", response.StatusCode, body)
	}
	response, body = exchange("GET", path, cookie, "")
	switchPath := "/__tnl/team/switch-account?return=" + url.QueryEscape(path)
	if response.StatusCode != 403 || response.Header.Get("Location") != "" || !strings.Contains(body, `method="post"`) || !strings.Contains(html.UnescapeString(body), switchPath) || strings.Contains(body, "private account name") {
		t.Fatalf("wrong-account document = %d %s", response.StatusCode, body)
	}
	response, _ = exchange("POST", switchPath, cookie, "https://other.example")
	if response.StatusCode != 403 || control.revoked.Load() {
		t.Fatal("cross-origin request switched account")
	}
	response, _ = exchange("POST", switchPath, cookie, "https://route.example")
	if response.StatusCode != 303 || !control.revoked.Load() || len(response.Cookies()) != 1 || response.Cookies()[0].MaxAge != -1 {
		t.Fatal("switch account did not revoke and clear the local browser session")
	}
	response, _ = exchange("GET", response.Header.Get("Location"), "", "")
	authorize, err = url.Parse(response.Header.Get("Location"))
	if err != nil || response.StatusCode != 303 || authorize.Query().Get("prompt") != "select_account" || authorize.Query().Get("return_path") != path {
		t.Fatalf("switch account lost provider selection or return query: %d %q", response.StatusCode, response.Header.Get("Location"))
	}
}

func TestBrowserReturnPathRejectsRedirectsAndKeepsEncodedQuery(t *testing.T) {
	for _, path := range []string{"//other.example", "/%2Fother.example", "/%5Cother.example", "/%0D%0Aheader", "https://other.example", "/bad path", "/#fragment", "/%zz"} {
		if validBrowserPath(path) {
			t.Fatalf("unsafe browser return path accepted: %q", path)
		}
	}
	if !validBrowserPath("/settings?next=%2Ffoo%3Fa%3D1&tab=profile%26name") {
		t.Fatal("safe encoded return query rejected")
	}
}

func TestBrowserSignInFailuresDoNotRedirectOrClearSession(t *testing.T) {
	for _, test := range []struct {
		name, method, path string
		client             browserAccessStub
		status             int
	}{
		{name: "handoff unavailable", method: "GET", path: "/__tnl/team/handoff/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", client: browserAccessStub{handoffErr: controlclient.ErrUnavailable}, status: 503},
		{name: "unknown handoff forbidden", method: "GET", path: "/__tnl/team/handoff/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", client: browserAccessStub{handoffErr: &controlclient.ProblemError{Status: 403, Problem: controlv1.Problem{Code: "unknown"}}}, status: 503},
		{name: "expired handoff", method: "GET", path: "/__tnl/team/handoff/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", client: browserAccessStub{handoffErr: controlclient.ErrNotFound}, status: 403},
		{name: "switch logout unavailable", method: "POST", path: "/__tnl/team/switch-account?return=%2Fsettings", client: browserAccessStub{logoutErr: controlclient.ErrUnavailable}, status: 503},
		{name: "invalid switch path", method: "POST", path: "/__tnl/team/switch-account?return=%2F%252Fother.example", status: 400},
		{name: "invalid login prompt", method: "GET", path: "/__tnl/team/login?return=%2Fsettings&prompt=login", status: 400},
		{name: "invalid automatic login mode", method: "GET", path: "/__tnl/team/login?return=%2Fsettings&automatic=maybe", status: 400},
		{name: "unsafe automatic return", method: "GET", path: "/__tnl/team/return?to=%2F%2Fother.example", status: 400},
		{name: "unsafe next host", method: "GET", path: "/__tnl/team/handoff/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", client: browserAccessStub{next: "http://other.example/"}, status: 503},
	} {
		t.Run(test.name, func(t *testing.T) {
			access := &browserAccess{client: &test.client, controlURL: "https://control.example"}
			request := httptest.NewRequest(test.method, test.path, nil)
			request.Host = "route.example"
			request.Header.Set("Origin", "https://route.example")
			request.AddCookie(&http.Cookie{Name: browserAccessCookieName, Value: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"})
			response := httptest.NewRecorder()
			access.handle(response, request)
			if response.Code != test.status || response.Header().Get("Location") != "" || len(response.Result().Cookies()) != 0 {
				t.Fatalf("sign-in failure changed session or started authentication: %d %#v", response.Code, response.Header())
			}
		})
	}
}
