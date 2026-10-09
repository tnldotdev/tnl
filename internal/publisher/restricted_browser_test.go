package publisher

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
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
		{name: "signed out", runtime: true, status: 403, action: "sign in"},
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
			if response.Code != test.status || response.Header().Get("Location") != "" || strings.Contains(body, "http-equiv") || strings.Contains(body, "<script") {
				t.Fatalf("restricted document = %d %s", response.Code, body)
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
	allowed atomic.Bool
	revoked atomic.Bool
}

func (*browserTLSFlowClient) EnableBrowserAccess(context.Context, string, uint64, credentials.PublishRunToken) error {
	return nil
}
func (c *browserTLSFlowClient) RedeemBrowserHandoff(context.Context, string, uint64, string, credentials.PublishRunToken) (controlv1.BrowserHandoffResponse, error) {
	c.revoked.Store(false)
	return controlv1.BrowserHandoffResponse{CookieSecret: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", ReturnPath: "/settings?next=%2Ffoo%3Fa%3D1&tab=profile", ExpiresAt: time.Now().Add(time.Hour)}, nil
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
	control := &browserTLSFlowClient{}
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
	response, body := exchange("GET", path, "", "")
	login := "/__tnl/team/login?return=" + url.QueryEscape(path)
	if response.StatusCode != 403 || response.Header.Get("Location") != "" || !strings.Contains(html.UnescapeString(body), login) {
		t.Fatalf("TLS document automatically authenticated: %d %s", response.StatusCode, body)
	}
	response, _ = exchange("GET", login, "", "")
	authorize, err := url.Parse(response.Header.Get("Location"))
	if err != nil || response.StatusCode != 303 || authorize.Host != "control.example" || authorize.Query().Get("return_path") != path || authorize.Query().Has("preview_id") {
		t.Fatalf("ordinary publish login scope = %d %q", response.StatusCode, response.Header.Get("Location"))
	}
	response, _ = exchange("GET", "/__tnl/team/handoff/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", "")
	if response.StatusCode != 303 || response.Header.Get("Location") != path || len(response.Cookies()) != 1 || !tracked.deadlineIsClear() {
		t.Fatal("handoff did not install a host-bound cookie and clear the denied TLS deadline")
	}
	cookie := "app_session=ok; " + response.Cookies()[0].Name + "=" + response.Cookies()[0].Value
	response, _ = exchange("GET", path, cookie, "")
	if response.StatusCode != 200 {
		t.Fatalf("owner browser did not reach app: %d", response.StatusCode)
	}
	if got := awaitPublisherTest(t, forwarded); got != path+" app_session=ok" {
		t.Fatalf("app received changed URL or browser secret: %q", got)
	}
	control.allowed.Store(false)
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

func TestAppReadyAccessInfoReflectsInstalledBrowserRuntimeAndServerPolicy(t *testing.T) {
	control := newCertificateTestControl(t, "route.example", publicURLCertificateTestPlan())
	control.store = certificateTestStore(t, filepath.Join(t.TempDir(), "state"))
	config := startCertificateTLSYamuxHarness(t, control)
	config.Control = &browserCapabilityControl{certificateTestControl: control, browserAccessClient: &browserAccessStub{}, enable: func(string, uint64, credentials.PublishRunToken) error { return nil }}
	config.ControlURL, config.BrowserLoginAvailable = "https://control.example", true
	control.setup.PublicUrl.AllowedIpPrefixes = new([]string{"192.0.2.10/32"})
	reachedReady := errors.New("reached ready")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	err := runSession(ctx, config, control.setup, func(info AccessInfo) error {
		if !info.BrowserSignInAvailable || info.PublicURLScope != controlv1.Member || len(info.AllowedIPPrefixes) != 1 || info.AllowedIPPrefixes[0] != "192.0.2.10/32" || info.PreviewID != "" {
			t.Errorf("ready access does not reflect this app run: %+v", info)
		}
		return reachedReady
	})
	if !errors.Is(err, reachedReady) {
		t.Fatalf("ready access callback: %v", err)
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
