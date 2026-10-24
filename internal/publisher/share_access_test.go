package publisher

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type shareDeadlineConn struct {
	net.Conn
	mu       sync.Mutex
	deadline time.Time
}

func (c *shareDeadlineConn) SetDeadline(value time.Time) error {
	c.mu.Lock()
	c.deadline = value
	c.mu.Unlock()
	return c.Conn.SetDeadline(value)
}

func (c *shareDeadlineConn) deadlineIsClear() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deadline.IsZero()
}

type shareAccessTestClient struct {
	shareID    string
	cookie     string
	active     bool
	minted     bool
	permission func() controlv1.VisitorTokenResponse
}

type shareHeaderDecisionClient struct {
	shareID      string
	secret       string
	cookieSecret string
	revoked      bool
}

func preparedShareAuthority(t *testing.T, client *shareAccessTestClient) *liveHTTPControl {
	t.Helper()
	authority := &liveHTTPControl{check: func(controlv1.HTTPVisitorRequest) (controlv1.HTTPVisitorResponse, error) {
		return controlv1.HTTPVisitorResponse{VisitAllowed: client.active && client.minted, ValidUntil: new(time.Now().Add(5 * time.Minute))}, nil
	}}
	prepareLiveHTTPControl(t, authority)
	client.permission = func() controlv1.VisitorTokenResponse { return authority.permission(t, client.cookie, true) }
	return authority
}

func (*shareHeaderDecisionClient) RedeemBrowserHandoff(context.Context, string, uint64, string, credentials.PublishRunToken) (controlv1.BrowserHandoffResponse, error) {
	return controlv1.BrowserHandoffResponse{}, errors.New("no browser handoff")
}

func (*shareHeaderDecisionClient) CheckBrowserAccess(context.Context, string, uint64, string, credentials.PublishRunToken) (controlv1.BrowserAccessResponse, error) {
	return controlv1.BrowserAccessResponse{}, errors.New("no browser session")
}

func (*shareHeaderDecisionClient) RevokeBrowserAccess(context.Context, string, uint64, string, credentials.PublishRunToken) error {
	return nil
}

func TestShareHeaderUsesCurrentDecisionAndIsRemovedBeforeForwarding(t *testing.T) {
	shareID := "shr_0123456789abcdefghijkl"
	secret := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("s", 32)))
	client := &shareHeaderDecisionClient{shareID: shareID, secret: secret}
	authority := &liveHTTPControl{check: func(input controlv1.HTTPVisitorRequest) (controlv1.HTTPVisitorResponse, error) {
		return controlv1.HTTPVisitorResponse{VisitAllowed: !client.revoked && input.ShareId != nil && *input.ShareId == shareID && input.ShareCookieSecret != nil && *input.ShareCookieSecret == secret,
			ValidUntil: new(time.Now().Add(5 * time.Minute))}, nil
	}}
	prepareLiveHTTPControl(t, authority)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(shareAccessHeaderName) != "" || r.Header.Get(visitorTokenHeader) != "" || r.Header.Get("Cookie") != "app_session=ok" {
			t.Errorf("tnl share credential reached local service: header=%q cookie=%q", r.Header.Get(shareAccessHeaderName), r.Header.Get("Cookie"))
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	route, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "route.example", Target: upstream.URL,
		PublicURLID: certificateTestPublicURLID, VisitorPolicy: authority.policy.Lease, VisitorTokens: authority.tokens,
		BrowserAccess: &browserAccess{client: client, runID: "run_test", version: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer route.Close()
	token := authority.credential(t, secret, true)
	visit := func() (int, string) {
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.Host = "route.example"
		request.TLS = &tls.ConnectionState{ServerName: "route.example"}
		request = request.WithContext(context.WithValue(request.Context(), denialContextKey{}, true))
		request.Header.Set(visitorTokenHeader, token)
		request.Header.Set("Cookie", "app_session=ok; __Host-tnl-share=expired")
		response := httptest.NewRecorder()
		route.http.Handler.ServeHTTP(response, request)
		return response.Code, response.Body.String()
	}
	if got, body := visit(); got != http.StatusNoContent {
		t.Fatalf("valid share header = %d: %s", got, body)
	}
	authority.mu.Lock()
	client.revoked = true
	authority.mu.Unlock()
	if err := authority.policy.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	authority.tokens.refresh(t.Context(), nil)
	if got, body := visit(); got != http.StatusForbidden {
		t.Fatalf("revoked share header = %d: %s", got, body)
	}
}

func (*shareAccessTestClient) EnableShareAccess(context.Context, string, uint64, string, credentials.PublishRunToken) error {
	return nil
}

func (c *shareAccessTestClient) RedeemPublishRunShare(_ context.Context, _ string, body controlv1.RedeemShareRequest, _ credentials.PublishRunToken) (controlv1.ShareRedemption, error) {
	if !c.active || body.ShareId == nil || *body.ShareId != c.shareID || body.Secret == nil || *body.Secret != base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("s", 32))) {
		return controlv1.ShareRedemption{}, errors.New("invalid share")
	}
	c.minted = true
	permission := controlv1.VisitorTokenResponse{VisitorToken: "signed-share-permission", ExpiresAt: time.Now().Add(5 * time.Minute)}
	if c.permission != nil {
		permission = c.permission()
	}
	return controlv1.ShareRedemption{
		ShareId: c.shareID, CookieSecret: c.cookie,
		ExpiresAt: time.Now().Add(time.Hour), NextUrl: "https://route.example/",
		Permission: permission,
	}, nil
}

func TestShareHTTPDenialsRedemptionAndCookieIsolation(t *testing.T) {
	upstreamCookies := make(chan string, 2)
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		upstreamCookies <- request.Header.Get("Cookie")
		response.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	client := &shareAccessTestClient{
		shareID: "shr_0123456789abcdefghijkl", cookie: base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("c", 32))), active: true,
	}
	authority := &liveHTTPControl{check: func(controlv1.HTTPVisitorRequest) (controlv1.HTTPVisitorResponse, error) {
		return controlv1.HTTPVisitorResponse{VisitAllowed: client.active && client.minted, ValidUntil: new(time.Now().Add(5 * time.Minute))}, nil
	}}
	prepareLiveHTTPControl(t, authority)
	client.permission = func() controlv1.VisitorTokenResponse { return authority.permission(t, client.cookie, true) }
	access := &shareAccess{client: client, runID: "pr_test", version: 1}
	decisions := &shareHeaderDecisionClient{shareID: client.shareID, cookieSecret: client.cookie}
	route, err := NewPublicURLServer(PublicURLServerConfig{Hostname: "route.example", Target: upstream.URL, ShareAccess: access,
		PublicURLID: certificateTestPublicURLID, VisitorPolicy: authority.policy.Lease, VisitorTokens: authority.tokens,
		BrowserAccess: &browserAccess{client: decisions, runID: "run_test", version: 1}})
	if err != nil {
		t.Fatal(err)
	}
	defer route.Close()
	serve := func(path string, denied bool, cookie string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Host, request.TLS = "route.example", &tls.ConnectionState{ServerName: "route.example"}
		request = request.WithContext(context.WithValue(request.Context(), denialContextKey{}, denied))
		if cookie != "" {
			request.Header.Set("Cookie", cookie)
		}
		response := httptest.NewRecorder()
		route.http.Handler.ServeHTTP(response, request)
		return response
	}
	if got := serve("/", true, ""); got.Code != http.StatusForbidden {
		t.Fatalf("missing share = %d", got.Code)
	}
	secret := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("s", 32)))
	link := "/__tnl/share/" + client.shareID + "." + secret
	redirect := serve(link, true, "")
	if redirect.Code != http.StatusSeeOther || redirect.Header().Get("Location") != "https://route.example/" || redirect.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("share redemption = %d %#v", redirect.Code, redirect.Header())
	}
	issued := redirect.Result().Cookies()
	if len(issued) != 2 {
		t.Fatalf("host-only share cookie = %#v", issued)
	}
	visitorCookies := "app_session=ok"
	for _, cookie := range issued {
		if (cookie.Name != shareCookieName && cookie.Name != visitorTokenCookie) || !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" || cookie.Domain != "" {
			t.Fatalf("host-only visitor cookie = %#v", cookie)
		}
		visitorCookies += "; " + cookie.Name + "=" + cookie.Value
	}
	if got := serve("/api", true, visitorCookies); got.Code != http.StatusNoContent {
		t.Fatalf("share visitor = %d %s", got.Code, got.Body.String())
	}
	if got := <-upstreamCookies; got != "app_session=ok" {
		t.Fatalf("local service saw share cookie: %q", got)
	}
	if got := serve("/", true, visitorCookies); got.Code != http.StatusNoContent {
		t.Fatalf("prepared share permission did not admit another request: %d", got.Code)
	}
	if got := <-upstreamCookies; got != "app_session=ok" {
		t.Fatalf("local service saw share cookie on another request: %q", got)
	}
	authority.mu.Lock()
	client.active = false
	authority.mu.Unlock()
	decisions.revoked = true
	if err := authority.policy.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	authority.tokens.refresh(t.Context(), nil)
	if got := serve("/", true, visitorCookies); got.Code != http.StatusForbidden {
		t.Fatalf("revoked visitor = %d", got.Code)
	}
	if got := serve("/", false, visitorCookies); got.Code != http.StatusForbidden {
		t.Fatalf("source IP bypassed share revocation: %d", got.Code)
	}
}

func TestShareHandoffBridgeResetsLongRedirectChains(t *testing.T) {
	redemption := controlv1.ShareRedemption{
		ShareId:      "shr_0123456789abcdefghijkl",
		CookieSecret: base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("c", 32))),
		NextUrl:      "https://api.example.test/__tnl/share/handoff/token?step=8&next=9",
		ExpiresAt:    time.Now().Add(time.Hour), Bridge: true,
		Permission: controlv1.VisitorTokenResponse{VisitorToken: "signed-share-permission", ExpiresAt: time.Now().Add(5 * time.Minute)},
	}
	response := httptest.NewRecorder()
	shareRedirect(response, redemption)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `step=8&amp;next=9`) ||
		!strings.Contains(response.Body.String(), "http-equiv=\"refresh\"") ||
		response.Header().Get("Referrer-Policy") != "no-referrer" || len(response.Result().Cookies()) != 2 {
		t.Fatalf("long handoff bridge = %d, %q, %#v", response.Code, response.Body.String(), response.Header())
	}
}

func TestShareVisitorClearsDeniedTLSDeadlineAfterRealHandshake(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/" || request.Header.Get("Cookie") != "app_session=ok" {
			t.Errorf("upstream request path=%q cookies=%q", request.URL.Path, request.Header.Get("Cookie"))
		}
		response.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	client := &shareAccessTestClient{
		shareID: "shr_0123456789abcdefghijkl", cookie: base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("c", 32))), active: true,
	}
	authority := preparedShareAuthority(t, client)
	access := &shareAccess{client: client, runID: "pr_test", version: 1}
	route, err := newTestPublicURLServer(t, PublicURLServerConfig{
		VisitorPolicy: authority.policy.Lease, VisitorTokens: authority.tokens,
		Hostname: "route.example", Target: upstream.URL, ShareAccess: access,
		Certificate: publicURLTestCertificate(t, "route.example"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := route.Start(); err != nil {
		t.Fatal(err)
	}
	defer route.Close()
	ingress, publisher := net.Pipe()
	tracked := &shareDeadlineConn{Conn: publisher}
	_ = ingress.SetDeadline(time.Now().Add(10 * time.Second))
	done := make(chan struct{})
	go func() { route.handleVisitor(tracked, true); close(done) }()
	defer func() { _ = ingress.Close(); <-done }()
	header, err := proxyproto.Encode(proxyproto.Header{
		Source: netip.MustParseAddrPort("192.0.2.10:1234"), Destination: netip.MustParseAddrPort("127.0.0.1:443"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ingress.Write(header); err != nil {
		t.Fatal(err)
	}
	visitor := tls.Client(ingress, &tls.Config{ServerName: "route.example", InsecureSkipVerify: true}) // test certificate is self-signed.
	if err := visitor.Handshake(); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(visitor)
	link := "/__tnl/share/" + client.shareID + "." + base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("s", 32)))
	if _, err := fmt.Fprintf(visitor, "GET %s HTTP/1.1\r\nHost: route.example\r\n\r\n", link); err != nil {
		t.Fatal(err)
	}
	first, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, first.Body)
	_ = first.Body.Close()
	if first.StatusCode != http.StatusSeeOther || len(first.Cookies()) != 2 || !tracked.deadlineIsClear() {
		t.Fatalf("share link did not clear denied TLS deadline: %d, cookies=%v", first.StatusCode, first.Cookies())
	}
	cookies := "app_session=ok"
	for _, cookie := range first.Cookies() {
		cookies += "; " + cookie.Name + "=" + cookie.Value
	}
	if _, err := fmt.Fprintf(visitor, "GET / HTTP/1.1\r\nHost: route.example\r\nCookie: %s\r\n\r\n", cookies); err != nil {
		t.Fatal(err)
	}
	second, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	_ = second.Body.Close()
	if second.StatusCode != http.StatusNoContent {
		t.Fatalf("shared request over same TLS connection = %d", second.StatusCode)
	}
}
