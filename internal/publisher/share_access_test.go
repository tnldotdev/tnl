package publisher

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
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

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/proxyproto"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
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
	shareID string
	cookie  string
	active  bool
	minted  bool
}

func (*shareAccessTestClient) EnableShareAccess(context.Context, string, uint64, string, credentials.PublishRunToken) error {
	return nil
}

func (c *shareAccessTestClient) GetPublishRunShareState(context.Context, string, uint64, credentials.PublishRunToken) (controlv1.PublishRunShareState, error) {
	if !c.active {
		return controlv1.PublishRunShareState{Shares: []controlv1.PublisherShare{}}, nil
	}
	secret := sha256.Sum256([]byte(strings.Repeat("s", 32)))
	entry := controlv1.PublisherShare{
		ShareId: c.shareID, ExpiresAt: time.Now().Add(time.Hour),
		SecretFingerprint: hex.EncodeToString(secret[:]), CookieHashes: []string{},
	}
	if c.minted {
		raw, _ := base64.RawURLEncoding.DecodeString(c.cookie)
		hash := sha256.Sum256(raw)
		entry.CookieHashes = []string{hex.EncodeToString(hash[:])}
	}
	return controlv1.PublishRunShareState{Shares: []controlv1.PublisherShare{entry}}, nil
}

func (c *shareAccessTestClient) RedeemPublishRunShare(_ context.Context, _ string, body controlv1.RedeemShareRequest, _ credentials.PublishRunToken) (controlv1.ShareRedemption, error) {
	if !c.active || body.ShareId == nil || *body.ShareId != c.shareID || body.Secret == nil || *body.Secret != base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("s", 32))) {
		return controlv1.ShareRedemption{}, errors.New("invalid share")
	}
	c.minted = true
	return controlv1.ShareRedemption{
		ShareId: c.shareID, CookieSecret: c.cookie,
		ExpiresAt: time.Now().Add(time.Hour), NextUrl: "https://route.example/",
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
	access := &shareAccess{client: client, runID: "pr_test", version: 1}
	if err := access.refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	route, err := NewPublicURLServer(PublicURLServerConfig{Hostname: "route.example", Target: upstream.URL, ShareAccess: access})
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
	if len(issued) != 1 || issued[0].Name != shareCookieName || !issued[0].Secure || !issued[0].HttpOnly || issued[0].Path != "/" || issued[0].Domain != "" {
		t.Fatalf("host-only share cookie = %#v", issued)
	}
	visitorCookies := "app_session=ok; " + issued[0].Name + "=" + issued[0].Value
	if got := serve("/api", true, visitorCookies); got.Code != http.StatusNoContent {
		t.Fatalf("share visitor = %d %s", got.Code, got.Body.String())
	}
	if got := <-upstreamCookies; got != "app_session=ok" {
		t.Fatalf("local service saw share cookie: %q", got)
	}
	access.mu.Lock()
	access.confirmed = time.Now().Add(-shareStateFreshness - time.Second)
	access.mu.Unlock()
	if got := serve("/", true, visitorCookies); got.Code != http.StatusForbidden {
		t.Fatalf("stale share state still admitted visitor: %d", got.Code)
	}
	if err := access.refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	client.active = false
	if err := access.refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := serve("/", true, visitorCookies); got.Code != http.StatusForbidden {
		t.Fatalf("revoked visitor = %d", got.Code)
	}
	if got := serve("/", false, visitorCookies); got.Code != http.StatusNoContent {
		t.Fatalf("allowed IP lost access after share revocation: %d", got.Code)
	}
	if got := <-upstreamCookies; got != "app_session=ok" {
		t.Fatalf("local service saw tnl cookie on allowed IP: %q", got)
	}
}

func TestShareHandoffBridgeResetsLongRedirectChains(t *testing.T) {
	redemption := controlv1.ShareRedemption{
		ShareId:      "shr_0123456789abcdefghijkl",
		CookieSecret: base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("c", 32))),
		NextUrl:      "https://api.example.test/__tnl/share/handoff/token?step=8&next=9",
		ExpiresAt:    time.Now().Add(time.Hour), Bridge: true,
	}
	response := httptest.NewRecorder()
	shareRedirect(response, redemption)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `step=8&amp;next=9`) ||
		!strings.Contains(response.Body.String(), "http-equiv=\"refresh\"") ||
		response.Header().Get("Referrer-Policy") != "no-referrer" || len(response.Result().Cookies()) != 1 {
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
	access := &shareAccess{client: client, runID: "pr_test", version: 1}
	if err := access.refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	route, err := NewPublicURLServer(PublicURLServerConfig{
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
	if first.StatusCode != http.StatusSeeOther || len(first.Cookies()) != 1 || !tracked.deadlineIsClear() {
		t.Fatalf("share link did not clear denied TLS deadline: %d, cookies=%v", first.StatusCode, first.Cookies())
	}
	if _, err := fmt.Fprintf(visitor, "GET / HTTP/1.1\r\nHost: route.example\r\nCookie: app_session=ok; %s=%s\r\n\r\n", first.Cookies()[0].Name, first.Cookies()[0].Value); err != nil {
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
