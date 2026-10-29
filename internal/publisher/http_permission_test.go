package publisher

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

func httpPermissionFixture(t *testing.T, anonymous bool) (*visitorlease.Lease, visitorlease.Update, visitortoken.Token) {
	t.Helper()
	return httpPermissionFixtureClock(t, anonymous, nil)
}

func httpPermissionFixtureClock(t *testing.T, anonymous bool, clock func() time.Time) (*visitorlease.Lease, visitorlease.Update, visitortoken.Token) {
	t.Helper()
	scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: "url_" + strings.Repeat("A", 22)}
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("h", 32)))
	policy, err := visitorlease.New(scope, clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(policy.Close)
	now := time.Now()
	update := visitorlease.Update{View: visitortoken.View{Issuer: "https://control.example.test", Scope: scope, Hostname: "preview.example.test", Port: 443,
		VisitorPolicyRevision: 1, ObservedAt: now, ValidUntil: now.Add(10 * time.Second)}.WithVerificationKeys(map[string]ed25519.PublicKey{"http": key.Public().(ed25519.PublicKey)}),
		KeyRevision: 1, Enabled: true, Anonymous: anonymous, Snapshot: true}
	if err := policy.Apply(policy.Begin(), update); err != nil {
		t.Fatal(err)
	}
	token, err := visitortoken.Sign(update.View.Issuer, "http", key, visitortoken.Permission{Scope: scope, Hostname: update.View.Hostname, Port: 443, VisitorPolicyRevision: 1,
		Subject: visitortoken.Browser{IdentityID: "ident_" + strings.Repeat("B", 22), SessionID: "cs_" + strings.Repeat("C", 22)}, ExpiresAt: time.Now().Add(5 * time.Minute)}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return policy, update, token
}

func permissionRequest() *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "preview.example.test"
	r.TLS = &tls.ConnectionState{ServerName: "preview.example.test"}
	r.RemoteAddr = "192.0.2.1:1234"
	return r
}

func TestLocalHTTPPermissionRejectsInvalidSuppliedCredentialsWithoutAnonymousFallback(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		policy, _, token := httpPermissionFixture(t, true)
		for _, test := range []struct {
			name   string
			change func(*http.Request)
		}{
			{"empty header", func(r *http.Request) { r.Header.Set(visitorTokenHeader, "") }},
			{"malformed token", func(r *http.Request) { r.Header.Set(visitorTokenHeader, "opaque-old-secret") }},
			{"duplicate headers", func(r *http.Request) { r.Header[visitorTokenHeader] = []string{token.Reveal(), token.Reveal()} }},
			{"header and cookie", func(r *http.Request) {
				r.Header.Set(visitorTokenHeader, token.Reveal())
				r.AddCookie(&http.Cookie{Name: visitorTokenCookie, Value: token.Reveal()})
			}},
			{"duplicate cookies", func(r *http.Request) {
				r.Header.Set("Cookie", visitorTokenCookie+"="+token.Reveal()+"; "+visitorTokenCookie+"="+token.Reveal())
			}},
			{"malformed cookie", func(r *http.Request) { r.Header.Set("Cookie", visitorTokenCookie+"=\"unterminated") }},
			{"retired share header", func(r *http.Request) { r.Header.Set(shareAccessHeaderName, "share.old-secret") }},
			{"retired browser cookie", func(r *http.Request) {
				r.AddCookie(&http.Cookie{Name: browserAccessCookieName, Value: liveBrowserCookie})
			}},
			{"retired share cookie", func(r *http.Request) { r.AddCookie(&http.Cookie{Name: shareCookieName, Value: "share.old-secret"}) }},
		} {
			r := permissionRequest()
			test.change(r)
			if _, err := localHTTPPermission(r, policy, nil); !errors.Is(err, visitortoken.ErrToken) {
				t.Fatalf("%s: supplied credential fell back to anonymous access: %v", test.name, err)
			}
		}
	})
}

func TestLocalHTTPPermissionUsesPreparedHostPolicyAndTrustedSource(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		policy, _, token := httpPermissionFixture(t, false)
		r := permissionRequest()
		r.Header.Set(visitorTokenHeader, token.Reveal())
		r.Header.Set("Authorization", "Bearer application-secret")
		r.Header.Set("X-Forwarded-For", "203.0.113.99")
		trusted := &visitorSession{visitor: Visitor{Source: netip.MustParseAddrPort("198.51.100.7:5678")}}
		r = r.WithContext(context.WithValue(r.Context(), visitorSessionKey{}, trusted))
		for range 100 {
			permission, err := localHTTPPermission(r, policy, nil)
			if err != nil || permission.anonymous || permission.source != trusted.visitor.Source.Addr() {
				t.Fatal("prepared request changed its signed permission or trusted source", err)
			}
			if r.Header.Get("Authorization") != "Bearer application-secret" {
				t.Fatal("visitor verification consumed application authentication")
			}
		}
		r.Host = "sibling.example.test"
		if _, err := localHTTPPermission(r, policy, nil); !errors.Is(err, visitortoken.ErrBinding) {
			t.Fatal("token crossed an HTTP authority boundary", err)
		}
	})
}

func TestLocalHTTPPermissionPolicyExpiryStopsSignedAndAnonymousRequests(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		policy, _, token := httpPermissionFixture(t, true)
		var guards []*publicHTTPGuard
		var requests []*http.Request
		for _, signed := range []bool{false, true} {
			r := permissionRequest()
			if signed {
				r.Header.Set(visitorTokenHeader, token.Reveal())
			}
			permission, err := localHTTPPermission(r, policy, nil)
			if err != nil {
				t.Fatal(err)
			}
			guard, bound, err := guardLocalHTTPRequest(httptest.NewRecorder(), r, policy, permission)
			if err != nil {
				t.Fatal(err)
			}
			guards, requests = append(guards, guard), append(requests, bound)
		}
		time.Sleep(10 * time.Second)
		synctest.Wait()
		for index, guard := range guards {
			if !errors.Is(requests[index].Context().Err(), context.Canceled) {
				t.Fatal("expired local policy retained an application request")
			}
			func() {
				defer func() {
					if recover() != http.ErrAbortHandler {
						t.Error("expired response ended cleanly")
					}
				}()
				guard.finish()
			}()
		}
		if _, err := localHTTPPermission(permissionRequest(), policy, nil); !errors.Is(err, visitortoken.ErrPolicy) {
			t.Fatal("expired policy admitted a new anonymous visitor", err)
		}
	})
}

func TestLocalHTTPPermissionRevocationKeepsUnrelatedHTTP2StreamAndConnection(t *testing.T) {
	policy, update, token := httpPermissionFixture(t, true)
	certificate := publicURLTestCertificate(t, update.View.Hostname)
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		permission, err := localHTTPPermission(r, policy, nil)
		if err != nil {
			http.Error(w, "visitor denied", http.StatusForbidden)
			return
		}
		guard, bound, err := guardLocalHTTPRequest(w, r, policy, permission)
		if err != nil {
			http.Error(w, "visitor denied", http.StatusForbidden)
			return
		}
		defer guard.finish()
		if bound.Header.Get("Authorization") != "application-secret" {
			t.Error("visitor checks changed application authentication")
		}
		if bound.Header.Get(visitorTokenHeader) != "" || bound.Header.Get("Cookie") != "app=unchanged" {
			t.Error("visitor credential reached the application or changed its cookie")
		}
		_, _ = io.WriteString(guard, "prefix")
		guard.Flush()
		if r.URL.Path == "/signed" {
			<-bound.Context().Done()
			return
		}
		select {
		case <-bound.Context().Done():
			return
		case <-release:
			_, _ = io.WriteString(guard, "finished")
		}
	}))
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer func() { unblock(); server.Close() }()
	var dials atomic.Int64
	transport := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{RootCAs: rootsForCertificate(t, certificate)},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			if dials.Add(1) != 1 {
				return nil, errors.New("visitor tried to replace its HTTP/2 connection")
			}
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	open := func(path string, signed bool) *http.Response {
		t.Helper()
		r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+update.View.Hostname+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Authorization", "application-secret")
		r.Header.Set("Cookie", "app=unchanged")
		if signed {
			r.Header.Set(visitorTokenHeader, token.Reveal())
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusOK || response.ProtoMajor != 2 {
			t.Fatalf("request was not admitted as HTTP/2: %d %s", response.StatusCode, response.Proto)
		}
		prefix := make([]byte, len("prefix"))
		if _, err := io.ReadFull(response.Body, prefix); err != nil || string(prefix) != "prefix" {
			t.Fatal("request did not begin streaming", err)
		}
		return response
	}
	first, sibling := open("/signed", true), open("/anonymous", false)
	defer first.Body.Close()
	defer sibling.Body.Close()
	update.View.VisitorPolicyRevision++
	now := time.Now()
	update.View.ObservedAt, update.View.ValidUntil = now, now.Add(10*time.Second)
	if err := policy.Apply(policy.Begin(), update); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, first.Body); err == nil {
		t.Fatal("revoked signed request ended as a successful response")
	}
	// a later anonymous request shares the same still-live HTTP/2 connection.
	third := open("/future", false)
	_ = third.Body.Close()
	if dials.Load() != 1 {
		t.Fatal("revocation closed the shared visitor connection")
	}
	unblock()
	body, err := io.ReadAll(sibling.Body)
	if err != nil || string(body) != "finished" {
		t.Fatal("revocation interrupted the unrelated HTTP/2 request", err)
	}
}
