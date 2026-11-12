package publisher

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"golang.org/x/net/websocket"
)

const liveBrowserCookie = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

type liveHTTPControl struct {
	browserAccessStub
	visitorfixture.HTTPControl
	check  func(visitorfixture.HTTPSource) (visitorfixture.HTTPDecision, error)
	policy *httpaccess.Policy
	tokens *httpaccess.Tokens
}

func liveHTTPAllowed(until time.Time) (visitorfixture.HTTPDecision, error) {
	return visitorfixture.HTTPDecision{VisitAllowed: true, ValidUntil: &until}, nil
}

func prepareLiveHTTPControl(t *testing.T, control *liveHTTPControl) {
	t.Helper()
	control.Check = control.check
	control.Init()
	policy, err := httpaccess.PreparePolicy(t.Context(), control, visitorscope.Scope{Kind: visitorscope.PublicURL, ID: certificateTestPublicURLID}, "pr_0123456789abcdefghijkl", 1, "fixture-run-token", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(policy.Close)
	control.policy = policy
	control.tokens, err = httpaccess.StartTokens(t.Context(), control, policy.Lease(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(control.tokens.Close)
	control.Lease = policy.Lease()
	browser := &httpaccess.Browser{Policy: policy, Tokens: control.tokens}
	control.Prepare = func(ctx context.Context, source json.RawMessage, response controlv1.VisitorTokenResponse, parent time.Time) error {
		_, err := browser.PrepareToken(ctx, source, response, parent)
		return err
	}
}

func startLiveHTTPRoute(t *testing.T, control *liveHTTPControl, handler http.Handler) *PublicURLServer {
	t.Helper()
	prepareLiveHTTPControl(t, control)
	route, err := NewPublicURLServer(PublicURLServerConfig{Hostname: "route.example", Certificate: visitorfixture.Certificate(t, "route.example"), Handler: handler,
		PublicURLID: certificateTestPublicURLID, PublishRunID: "pr_0123456789abcdefghijkl", PublishRunNumber: 1, VisitorPolicy: control.policy.Lease(), VisitorTokens: control.tokens,
		VisitorSourceKey: control.policy.SourceKey(),
		BrowserAccess:    &httpaccess.Browser{Client: control, RunID: "original-run", Number: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if err := route.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })
	return route
}

func TestPublicHTTPLiveRenewalAndHTTP2Isolation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var revoked bool
		control := &liveHTTPControl{check: func(input visitorfixture.HTTPSource) (visitorfixture.HTTPDecision, error) {
			if input.BrowserCookieSecret != nil && *input.BrowserCookieSecret == liveBrowserCookie && revoked {
				return visitorfixture.HTTPDecision{}, clientcontrol.ErrUnauthenticated
			}
			return liveHTTPAllowed(time.Now().Add(2 * time.Minute))
		}}
		var requests atomic.Int32
		keepSibling := make(chan struct{})
		route := startLiveHTTPRoute(t, control, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			if r.Header.Get("Authorization") != "app-secret" || r.Header.Get("Cookie") != "app=unchanged" {
				t.Error("application credentials changed")
			}
			w.Header().Set("X-App", "unchanged")
			_, _ = io.WriteString(w, "prefix")
			w.(http.Flusher).Flush()
			if r.URL.Query().Get("id") == "sibling" {
				select {
				case <-r.Context().Done():
					return
				case <-keepSibling:
					_, _ = io.WriteString(w, "still streaming")
					w.(http.Flusher).Flush()
				}
			}
			<-r.Context().Done()
		}))
		client := mixedVisitorClient(t, route, true, false)
		client.Timeout = 0
		request := func(id, cookie string) *http.Response {
			r, _ := http.NewRequest("POST", "https://route.example/stream?id="+id, strings.NewReader("original body"))
			r.Header.Set("Authorization", "app-secret")
			r.Header.Set("Cookie", "app=unchanged; "+httpaccess.VisitorTokenCookie+"="+control.Credential(t, cookie, false))
			response, err := client.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			if response.ProtoMajor != 2 || response.Header.Get("X-App") != "unchanged" {
				t.Fatalf("%s: not a streaming HTTP/2 response: %d %s", id, response.StatusCode, response.Proto)
			}
			prefix := make([]byte, len("prefix"))
			if _, err := io.ReadFull(response.Body, prefix); err != nil || string(prefix) != "prefix" {
				t.Fatalf("streamed prefix: %q, %v", prefix, err)
			}
			return response
		}
		first := request("original", liveBrowserCookie)
		defer first.Body.Close()
		sibling := request("sibling", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA")
		defer sibling.Body.Close()
		time.Sleep(5 * time.Minute)
		synctest.Wait()
		control.Mu.Lock()
		if control.Calls < 12 {
			t.Error("long HTTP request did not renew")
		}
		revoked = true
		control.Mu.Unlock()
		ended := make(chan error, 1)
		go func() { _, err := io.Copy(io.Discard, first.Body); ended <- err }()
		time.Sleep(30 * time.Second)
		synctest.Wait()
		select {
		case err := <-ended:
			if err == nil {
				t.Error("revoked HTTP/2 stream ended cleanly")
			}
		default:
			t.Fatal("revoked HTTP/2 stream survived recheck")
		}
		close(keepSibling)
		continued := make([]byte, len("still streaming"))
		if _, err := io.ReadFull(sibling.Body, continued); err != nil || string(continued) != "still streaming" {
			t.Fatalf("denial interrupted the sibling stream: %q, %v", continued, err)
		}
		// another request must still use this exact TLS connection; this client's
		// dialer rejects any attempt to replace it. the sibling remains active.
		third := request("future", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA")
		_ = third.Body.Close()
		if requests.Load() != 3 {
			t.Fatalf("application request replay: %d", requests.Load())
		}
	})
}

func TestPublicHTTPLiveOutageAndOriginalCredentialDeadline(t *testing.T) {
	for _, mode := range []string{"outage", "browser expiry", "share expiry", "share revoked"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				deadline := time.Now().Add(90 * time.Second)
				if mode == "outage" {
					deadline = time.Now().Add(10 * time.Second)
				}
				var unavailable bool
				control := &liveHTTPControl{check: func(input visitorfixture.HTTPSource) (visitorfixture.HTTPDecision, error) {
					if unavailable && mode == "outage" {
						return visitorfixture.HTTPDecision{}, clientcontrol.ErrUnavailable
					}
					if unavailable && mode == "share revoked" {
						return visitorfixture.HTTPDecision{}, &clientcontrol.ProblemError{Status: 403}
					}
					return liveHTTPAllowed(deadline)
				}}
				started, ended := make(chan struct{}), make(chan struct{})
				var requests atomic.Int32
				route := startLiveHTTPRoute(t, control, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					body, err := io.ReadAll(r.Body)
					if err != nil || string(body) != "exact body" {
						t.Errorf("request body changed: %q, %v", body, err)
					}
					close(started)
					<-r.Context().Done()
					close(ended)
				}))
				client := mixedVisitorClient(t, route, false, false)
				client.Timeout = 0
				r, _ := http.NewRequest("POST", "https://route.example/stream", strings.NewReader("exact body"))
				if strings.HasPrefix(mode, "share") {
					r.Header.Set("Cookie", httpaccess.VisitorTokenCookie+"="+control.Credential(t, liveBrowserCookie, true))
				} else {
					r.AddCookie(&http.Cookie{Name: httpaccess.VisitorTokenCookie, Value: control.Credential(t, liveBrowserCookie, false)})
				}
				result := make(chan error, 1)
				go func() {
					response, err := client.Do(r)
					if response != nil {
						_ = response.Body.Close()
					}
					result <- err
				}()
				select {
				case <-started:
				case err := <-result:
					t.Fatal("visitor failed before reaching the application", err)
				}
				control.Mu.Lock()
				unavailable = true
				control.Mu.Unlock()
				if mode != "share revoked" {
					time.Sleep(time.Until(deadline) - time.Second)
					synctest.Wait()
					select {
					case <-ended:
						t.Fatal("request ended before the last successful deadline")
					default:
					}
					time.Sleep(2 * time.Second)
				} else {
					time.Sleep(30 * time.Second)
				}
				synctest.Wait()
				select {
				case <-ended:
				default:
					t.Fatal("request survived its original deadline")
				}
				if err := <-result; err == nil {
					t.Fatal("terminated request returned success")
				}
				if requests.Load() != 1 {
					t.Fatal("request was replayed")
				}
			})
		})
	}
}

func TestPublicHTTPReplacementOnlyAuthorizesFutureRequests(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		originalDeadline := time.Now().Add(90 * time.Second)
		replacement := "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA"
		control := &liveHTTPControl{check: func(input visitorfixture.HTTPSource) (visitorfixture.HTTPDecision, error) {
			if input.BrowserCookieSecret != nil && *input.BrowserCookieSecret == liveBrowserCookie {
				return liveHTTPAllowed(originalDeadline)
			}
			return liveHTTPAllowed(time.Now().Add(2 * time.Minute))
		}}
		ended := make(chan string, 3)
		route := startLiveHTTPRoute(t, control, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "prefix")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			ended <- r.URL.Path
		}))
		client := mixedVisitorClient(t, route, true, false)
		client.Timeout = 0
		request := func(path, cookie string) *http.Response {
			r, _ := http.NewRequest("GET", "https://route.example/"+path, nil)
			r.AddCookie(&http.Cookie{Name: httpaccess.VisitorTokenCookie, Value: control.Credential(t, cookie, false)})
			response, err := client.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			return response
		}
		old := request("original", liveBrowserCookie)
		defer old.Body.Close()
		time.Sleep(30 * time.Second)
		fresh := request("replacement", replacement)
		defer fresh.Body.Close()
		time.Sleep(61 * time.Second)
		synctest.Wait()
		select {
		case path := <-ended:
			if path != "/original" {
				t.Fatal("replacement ended with the old credential", path)
			}
		default:
			t.Fatal("replacement extended the original request")
		}
		select {
		case path := <-ended:
			t.Fatal("unrelated request ended", path)
		default:
		}
		third := request("future", replacement)
		_ = third.Body.Close()
	})
}

func TestPublicHTTPGuardRetainsPreparedPolicyAge(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var revoked bool
		control := &liveHTTPControl{check: func(visitorfixture.HTTPSource) (visitorfixture.HTTPDecision, error) {
			if revoked {
				return visitorfixture.HTTPDecision{}, clientcontrol.ErrUnavailable
			}
			return liveHTTPAllowed(time.Now().Add(2 * time.Minute))
		}}
		ended := make(chan struct{})
		route := startLiveHTTPRoute(t, control, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/warm" {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			close(ended)
		}))
		client := mixedVisitorClient(t, route, true, false)
		client.Timeout = 0
		request := func(path string) *http.Response {
			r, _ := http.NewRequest("GET", "https://route.example/"+path, nil)
			r.AddCookie(&http.Cookie{Name: httpaccess.VisitorTokenCookie, Value: control.Credential(t, liveBrowserCookie, false)})
			response, err := client.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			return response
		}
		warm := request("warm")
		_ = warm.Body.Close()
		time.Sleep(4 * time.Second)
		control.Mu.Lock()
		revoked = true
		control.Mu.Unlock()
		// finish any successful in-flight refresh before capturing its deadline.
		synctest.Wait()
		confirmed, _, _ := control.policy.Lease().Current()
		time.Sleep(time.Until(confirmed.ValidUntil) - 2*time.Second)
		stream := request("stream")
		defer stream.Body.Close()
		if stream.StatusCode != http.StatusOK || stream.ProtoMajor != 2 {
			t.Fatalf("request before the last policy deadline was not admitted: %d %s", stream.StatusCode, stream.Proto)
		}
		time.Sleep(time.Second)
		synctest.Wait()
		select {
		case <-ended:
			t.Fatal("request ended before the last confirmed policy deadline")
		default:
		}
		time.Sleep(2 * time.Second)
		synctest.Wait()
		select {
		case <-ended:
		default:
			t.Fatal("starting a request reset the prepared policy's ten-second freshness bound")
		}
	})
}

func TestPublicHTTPWebSocketRenewsAndClosesOnRevocation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var revoked bool
		control := &liveHTTPControl{check: func(input visitorfixture.HTTPSource) (visitorfixture.HTTPDecision, error) {
			if input.BrowserCookieSecret == nil || *input.BrowserCookieSecret != liveBrowserCookie {
				t.Error("upgrade lost its original credential")
			}
			if revoked {
				return visitorfixture.HTTPDecision{}, &clientcontrol.ProblemError{Status: 403}
			}
			return liveHTTPAllowed(time.Now().Add(2 * time.Minute))
		}}
		var upgrades atomic.Int32
		route := startLiveHTTPRoute(t, control, websocket.Handler(func(ws *websocket.Conn) {
			upgrades.Add(1)
			defer ws.Close()
			for {
				var text string
				if websocket.Message.Receive(ws, &text) != nil {
					return
				}
				if websocket.Message.Send(ws, text) != nil {
					return
				}
			}
		}))
		done := make(chan struct{})
		raw, err := openHTTPTestRouteServer(route, done)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = raw.Close(); <-done }()
		secured := tls.Client(raw, &tls.Config{ServerName: "route.example", RootCAs: visitorfixture.Roots(t, *route.certificate.Load())})
		config, _ := websocket.NewConfig("wss://route.example/socket", "https://route.example")
		config.Header.Set("Cookie", httpaccess.VisitorTokenCookie+"="+control.Credential(t, liveBrowserCookie, false))
		ws, err := websocket.NewClient(config, secured)
		if err != nil {
			t.Fatal(err)
		}
		_ = raw.SetDeadline(time.Time{})
		defer ws.Close()
		time.Sleep(5 * time.Minute)
		if err := websocket.Message.Send(ws, "still live"); err != nil {
			t.Fatal(err)
		}
		var text string
		if err := websocket.Message.Receive(ws, &text); err != nil || text != "still live" {
			t.Fatal(text, err)
		}
		control.Mu.Lock()
		revoked = true
		control.Mu.Unlock()
		closed := make(chan error, 1)
		go func() { closed <- websocket.Message.Receive(ws, &text) }()
		time.Sleep(30 * time.Second)
		synctest.Wait()
		select {
		case err := <-closed:
			if err == nil {
				t.Fatal("revoked WebSocket stayed open")
			}
		default:
			t.Fatal("WebSocket survived denial")
		}
		if upgrades.Load() != 1 {
			t.Fatal("WebSocket was replayed")
		}
	})
}

// malformed issuance never produces a usable permission.
func TestPublicHTTPMissingDeadlineIsDenied(t *testing.T) {
	control := &liveHTTPControl{check: func(visitorfixture.HTTPSource) (visitorfixture.HTTPDecision, error) {
		return visitorfixture.HTTPDecision{VisitAllowed: true}, nil
	}}
	route := startLiveHTTPRoute(t, control, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("malformed decision reached target") }))
	r := newInlineTestRequest()
	w := httptest.NewRecorder()
	serveTestPublicRequest(t, route, w, r)
	if w.Code != http.StatusForbidden {
		t.Fatal(w.Code)
	}
}
