package publisher

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"golang.org/x/net/websocket"
)

const liveBrowserCookie = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

type liveHTTPControl struct {
	browserAccessStub
	mu    sync.Mutex
	check func(controlv1.HTTPVisitorRequest) (controlv1.HTTPVisitorResponse, error)
	calls int
}

type coalescedHTTPControl struct {
	browserAccessStub
	check func(context.Context) (controlv1.HTTPVisitorResponse, error)
}

func (c coalescedHTTPControl) AuthorizeHTTPVisitor(ctx context.Context, _ string, _ controlv1.HTTPVisitorRequest, _ credentials.PublishRunToken) (controlv1.HTTPVisitorResponse, error) {
	return c.check(ctx)
}

func TestPublicHTTPGuardCoalescedRefreshCancellationIsolation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		started, release := make(chan struct{}), make(chan struct{})
		var calls atomic.Int32
		control := &coalescedHTTPControl{check: func(ctx context.Context) (controlv1.HTTPVisitorResponse, error) {
			if calls.Add(1) == 2 {
				close(started)
				select {
				case <-ctx.Done():
					return controlv1.HTTPVisitorResponse{}, ctx.Err()
				case <-release:
				}
			}
			return liveHTTPAllowed(time.Now().Add(visitorDecisionLifetime))
		}}
		access := &browserAccess{client: control, runID: "original-run", version: 1, decisions: &visitorDecisionCache[controlv1.HTTPVisitorResponse]{}}
		original := httptest.NewRequest("GET", "https://route.example/stream", nil)
		original.AddCookie(&http.Cookie{Name: browserAccessCookieName, Value: liveBrowserCookie})
		initial, checkedAt, err := access.currentDecision(original, false)
		if err != nil {
			t.Fatal(err)
		}
		firstCtx, cancelFirst := context.WithCancel(original.Context())
		defer cancelFirst()
		first, firstRequest := guardPublicHTTPRequest(httptest.NewRecorder(), original.WithContext(firstCtx), original, access, initial, checkedAt)
		time.Sleep(visitorDecisionRecheck)
		<-started
		second, secondRequest := guardPublicHTTPRequest(httptest.NewRecorder(), original, original, access, initial, checkedAt)
		defer func() {
			// an expired guard panics when its handler finishes; retain the failed
			// assertion while still joining cleanup on the regressed implementation.
			defer func() {
				if recovered := recover(); recovered != nil && recovered != http.ErrAbortHandler {
					panic(recovered)
				}
			}()
			second.finish()
		}()
		time.Sleep(time.Millisecond)
		synctest.Wait()
		access.decisions.mu.Lock()
		active := len(access.decisions.active)
		access.decisions.mu.Unlock()
		if active != 1 || calls.Load() != 2 {
			t.Fatalf("guards did not share the exact refresh: active=%d, calls=%d", active, calls.Load())
		}
		cancelFirst()
		first.finish()
		synctest.Wait()
		if !errors.Is(firstRequest.Context().Err(), context.Canceled) {
			t.Fatal("the first caller did not stop waiting independently")
		}
		if err := secondRequest.Context().Err(); err != nil {
			t.Errorf("canceling the refresh initiator aborted the unrelated guard: %v", err)
		}
		close(release)
		synctest.Wait()
		time.Sleep(visitorDecisionLifetime)
		synctest.Wait()
		if err := secondRequest.Context().Err(); err != nil {
			t.Errorf("the remaining guard did not keep renewing: %v", err)
		}
	})
}

func (c *liveHTTPControl) AuthorizeHTTPVisitor(_ context.Context, _ string, input controlv1.HTTPVisitorRequest, _ credentials.PublishRunToken) (controlv1.HTTPVisitorResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	return c.check(input)
}

func liveHTTPAllowed(until time.Time) (controlv1.HTTPVisitorResponse, error) {
	return controlv1.HTTPVisitorResponse{VisitAllowed: true, ValidUntil: &until}, nil
}

func startLiveHTTPRoute(t *testing.T, control *liveHTTPControl, handler http.Handler) *PublicURLServer {
	t.Helper()
	route, err := NewPublicURLServer(PublicURLServerConfig{Hostname: "route.example", Certificate: publicURLTestCertificate(t, "route.example"), Handler: handler,
		BrowserAccess: &browserAccess{client: control, runID: "original-run", version: 1, decisions: &visitorDecisionCache[controlv1.HTTPVisitorResponse]{}}})
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
		control := &liveHTTPControl{check: func(input controlv1.HTTPVisitorRequest) (controlv1.HTTPVisitorResponse, error) {
			if input.SourceIp != "192.0.2.10" {
				t.Error("lost trusted visitor source")
			}
			if input.BrowserCookieSecret != nil && *input.BrowserCookieSecret == liveBrowserCookie && revoked {
				return controlv1.HTTPVisitorResponse{}, controlclient.ErrUnauthenticated
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
			r.Header.Set("Cookie", "app=unchanged; "+browserAccessCookieName+"="+cookie)
			response, err := client.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			if response.ProtoMajor != 2 || response.Header.Get("X-App") != "unchanged" {
				t.Fatal("not a streaming HTTP/2 response")
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
		control.mu.Lock()
		if control.calls < 12 {
			t.Error("long HTTP request did not renew")
		}
		revoked = true
		control.mu.Unlock()
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
					deadline = time.Now().Add(visitorDecisionLifetime)
				}
				var unavailable bool
				control := &liveHTTPControl{check: func(input controlv1.HTTPVisitorRequest) (controlv1.HTTPVisitorResponse, error) {
					if unavailable && mode == "outage" {
						return controlv1.HTTPVisitorResponse{}, controlclient.ErrUnavailable
					}
					if unavailable && mode == "share revoked" {
						return controlv1.HTTPVisitorResponse{}, &controlclient.ProblemError{Status: 403}
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
					r.Header.Set("Cookie", shareCookieName+"=shr_0123456789abcdefghijkl."+liveBrowserCookie)
				} else {
					r.AddCookie(&http.Cookie{Name: browserAccessCookieName, Value: liveBrowserCookie})
				}
				result := make(chan error, 1)
				go func() {
					response, err := client.Do(r)
					if response != nil {
						_ = response.Body.Close()
					}
					result <- err
				}()
				<-started
				control.mu.Lock()
				unavailable = true
				control.mu.Unlock()
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
		control := &liveHTTPControl{check: func(input controlv1.HTTPVisitorRequest) (controlv1.HTTPVisitorResponse, error) {
			if input.BrowserCookieSecret != nil && *input.BrowserCookieSecret == liveBrowserCookie {
				return liveHTTPAllowed(originalDeadline)
			}
			return liveHTTPAllowed(time.Now().Add(visitorDecisionLifetime))
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
			r.AddCookie(&http.Cookie{Name: browserAccessCookieName, Value: cookie})
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

func TestPublicHTTPGuardRetainsCachedDecisionAge(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var revoked bool
		control := &liveHTTPControl{check: func(controlv1.HTTPVisitorRequest) (controlv1.HTTPVisitorResponse, error) {
			if revoked {
				return controlv1.HTTPVisitorResponse{}, controlclient.ErrUnauthenticated
			}
			return liveHTTPAllowed(time.Now().Add(visitorDecisionLifetime))
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
			r.AddCookie(&http.Cookie{Name: browserAccessCookieName, Value: liveBrowserCookie})
			response, err := client.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			return response
		}
		warm := request("warm")
		_ = warm.Body.Close()
		time.Sleep(24 * time.Second)
		control.mu.Lock()
		revoked = true
		control.mu.Unlock()
		stream := request("stream")
		defer stream.Body.Close()
		time.Sleep(6 * time.Second)
		synctest.Wait()
		select {
		case <-ended:
		default:
			t.Fatal("starting a request reset the cached decision's 30-second recheck bound")
		}
	})
}

func TestPublicHTTPWebSocketRenewsAndClosesOnRevocation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var revoked bool
		control := &liveHTTPControl{check: func(input controlv1.HTTPVisitorRequest) (controlv1.HTTPVisitorResponse, error) {
			if input.BrowserCookieSecret == nil || *input.BrowserCookieSecret != liveBrowserCookie {
				t.Error("upgrade lost its original credential")
			}
			if revoked {
				return controlv1.HTTPVisitorResponse{}, &controlclient.ProblemError{Status: 403}
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
		secured := tls.Client(raw, &tls.Config{ServerName: "route.example", RootCAs: rootsForCertificate(t, *route.certificate.Load())})
		config, _ := websocket.NewConfig("wss://route.example/socket", "https://route.example")
		config.Header.Set("Cookie", browserAccessCookieName+"="+liveBrowserCookie)
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
		control.mu.Lock()
		revoked = true
		control.mu.Unlock()
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

// keep malformed decisions fail-closed even without a populated cache.
func TestPublicHTTPMissingDeadlineIsDenied(t *testing.T) {
	control := &liveHTTPControl{check: func(controlv1.HTTPVisitorRequest) (controlv1.HTTPVisitorResponse, error) {
		return controlv1.HTTPVisitorResponse{VisitAllowed: true}, nil
	}}
	route := startLiveHTTPRoute(t, control, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("malformed decision reached target") }))
	r := newInlineTestRequest()
	w := httptest.NewRecorder()
	route.http.Handler.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatal(w.Code)
	}
}
