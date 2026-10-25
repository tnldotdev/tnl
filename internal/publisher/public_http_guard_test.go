package publisher

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
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

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/publisher/visitorpolicy"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"golang.org/x/net/websocket"
)

const liveBrowserCookie = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

type liveHTTPControl struct {
	browserAccessStub
	mu       sync.Mutex
	check    func(controlv1.HTTPVisitorRequest) (controlv1.HTTPVisitorResponse, error)
	calls    int
	policy   *visitorpolicy.Policy
	tokens   *browserTokens
	revision int64
	sources  map[string]controlv1.HTTPVisitorRequest
	allowed  map[string]bool
	issued   map[string]visitortoken.Token
}

func liveHTTPAllowed(until time.Time) (controlv1.HTTPVisitorResponse, error) {
	return controlv1.HTTPVisitorResponse{VisitAllowed: true, ValidUntil: &until}, nil
}

func prepareLiveHTTPControl(t *testing.T, control *liveHTTPControl) {
	t.Helper()
	control.revision = 1
	control.sources, control.allowed, control.issued = make(map[string]controlv1.HTTPVisitorRequest), make(map[string]bool), make(map[string]visitortoken.Token)
	policy, err := visitorpolicy.Prepare(t.Context(), control, visitorscope.Scope{Kind: visitorscope.PublicURL, ID: certificateTestPublicURLID}, "pr_0123456789abcdefghijkl", 1, "fixture-run-token", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(policy.Close)
	control.policy = policy
	control.tokens, err = startBrowserTokens(t.Context(), control, policy.Lease, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(control.tokens.Close)
}

func startLiveHTTPRoute(t *testing.T, control *liveHTTPControl, handler http.Handler) *PublicURLServer {
	t.Helper()
	prepareLiveHTTPControl(t, control)
	route, err := NewPublicURLServer(PublicURLServerConfig{Hostname: "route.example", Certificate: publicURLTestCertificate(t, "route.example"), Handler: handler,
		PublicURLID: certificateTestPublicURLID, PublishRunID: "pr_0123456789abcdefghijkl", PublishRunNumber: 1, VisitorPolicy: control.policy.Lease, VisitorTokens: control.tokens,
		BrowserAccess: &browserAccess{client: control, runID: "original-run", version: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if err := route.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })
	return route
}

func (c *liveHTTPControl) ReadPublisherVisitorPolicy(_ context.Context, body controlv1.PublisherVisitorPolicyRequest, _ string) (controlv1.VisitorPolicyUpdate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, input := range c.sources {
		decision, err := c.check(input)
		c.calls++
		if errors.Is(err, clientcontrol.ErrUnavailable) {
			return controlv1.VisitorPolicyUpdate{}, err
		}
		allowed := err == nil && decision.VisitAllowed && decision.ValidUntil != nil && decision.ValidUntil.After(time.Now())
		if allowed != c.allowed[key] {
			c.revision++
			c.allowed[key] = allowed
		}
	}
	now := time.Now()
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("l", 32)))
	events := []int64{}
	if body.AfterRevision != 0 {
		for next := body.AfterRevision + 1; next <= c.revision; next++ {
			events = append(events, next)
		}
	}
	return controlv1.VisitorPolicyUpdate{AfterRevision: body.AfterRevision, Revisions: events, SnapshotRequired: body.AfterRevision == 0,
		Policy: controlv1.VisitorPolicySnapshot{Resource: body.Resource, Hostname: "route.example", Port: 443, Issuer: "https://control.example.test", Enabled: true,
			VisitorPolicyRevision: c.revision, KeyRevision: 1, ObservedAt: now, ValidUntil: now.Add(10 * time.Second),
			VerificationKeys: []controlv1.VisitorVerificationKey{{Id: "live", PublicKey: key.Public().(ed25519.PublicKey)}}, WorkloadLeases: []controlv1.VisitorWorkloadLease{}, StreamAllocations: []controlv1.StreamCapacityAllocation{}}}, nil
}

func (c *liveHTTPControl) IssueVisitorToken(_ context.Context, body controlv1.VisitorTokenRequest) (controlv1.VisitorTokenResponse, error) {
	var source struct {
		Kind    string `json:"kind"`
		Secret  string `json:"secret"`
		ShareID string `json:"share_id"`
	}
	if json.Unmarshal(body.Source, &source) != nil {
		return controlv1.VisitorTokenResponse{}, errors.New("invalid fixture token source")
	}
	keyID := source.Kind + ":" + source.ShareID + ":" + source.Secret
	c.mu.Lock()
	defer c.mu.Unlock()
	input, exists := c.sources[keyID]
	if !exists {
		return controlv1.VisitorTokenResponse{}, &clientcontrol.ProblemError{Status: http.StatusForbidden}
	}
	decision, err := c.check(input)
	c.calls++
	if err != nil {
		if errors.Is(err, clientcontrol.ErrUnauthenticated) {
			return controlv1.VisitorTokenResponse{}, &clientcontrol.ProblemError{Status: http.StatusUnauthorized}
		}
		return controlv1.VisitorTokenResponse{}, err
	}
	if !decision.VisitAllowed || decision.ValidUntil == nil || !decision.ValidUntil.After(time.Now()) {
		return controlv1.VisitorTokenResponse{}, &clientcontrol.ProblemError{Status: http.StatusForbidden}
	}
	digest := sha256.Sum256([]byte(keyID))
	id := hex.EncodeToString(digest[:11])
	var subject visitortoken.Subject = visitortoken.Browser{IdentityID: "ident_" + id, SessionID: "cs_" + id}
	if source.Kind == "share_session" {
		subject = visitortoken.Share{ShareID: source.ShareID}
	}
	permission := visitortoken.Permission{Scope: visitorscope.Scope{Kind: visitorscope.PublicURL, ID: certificateTestPublicURLID}, Hostname: "route.example", Port: 443,
		VisitorPolicyRevision: c.revision, Subject: subject, ExpiresAt: decision.ValidUntil.Truncate(time.Second)}
	private := ed25519.NewKeyFromSeed([]byte(strings.Repeat("l", 32)))
	token, err := visitortoken.Sign("https://control.example.test", "live", private, permission, time.Now())
	if err != nil {
		return controlv1.VisitorTokenResponse{}, err
	}
	c.issued[keyID] = token
	return controlv1.VisitorTokenResponse{Resource: body.Resource, Hostname: permission.Hostname, Port: 443, VisitorPolicyRevision: c.revision,
		ExpiresAt: permission.ExpiresAt, VisitorToken: token.Reveal()}, nil
}

func (c *liveHTTPControl) credential(t *testing.T, cookie string, share bool) string {
	t.Helper()
	kind, shareID := "browser_session", ""
	input := controlv1.HTTPVisitorRequest{PublishRunNumber: 1, SourceIp: "192.0.2.10", BrowserCookieSecret: &cookie}
	var source json.RawMessage
	if share {
		kind, shareID = "share_session", "shr_0123456789abcdefghijkl"
		input.BrowserCookieSecret, input.ShareId, input.ShareCookieSecret = nil, &shareID, &cookie
		source, _ = json.Marshal(controlv1.VisitorTokenShareSessionSource{Kind: controlv1.VisitorTokenShareSession, ShareId: shareID, Secret: cookie})
	} else {
		source = browserSourceFixture(cookie)
	}
	key := kind + ":" + shareID + ":" + cookie
	c.mu.Lock()
	if token, exists := c.issued[key]; exists {
		c.mu.Unlock()
		return token.Reveal()
	}
	c.sources[key], c.allowed[key] = input, true
	c.mu.Unlock()
	response, err := c.IssueVisitorToken(t.Context(), controlv1.VisitorTokenRequest{Resource: controlv1.VisitorResourceScope{Kind: "public_url", Id: certificateTestPublicURLID}, Source: source})
	if err != nil {
		return "invalid-visitor-permission"
	}
	if err := c.tokens.install(source, response, time.Now().Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.issued[key] = visitortoken.Token(response.VisitorToken)
	c.mu.Unlock()
	return response.VisitorToken
}

func (c *liveHTTPControl) permission(t *testing.T, cookie string, share bool) controlv1.VisitorTokenResponse {
	t.Helper()
	token := c.credential(t, cookie, share)
	view, _, _ := c.policy.Lease.Current()
	permission, err := visitortoken.VerifyBearer(visitortoken.Token(token), view, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return controlv1.VisitorTokenResponse{Resource: controlv1.VisitorResourceScope{Kind: "public_url", Id: view.Scope.ID}, Hostname: view.Hostname, Port: int(view.Port),
		VisitorPolicyRevision: permission.VisitorPolicyRevision, ExpiresAt: permission.ExpiresAt, VisitorToken: token}
}

func TestPublicHTTPLiveRenewalAndHTTP2Isolation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var revoked bool
		control := &liveHTTPControl{check: func(input controlv1.HTTPVisitorRequest) (controlv1.HTTPVisitorResponse, error) {
			if input.SourceIp != "192.0.2.10" {
				t.Error("lost trusted visitor source")
			}
			if input.BrowserCookieSecret != nil && *input.BrowserCookieSecret == liveBrowserCookie && revoked {
				return controlv1.HTTPVisitorResponse{}, clientcontrol.ErrUnauthenticated
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
			r.Header.Set("Cookie", "app=unchanged; "+visitorTokenCookie+"="+control.credential(t, cookie, false))
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
					deadline = time.Now().Add(10 * time.Second)
				}
				var unavailable bool
				control := &liveHTTPControl{check: func(input controlv1.HTTPVisitorRequest) (controlv1.HTTPVisitorResponse, error) {
					if unavailable && mode == "outage" {
						return controlv1.HTTPVisitorResponse{}, clientcontrol.ErrUnavailable
					}
					if unavailable && mode == "share revoked" {
						return controlv1.HTTPVisitorResponse{}, &clientcontrol.ProblemError{Status: 403}
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
					r.Header.Set("Cookie", visitorTokenCookie+"="+control.credential(t, liveBrowserCookie, true))
				} else {
					r.AddCookie(&http.Cookie{Name: visitorTokenCookie, Value: control.credential(t, liveBrowserCookie, false)})
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
			r.AddCookie(&http.Cookie{Name: visitorTokenCookie, Value: control.credential(t, cookie, false)})
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
				return controlv1.HTTPVisitorResponse{}, clientcontrol.ErrUnavailable
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
			r.AddCookie(&http.Cookie{Name: visitorTokenCookie, Value: control.credential(t, liveBrowserCookie, false)})
			response, err := client.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			return response
		}
		warm := request("warm")
		_ = warm.Body.Close()
		time.Sleep(4 * time.Second)
		synctest.Wait()
		control.mu.Lock()
		revoked = true
		control.mu.Unlock()
		confirmed, _, _ := control.policy.Lease.Current()
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
		control := &liveHTTPControl{check: func(input controlv1.HTTPVisitorRequest) (controlv1.HTTPVisitorResponse, error) {
			if input.BrowserCookieSecret == nil || *input.BrowserCookieSecret != liveBrowserCookie {
				t.Error("upgrade lost its original credential")
			}
			if revoked {
				return controlv1.HTTPVisitorResponse{}, &clientcontrol.ProblemError{Status: 403}
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
		config.Header.Set("Cookie", visitorTokenCookie+"="+control.credential(t, liveBrowserCookie, false))
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
