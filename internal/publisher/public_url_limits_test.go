package publisher

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/diagnostic"
)

func newInlineTestRequest() *http.Request {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Host = "route.example"
	request.TLS = &tls.ConnectionState{ServerName: "route.example"}
	return request
}

func TestInlinePublisherAppliesTotalAndRateAfterVisitorAccess(t *testing.T) {
	for _, test := range []struct {
		name       string
		limits     ApplicationLimits
		status     int
		code       string
		retryAfter string
		completed  bool
	}{
		{"total", ApplicationLimits{Requests: 1}, http.StatusServiceUnavailable, "TNL_REQUEST_BUDGET_EXHAUSTED", "", true},
		{"rate", ApplicationLimits{RateRequests: 1, RatePer: time.Minute}, http.StatusTooManyRequests, "TNL_REQUEST_RATE_LIMITED", "60", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var served atomic.Int32
			server, err := NewPublicURLServer(PublicURLServerConfig{
				Hostname: "route.example", Limits: test.limits,
				Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					served.Add(1)
					w.WriteHeader(http.StatusNoContent)
				}),
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = server.Close() })
			first := httptest.NewRecorder()
			server.http.Handler.ServeHTTP(first, newInlineTestRequest())
			if first.Code != http.StatusNoContent {
				t.Fatalf("first request = %d", first.Code)
			}
			denied := newInlineTestRequest()
			denied = denied.WithContext(context.WithValue(denied.Context(), denialContextKey{}, true))
			policy := httptest.NewRecorder()
			server.http.Handler.ServeHTTP(policy, denied)
			if policy.Code != http.StatusForbidden {
				t.Fatalf("policy rejection = %d", policy.Code)
			}
			second := httptest.NewRecorder()
			server.http.Handler.ServeHTTP(second, newInlineTestRequest())
			if second.Code != test.status || second.Header().Get("Tnl-Error-Code") != test.code ||
				second.Header().Get("Retry-After") != test.retryAfter || served.Load() != 1 {
				t.Fatalf("rejected request = %d, headers = %v, served = %d", second.Code, second.Header(), served.Load())
			}
			select {
			case <-server.admission.completed:
				if !test.completed {
					t.Fatal("rate rejection ended the publish run")
				}
			default:
				if test.completed {
					t.Fatal("total budget did not complete the publish run")
				}
			}
		})
	}
}

func TestInlinePublisherAdmissionFollowsVisitorAccess(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	server, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "route.example", RequestLimit: 1,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			close(started)
			<-release
			w.WriteHeader(http.StatusNoContent)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		server.http.Handler.ServeHTTP(httptest.NewRecorder(), newInlineTestRequest())
	}()
	defer func() { close(release); <-done }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("inline handler did not start")
	}

	denied := newInlineTestRequest()
	denied = denied.WithContext(context.WithValue(denied.Context(), denialContextKey{}, true))
	response := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(response, denied)
	if response.Code != http.StatusForbidden || response.Header().Get("Tnl-Error-Code") != string(diagnostic.IPPolicyDenied) {
		t.Fatalf("denied visitor during application saturation = %d, %q", response.Code, response.Header().Get("Tnl-Error-Code"))
	}

	response = httptest.NewRecorder()
	server.http.Handler.ServeHTTP(response, newInlineTestRequest())
	if response.Code != http.StatusServiceUnavailable || response.Header().Get("Retry-After") != "1" ||
		response.Header().Get("Connection") != "close" {
		t.Fatalf("application overload = %d, headers = %v", response.Code, response.Header())
	}
}

func TestRouteServerBoundsHTTP2FanoutAcrossVisitorConnections(t *testing.T) {
	const limit = 4
	started := make(chan struct{}, limit+1)
	var accepted atomic.Int32
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 1 {
			t.Errorf("local service protocol = %s", r.Proto)
		}
		if r.Method == http.MethodPost {
			started <- struct{}{}
			_, _ = io.Copy(io.Discard, r.Body)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	upstream.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			accepted.Add(1)
		}
	}
	upstream.Start()
	t.Cleanup(upstream.Close)
	route, finished := startLimitedTestPublicURL(t, upstream.URL, limit, 0)
	client := singleConnectionRouteClient(t, route, true)
	var bodies []*io.PipeWriter
	var results []<-chan publicURLRequestResult
	var cancels []context.CancelFunc
	for range limit {
		body, result, cancel := startIncompleteRouteRequest(t, client)
		bodies, results, cancels = append(bodies, body), append(results, result), append(cancels, cancel)
		awaitPublisherTest(t, started)
	}
	// a visitor connection can open concurrent streams, but only the public
	// URL's request budget can reach the local HTTP/1 service.
	for range 32 {
		assertRouteOverloaded(t, client)
	}
	other := singleConnectionRouteClient(t, route, true)
	assertRouteOverloaded(t, other)
	assertHTTP1OverloadDoesNotDrainBody(t, route)
	if got := accepted.Load(); got != limit {
		t.Fatalf("upstream TCP connections = %d, want %d", got, limit)
	}
	independent, _ := startLimitedTestPublicURL(t, upstream.URL, 1, 0)
	assertRouteAvailable(t, singleConnectionRouteClient(t, independent, true))
	// cancel one stream: its slot must become available to another connection.
	cancels[0]()
	awaitPublisherTest(t, results[0])
	awaitPublisherTest(t, finished)
	assertRouteAvailable(t, other)
	for i := 1; i < limit; i++ {
		if _, err := bodies[i].Write([]byte("b")); err != nil {
			t.Fatal(err)
		}
		_ = bodies[i].Close()
		got := awaitPublisherTest(t, results[i])
		if got.err != nil || got.status != http.StatusNoContent || got.protocol != 2 {
			t.Fatalf("completed request = %+v", got)
		}
		awaitPublisherTest(t, finished)
	}
	assertRouteAvailable(t, client)
}

func TestRouteServerRejectsMisdirectedHTTP2StreamWithRetryableStatus(t *testing.T) {
	var forwarded atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		forwarded.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	route, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "route.example", Target: upstream.URL,
		Certificate: publicURLTestCertificate(t, "*.example"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })
	if err := route.Start(); err != nil {
		t.Fatal(err)
	}
	client := singleConnectionRouteClient(t, route, true)

	// establish a TLS connection for route.example, then send a stream for a
	// different authority over that same HTTP/2 connection, as browsers can do
	// when sibling public URLs share a wildcard certificate and ingress address.
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://route.example/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := doRouteRequest(client, request); got.err != nil || got.status != http.StatusNoContent || got.protocol != 2 {
		t.Fatalf("first HTTP/2 request = %+v", got)
	}
	request, err = http.NewRequestWithContext(t.Context(), http.MethodGet, "https://route.example/", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "sibling.example"
	got := doRouteRequest(client, request)
	if got.err != nil || got.status != http.StatusMisdirectedRequest || got.protocol != 2 ||
		got.header.Get("Tnl-Error-Code") != "TNL_REQUEST_MISDIRECTED" {
		t.Fatalf("misdirected HTTP/2 stream = %+v", got)
	}
	if count := forwarded.Load(); count != 1 {
		t.Fatalf("requests reaching local service = %d, want 1", count)
	}
}

func TestRouteServerTimesOutIncompleteBodies(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		for _, trickle := range []bool{false, true} {
			t.Run(fmt.Sprintf("http2=%t/trickle=%t", h2, trickle), func(t *testing.T) {
				t.Parallel()
				started, ended := make(chan struct{}, 1), make(chan error, 1)
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodPost {
						started <- struct{}{}
						_, err := io.Copy(io.Discard, r.Body)
						ended <- err
					}
					w.WriteHeader(http.StatusNoContent)
				}))
				t.Cleanup(upstream.Close)
				route, finished := startLimitedTestPublicURL(t, upstream.URL, 1, 500*time.Millisecond)
				client := singleConnectionRouteClient(t, route, h2)
				reader, writer := io.Pipe()
				t.Cleanup(func() { _ = writer.Close() })
				ctx, cancel := context.WithCancel(t.Context())
				t.Cleanup(cancel)
				request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://route.example/hold", reader)
				if err != nil {
					t.Fatal(err)
				}
				// unknown length also covers HTTP/1 chunked request bodies.
				result, done := make(chan publicURLRequestResult, 1), make(chan struct{})
				go func() { defer close(done); result <- doRouteRequest(client, request) }()
				t.Cleanup(func() { cancel(); _ = writer.Close(); awaitPublisherTest(t, done) })
				if _, err := writer.Write([]byte("a")); err != nil {
					t.Fatal(err)
				}
				awaitPublisherTest(t, started)
				if trickle {
					done := make(chan struct{})
					go func() {
						defer close(done)
						ticker := time.NewTicker(25 * time.Millisecond)
						defer ticker.Stop()
						for {
							select {
							case <-ticker.C:
								if _, err := writer.Write([]byte("a")); err != nil {
									return
								}
							case <-ctx.Done():
								return
							}
						}
					}()
					t.Cleanup(func() { cancel(); _ = writer.Close(); awaitPublisherTest(t, done) })
				}
				var got publicURLRequestResult
				select {
				case got = <-result:
				case <-time.After(2 * time.Second):
					t.Fatal("body deadline did not interrupt the request before the client timeout")
				}
				if got.err == nil && got.status < 400 {
					t.Fatalf("incomplete body succeeded: %+v", got)
				}
				if err := awaitPublisherTest(t, ended); err == nil {
					t.Fatal("incomplete upstream body was not interrupted")
				}
				// observe the handler return before testing admission again.
				awaitPublisherTest(t, finished)
				if !h2 {
					client = singleConnectionRouteClient(t, route, false)
				}
				assertRouteAvailable(t, client)
			})
		}
	}
}

func TestRouteServerCompletedBodiesAllowLongResponses(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("http2=%t", h2), func(t *testing.T) {
			t.Parallel()
			release := make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if _, err := io.Copy(io.Discard, r.Body); err != nil {
					return
				}
				_, _ = io.WriteString(w, "first\n")
				w.(http.Flusher).Flush()
				<-release
				_, _ = io.WriteString(w, "second\n")
			}))
			t.Cleanup(upstream.Close)
			route, _ := startLimitedTestPublicURL(t, upstream.URL, 1, 100*time.Millisecond)
			client := singleConnectionRouteClient(t, route, h2)
			t.Cleanup(unblock)
			response, err := client.Post("https://route.example/", "text/plain", strings.NewReader("complete body"))
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			first := make([]byte, len("first\n"))
			if _, err := io.ReadFull(response.Body, first); err != nil {
				t.Fatal(err)
			}
			assertRouteOverloaded(t, singleConnectionRouteClient(t, route, true))
			time.Sleep(2 * route.http.ReadTimeout)
			unblock()
			rest, err := io.ReadAll(response.Body)
			if err != nil || string(first) != "first\n" || string(rest) != "second\n" {
				t.Fatalf("streamed response = %q %q, %v", first, rest, err)
			}
		})
	}
}

// the real public URL server is used, with only its deadline shortened for tests.
func startLimitedTestPublicURL(t *testing.T, target string, limit int, timeout time.Duration) (*PublicURLServer, chan struct{}) {
	t.Helper()
	route, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "route.example", Target: target, RequestLimit: limit,
		Certificate: publicURLTestCertificate(t, "route.example"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })
	if route.http.ReadTimeout <= 0 || route.http.ReadTimeout > 30*time.Second {
		t.Fatalf("unsafe production read timeout: %v", route.http.ReadTimeout)
	}
	if timeout != 0 {
		route.http.ReadTimeout = timeout
	}
	finished := make(chan struct{}, 16)
	handler := route.http.Handler
	route.http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if r.URL.Path == "/hold" {
				finished <- struct{}{}
			}
		}()
		handler.ServeHTTP(w, r)
	})
	if err := route.Start(); err != nil {
		t.Fatal(err)
	}
	return route, finished
}

func singleConnectionRouteClient(t *testing.T, route *PublicURLServer, h2 bool) *http.Client {
	t.Helper()
	var dialed atomic.Bool
	transport := &http.Transport{
		ForceAttemptHTTP2: h2,
		TLSClientConfig: &tls.Config{
			ServerName: "route.example", RootCAs: rootsForCertificate(t, *route.certificate.Load()),
		},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			if dialed.Swap(true) {
				return nil, errors.New("test client attempted a second visitor connection")
			}
			handled := make(chan struct{})
			connection, err := openHTTPTestRouteServer(route, handled)
			t.Cleanup(func() {
				if connection != nil {
					_ = connection.Close()
				}
				awaitPublisherTest(t, handled)
			})
			return connection, err
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}
}

type publicURLRequestResult struct {
	status, protocol int
	header           http.Header
	err              error
}

func doRouteRequest(client *http.Client, request *http.Request) publicURLRequestResult {
	response, err := client.Do(request)
	if err != nil {
		return publicURLRequestResult{err: err}
	}
	defer response.Body.Close()
	_, err = io.Copy(io.Discard, response.Body)
	return publicURLRequestResult{status: response.StatusCode, protocol: response.ProtoMajor, header: response.Header, err: err}
}

func startIncompleteRouteRequest(t *testing.T, client *http.Client) (*io.PipeWriter, <-chan publicURLRequestResult, context.CancelFunc) {
	t.Helper()
	reader, writer := io.Pipe()
	ctx, cancel := context.WithCancel(t.Context())
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://route.example/hold", reader)
	if err != nil {
		t.Fatal(err)
	}
	request.ContentLength = 2
	result, done := make(chan publicURLRequestResult, 1), make(chan struct{})
	go func() { defer close(done); result <- doRouteRequest(client, request) }()
	t.Cleanup(func() { cancel(); _ = writer.Close(); awaitPublisherTest(t, done) })
	if _, err := writer.Write([]byte("a")); err != nil {
		t.Fatal(err)
	}
	return writer, result, cancel
}

func assertRouteOverloaded(t *testing.T, client *http.Client) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://route.example/", nil)
	if err != nil {
		t.Fatal(err)
	}
	got := doRouteRequest(client, request)
	if got.err != nil || got.status != http.StatusServiceUnavailable || got.protocol != 2 ||
		got.header.Get("Retry-After") != "1" || got.header.Get("Tnl-Error-Code") != "TNL_REQUEST_LIMIT_REACHED" {
		t.Fatalf("excess request = %+v", got)
	}
}

func assertRouteAvailable(t *testing.T, client *http.Client) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://route.example/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := doRouteRequest(client, request); got.err != nil || got.status != http.StatusNoContent {
		t.Fatalf("request after capacity release = %+v", got)
	}
}

func assertHTTP1OverloadDoesNotDrainBody(t *testing.T, route *PublicURLServer) {
	t.Helper()
	handled := make(chan struct{})
	connection, err := openHTTPTestRouteServer(route, handled)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close(); awaitPublisherTest(t, handled) })
	client := tls.Client(connection, &tls.Config{ServerName: "route.example", RootCAs: rootsForCertificate(t, *route.certificate.Load())})
	if _, err := io.WriteString(client, "POST / HTTP/1.1\r\nHost: route.example\r\nContent-Length: 2\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable || !response.Close {
		t.Fatalf("HTTP/1 overload = %d, close = %t", response.StatusCode, response.Close)
	}
	_, _ = io.Copy(io.Discard, response.Body)
}
