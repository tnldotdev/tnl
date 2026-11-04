package proxy

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"sync"
	"testing"
	"time"
)

func TestConfigRejectsInvalidTransportSizing(t *testing.T) {
	if _, err := New(Config{Target: "3000", Hostname: "route.example", MaxConnsPerHost: -1}); err == nil {
		t.Fatal("negative transport connection limit accepted")
	}
}

func TestTransportSizingWaitsWithoutApplicationAdmission(t *testing.T) {
	for _, kind := range []string{"base", "mounted", "dynamic"} {
		t.Run(kind, func(t *testing.T) {
			started, release := make(chan struct{}), make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/hold" {
					close(started)
					select {
					case <-release:
					case <-r.Context().Done():
					}
				}
				_, _ = io.WriteString(w, "ok")
			}))
			t.Cleanup(upstream.Close)
			t.Cleanup(unblock)
			config := Config{Target: upstream.URL, Hostname: "route.example", MaxConnsPerHost: 1}
			prefix := ""
			switch kind {
			case "mounted":
				config.Mounts = []Mount{{Prefix: "/api", Target: upstream.URL, StripPrefix: true}}
				prefix = "/api"
			case "dynamic":
				config.ResolveTarget = func(*http.Request) (string, string, error) { return upstream.URL, "one", nil }
			}
			handler, err := New(config)
			if err != nil {
				t.Fatal(err)
			}
			serve := func(ctx context.Context, path string) *httptest.ResponseRecorder {
				request := httptest.NewRequestWithContext(ctx, http.MethodGet, prefix+path, nil)
				request.Host = "route.example"
				request.TLS = &tls.ConnectionState{ServerName: "route.example"}
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				return response
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			t.Cleanup(cancel)
			first, firstDone := make(chan *httptest.ResponseRecorder, 1), make(chan struct{})
			go func() { defer close(firstDone); first <- serve(ctx, "/hold") }()
			t.Cleanup(func() { unblock(); cancel(); awaitProxyTest(t, firstDone) })
			awaitProxyTest(t, started)
			// reaching GetConn proves this request was not rejected by a second
			// application budget. the occupied target transport must wait instead.
			waiting, connected := make(chan struct{}), make(chan struct{}, 1)
			waitingCtx, stopWaiting := context.WithTimeout(httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
				GetConn: func(string) { close(waiting) },
				GotConn: func(httptrace.GotConnInfo) { connected <- struct{}{} },
			}), 100*time.Millisecond)
			t.Cleanup(stopWaiting)
			second, secondDone := make(chan *httptest.ResponseRecorder, 1), make(chan struct{})
			go func() { defer close(secondDone); second <- serve(waitingCtx, "/check") }()
			t.Cleanup(func() { stopWaiting(); awaitProxyTest(t, secondDone) })
			awaitProxyTest(t, waiting)
			if response := awaitProxyTest(t, second); response.Code != http.StatusBadGateway || response.Header().Get("Retry-After") != "" || waitingCtx.Err() != context.DeadlineExceeded {
				t.Fatalf("transport did not wait for cancellation: %d %v, context=%v", response.Code, response.Header(), waitingCtx.Err())
			}
			select {
			case <-connected:
				t.Fatal("transport exceeded MaxConnsPerHost")
			default:
			}
			unblock()
			if response := awaitProxyTest(t, first); response.Code != http.StatusOK || response.Body.String() != "ok" {
				t.Fatalf("held request = %d %q", response.Code, response.Body.String())
			}
			if response := serve(ctx, "/check"); response.Code != http.StatusOK || response.Body.String() != "ok" {
				t.Fatalf("request after transport release = %d %q", response.Code, response.Body.String())
			}
		})
	}
}

func awaitProxyTest[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("proxy test operation did not finish")
		var zero T
		return zero
	}
}
