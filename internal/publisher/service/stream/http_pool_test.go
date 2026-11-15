package stream

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/transport/httpstream"
	"github.com/tnldotdev/tnl/internal/transport/targettransport"
)

func poolTarget(address string, connections int) HTTPTarget {
	return HTTPTarget{Address: strings.TrimPrefix(address, "http://"), Connections: connections,
		Transport: targettransport.Transport{Protocol: config.ProtocolHTTP}}
}

func poolRequest(ctx context.Context, path string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, path, nil).WithContext(ctx)
	request.Host = "service.example.test"
	return request
}

func poolAwait[T any](t *testing.T, ctx context.Context, values <-chan T) T {
	t.Helper()
	select {
	case value := <-values:
		return value
	case <-ctx.Done():
		t.Fatal("HTTP pool work did not join within the original deadline")
		var zero T
		return zero
	}
}

func TestHTTPRunProxyReusesTargetAcrossJoinedVisitors(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var connections atomic.Int32
	closed := make(chan struct{}, 4)
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.RemoteAddr)
	}))
	upstream.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
		if state == http.StateClosed {
			closed <- struct{}{}
		}
	}
	upstream.Start()
	defer upstream.Close()
	target := poolTarget(upstream.URL, 1)
	var err error
	target.proxy, err = target.NewHTTPProxy(ctx, "service.example.test", httpstream.ResponseHooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := target.proxy.Close(); err != nil {
			t.Error("close run HTTP proxy", err)
		}
	}()
	visit := func() string {
		t.Helper()
		life, stop := context.WithCancel(ctx)
		server, visitor := net.Pipe()
		done := make(chan error, 1)
		go func() {
			done <- target.Serve(life, server, "service.example.test", func(h http.Handler) http.Handler { return h }, httpstream.ResponseHooks{})
		}()
		transport := &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) { return visitor, nil }}
		defer func() {
			transport.CloseIdleConnections()
			stop()
			_ = visitor.Close()
			if err := poolAwait(t, ctx, done); err != nil {
				t.Error("join HTTP visitor", err)
			}
		}()
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://service.example.test/", nil)
		response, err := (&http.Client{Transport: transport}).Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(response.Body)
		if err := errors.Join(readErr, response.Body.Close()); err != nil || response.StatusCode != http.StatusOK {
			t.Fatal("pooled target response failed", response.StatusCode, err)
		}
		return string(body)
	}
	first, second := visit(), visit()
	if first == "" || second != first || connections.Load() != 1 || len(closed) != 0 {
		t.Fatal("a joined visitor retired or replaced the run's target pool", first, second, connections.Load())
	}
	if err := target.proxy.Close(); err != nil {
		t.Fatal(err)
	}
	poolAwait(t, ctx, closed)
	denied := httptest.NewRecorder()
	target.proxy.ServeAdmittedHTTP(denied, poolRequest(ctx, "/after-close"))
	if denied.Header().Get("Tnl-Error-Code") != string(diagnostic.TargetUnavailable) || connections.Load() != 1 {
		t.Fatal("closed run HTTP proxy allowed new target work", denied.Code, denied.Header())
	}
}

func TestHTTPRunProxyBoundsTargetConnectionsAndCancelsWaiters(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	entered, release := make(chan struct{}, 2), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	var connections atomic.Int32
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		select {
		case <-release:
			_, _ = io.WriteString(w, "released")
		case <-r.Context().Done():
		}
	}))
	upstream.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	upstream.Start()
	defer func() { unblock(); upstream.Close() }()
	forwarder, err := poolTarget(upstream.URL, 1).NewHTTPProxy(ctx, "service.example.test", httpstream.ResponseHooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := forwarder.Close(); err != nil {
			t.Error(err)
		}
	}()
	first := httptest.NewRecorder()
	firstDone := make(chan struct{})
	go func() { defer close(firstDone); forwarder.ServeAdmittedHTTP(first, poolRequest(ctx, "/held")) }()
	defer func() { unblock(); poolAwait(t, ctx, firstDone) }()
	poolAwait(t, ctx, entered)
	waiter, stopWaiter := context.WithCancel(ctx)
	defer stopWaiter()
	waiting := make(chan struct{})
	waiter = httptrace.WithClientTrace(waiter, &httptrace.ClientTrace{GetConn: func(string) { close(waiting) }})
	second := httptest.NewRecorder()
	secondDone := make(chan struct{})
	go func() {
		defer close(secondDone)
		forwarder.ServeAdmittedHTTP(second, poolRequest(waiter, "/cancelled"))
	}()
	poolAwait(t, ctx, waiting)
	stopWaiter()
	poolAwait(t, ctx, secondDone)
	if connections.Load() != 1 || len(entered) != 0 || second.Header().Get("Tnl-Error-Code") != string(diagnostic.TargetUnavailable) {
		t.Fatal("a cancelled waiter exceeded the run's target capacity or reached the target", connections.Load(), second.Code)
	}
	unblock()
	poolAwait(t, ctx, firstDone)
	if first.Code != http.StatusOK || first.Body.String() != "released" {
		t.Fatal("cancelling a target waiter interrupted a sibling response")
	}
}

func TestHTTPRunProxyDoesNotReplayFailedRequestOnReusedTarget(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var requests atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path == "/commit" {
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = connection.Close()
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()
	forwarder, err := poolTarget(upstream.URL, 1).NewHTTPProxy(ctx, "service.example.test", httpstream.ResponseHooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := forwarder.Close(); err != nil {
			t.Error(err)
		}
	}()
	for _, path := range []string{"/warm", "/commit", "/later"} {
		response := httptest.NewRecorder()
		forwarder.ServeAdmittedHTTP(response, poolRequest(ctx, path))
		if path == "/commit" {
			if requests.Load() != 2 || response.Header().Get("Tnl-Error-Code") != string(diagnostic.TargetUnavailable) {
				t.Fatal("a failed request was replayed or lost its forwarding diagnostic", requests.Load(), response.Code)
			}
		} else if response.Code != http.StatusOK || response.Body.String() != "ok" {
			t.Fatal("a separate request could not use the target pool", path, response.Code)
		}
	}
	if requests.Load() != 3 {
		t.Fatal("target pooling duplicated a request", requests.Load())
	}
}
