package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
)

func TestDynamicTargetFollowsReplacementWithoutReusingOldConnections(t *testing.T) {
	var accepts atomic.Int32
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "current app")
	}))
	upstream.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			accepts.Add(1)
		}
	}
	upstream.Start()
	defer upstream.Close()
	identity := "container-one"
	address := upstream.URL
	proxy, err := New(Config{Target: upstream.URL, Hostname: "route.example", MaxConnsPerHost: 4,
		ResolveTarget: func(*http.Request) (string, string, error) {
			return address, identity, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	visit := func() {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Host = "route.example"
		r.TLS = &tls.ConnectionState{ServerName: "route.example"}
		w := httptest.NewRecorder()
		proxy.ServeHTTP(w, r)
		if w.Code != http.StatusOK || w.Body.String() != "current app" {
			t.Fatalf("dynamic target visit = %d %q", w.Code, w.Body.String())
		}
	}
	visit()
	visit()
	if got := accepts.Load(); got != 1 {
		t.Fatalf("unchanged target did not reuse a connection: %d", got)
	}
	identity = "container-two"
	visit()
	if got := accepts.Load(); got != 2 {
		t.Fatalf("replacement at the same address reused the old container connection: %d", got)
	}
	replacement := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "current app")
	}))
	defer replacement.Close()
	address = replacement.URL
	visit()
	if got := accepts.Load(); got != 2 {
		t.Fatalf("new target address reached old target: %d connections", got)
	}
}

func TestDynamicTargetRetiresPoolAfterStreamingRequestFinishes(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var accepts atomic.Int32
	closed := make(chan struct{}, 1)
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hold" {
			_, _ = io.WriteString(w, "first")
			w.(http.Flusher).Flush()
			close(started)
			select {
			case <-release:
			case <-r.Context().Done():
			}
		}
		_, _ = io.WriteString(w, "last")
	}))
	upstream.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			accepts.Add(1)
		} else if state == http.StateClosed {
			select {
			case closed <- struct{}{}:
			default:
			}
		}
	}
	upstream.Start()
	t.Cleanup(upstream.Close)
	var replaced atomic.Bool
	handler, err := New(Config{Target: upstream.URL, Hostname: "route.example", MaxConnsPerHost: 1,
		ResolveTarget: func(*http.Request) (string, string, error) {
			identity := "one"
			if replaced.Load() {
				identity = "two"
			}
			return upstream.URL, identity, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	serve := func(path string) *httptest.ResponseRecorder {
		r := httptest.NewRequestWithContext(ctx, http.MethodGet, path, nil)
		r.Host = "route.example"
		r.TLS = &tls.ConnectionState{ServerName: "route.example"}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	first, done := make(chan *httptest.ResponseRecorder, 1), make(chan struct{})
	go func() { defer close(done); first <- serve("/hold") }()
	t.Cleanup(func() { cancel(); awaitProxyTest(t, done) })
	awaitProxyTest(t, started)
	replaced.Store(true)
	if w := serve("/"); w.Code != http.StatusOK || w.Body.String() != "last" {
		t.Fatalf("replacement visit = %d %q", w.Code, w.Body.String())
	}
	select {
	case <-done:
		t.Fatal("replacement interrupted the old streaming request")
	default:
	}
	close(release)
	if w := awaitProxyTest(t, first); w.Code != http.StatusOK || w.Body.String() != "firstlast" || !w.Flushed {
		t.Fatalf("retired target stream = %d %q, flushed=%t", w.Code, w.Body.String(), w.Flushed)
	}
	awaitProxyTest(t, closed)
	if w := serve("/"); w.Code != http.StatusOK || accepts.Load() != 2 {
		t.Fatalf("current pool was not retained: %d, accepts=%d", w.Code, accepts.Load())
	}
}

func TestDynamicTargetRejectsUnavailableSelectionWithoutFallingBack(t *testing.T) {
	var forwarded atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		forwarded.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	for _, test := range []struct {
		name, address, identity string
		err                     error
	}{
		{name: "resolver failure", err: errors.New("not running")},
		{name: "missing address", identity: "one"},
		{name: "missing identity", address: upstream.URL},
		{name: "invalid address", address: "http://user:secret@localhost", identity: "one"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var resolutions atomic.Int32
			handler, err := New(Config{Target: upstream.URL, Hostname: "route.example",
				Mounts: []Mount{{Prefix: "/api", Target: upstream.URL}},
				ResolveTarget: func(*http.Request) (string, string, error) {
					resolutions.Add(1)
					return test.address, test.identity, test.err
				}})
			if err != nil {
				t.Fatal(err)
			}
			serve := func(path string) *httptest.ResponseRecorder {
				r := httptest.NewRequestWithContext(proxyContext(t), http.MethodGet, path, nil)
				r.Host = "route.example"
				r.TLS = &tls.ConnectionState{ServerName: "route.example"}
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				return w
			}
			before := forwarded.Load()
			if w := serve("/"); w.Code != http.StatusBadGateway || w.Header().Get("Tnl-Error-Code") != string(diagnostic.TargetUnavailable) || forwarded.Load() != before {
				t.Fatalf("unavailable selection fell back: %d %v, forwarded=%d", w.Code, w.Header(), forwarded.Load())
			}
			if w := serve("/api/check"); w.Code != http.StatusNoContent || resolutions.Load() != 1 || forwarded.Load() != before+1 {
				t.Fatalf("mount used base resolver: %d, resolutions=%d, forwarded=%d", w.Code, resolutions.Load(), forwarded.Load())
			}
		})
	}
}
