package publisher

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/applicationlimits"
	publisherproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
)

// admission belongs to the publisher, including streams and upgrades that no
// longer occupy an ordinary pooled target connection.
func TestPublicURLPublisherSharesRequestLimitDuringStreams(t *testing.T) {
	for _, kind := range []string{"base", "mounted", "inline"} {
		t.Run(kind, func(t *testing.T) {
			started, release := make(chan struct{}), make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })
			service := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !strings.HasSuffix(r.URL.Path, "/hold") {
					_, _ = io.WriteString(w, "web")
					return
				}
				_, _ = io.WriteString(w, "first")
				w.(http.Flusher).Flush()
				close(started)
				select {
				case <-release:
				case <-r.Context().Done():
				}
				_, _ = io.WriteString(w, "last")
			})
			config := PublicURLServerConfig{Hostname: "route.example", Limits: applicationlimits.Limits{Concurrency: 1}}
			path := "/hold"
			if kind == "inline" {
				config.Handler = service
			} else {
				base, mounted := httptest.NewServer(service), httptest.NewServer(service)
				t.Cleanup(base.Close)
				t.Cleanup(mounted.Close)
				config.Target = base.URL
				config.Mounts = []publisherproxy.Mount{{Prefix: "/api", Target: mounted.URL, StripPrefix: true}}
				if kind == "mounted" {
					path = "/api/hold"
				}
			}
			t.Cleanup(unblock)
			route, err := newTestPublicURLServer(t, config)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = route.Close() })
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			t.Cleanup(cancel)
			serve := func(path string) *httptest.ResponseRecorder {
				request := newInlineTestRequest().WithContext(ctx)
				request.URL.Path = path
				response := httptest.NewRecorder()
				serveTestPublicRequest(t, route, response, request)
				return response
			}
			finished, done := make(chan *httptest.ResponseRecorder, 1), make(chan struct{})
			go func() { defer close(done); finished <- serve(path) }()
			t.Cleanup(func() { unblock(); cancel(); awaitPublisherTest(t, done) })
			awaitPublisherTest(t, started)
			for _, path := range []string{"/", "/api/check"} {
				response := serve(path)
				if response.Code != http.StatusServiceUnavailable || response.Header().Get("Tnl-Error-Code") != "TNL_REQUEST_LIMIT_REACHED" ||
					response.Header().Get("Retry-After") != "1" || response.Header().Get("Connection") != "close" {
					t.Fatalf("request %s bypassed stream limit: %d %v", path, response.Code, response.Header())
				}
			}
			unblock()
			if response := awaitPublisherTest(t, finished); response.Code != http.StatusOK || response.Body.String() != "firstlast" || !response.Flushed {
				t.Fatalf("stream = %d %q flushed=%t", response.Code, response.Body.String(), response.Flushed)
			}
			for _, path := range []string{"/", "/api/check"} {
				if response := serve(path); response.Code != http.StatusOK || response.Body.String() != "web" {
					t.Fatalf("request limit did not release for %s: %d %q", path, response.Code, response.Body.String())
				}
			}
		})
	}
}

func TestPublicURLPublisherHoldsRequestLimitDuringUpgrades(t *testing.T) {
	for _, kind := range []string{"base", "mounted", "inline"} {
		t.Run(kind, func(t *testing.T) {
			result := make(chan error, 1)
			service := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/hmr" {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				if r.Header.Get("Connection") != "Upgrade" || r.Header.Get("Upgrade") != "websocket" {
					http.Error(w, "missing upgrade", http.StatusBadRequest)
					return
				}
				conn, buffer, err := w.(http.Hijacker).Hijack()
				if err != nil {
					result <- err
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				_, err = buffer.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nhot")
				if err == nil {
					err = buffer.Flush()
				}
				payload := make([]byte, len("client upgrade bytes"))
				if err == nil {
					_, err = io.ReadFull(buffer, payload)
				}
				if err == nil && string(payload) != "client upgrade bytes" {
					err = fmt.Errorf("upgraded request = %q", payload)
				}
				if err == nil {
					_, err = conn.Write([]byte("ack"))
				}
				result <- err
			})
			config := PublicURLServerConfig{Hostname: "route.example", Limits: applicationlimits.Limits{Concurrency: 1},
				Certificate: visitorfixture.Certificate(t, "route.example")}
			path := "/hmr"
			if kind == "inline" {
				config.Handler = service
			} else {
				upstream := httptest.NewServer(service)
				t.Cleanup(upstream.Close)
				config.Target = upstream.URL
				if kind == "mounted" {
					base := httptest.NewServer(service)
					t.Cleanup(base.Close)
					config.Target = base.URL
					config.Mounts = []publisherproxy.Mount{{Prefix: "/api", Target: upstream.URL, StripPrefix: true}}
					path = "/api/hmr"
				}
			}
			route, err := newTestPublicURLServer(t, config)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = route.Close() })
			finished := make(chan struct{})
			handler := route.http.Handler
			route.http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == path {
					defer close(finished)
				}
				handler.ServeHTTP(w, r)
			})
			if err := route.Start(); err != nil {
				t.Fatal(err)
			}
			handled := make(chan struct{})
			stream, err := openHTTPTestRouteServer(route, handled)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = stream.Close(); awaitPublisherTest(t, handled) })
			conn := tls.Client(stream, &tls.Config{ServerName: "route.example", RootCAs: visitorfixture.Roots(t, config.Certificate)})
			defer conn.Close()
			if _, err := io.WriteString(conn, "GET "+path+" HTTP/1.1\r\nHost: route.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			reader := bufio.NewReader(conn)
			response, err := http.ReadResponse(reader, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusSwitchingProtocols {
				t.Fatalf("upgrade status = %d", response.StatusCode)
			}
			payload := make([]byte, len("hot"))
			if _, err := io.ReadFull(reader, payload); err != nil || string(payload) != "hot" {
				t.Fatalf("upgraded response = %q, %v", payload, err)
			}
			other := singleConnectionRouteClient(t, route, true)
			assertRouteOverloaded(t, other)
			if _, err := io.WriteString(conn, "client upgrade bytes"); err != nil {
				t.Fatal(err)
			}
			ack := make([]byte, len("ack"))
			if _, err := io.ReadFull(reader, ack); err != nil || string(ack) != "ack" {
				t.Fatalf("upgrade acknowledgement = %q, %v", ack, err)
			}
			// close the pipe before TLS cleanup: simultaneous close-notify writes
			// from an inline handler and client would wait on each other.
			_ = stream.Close()
			if err := awaitPublisherTest(t, result); err != nil {
				t.Fatal(err)
			}
			awaitPublisherTest(t, finished)
			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://route.example/", nil)
			if err != nil {
				t.Fatal(err)
			}
			if got := doRouteRequest(other, request); got.err != nil || got.status != http.StatusNoContent {
				t.Fatalf("request after upgrade release = %d, %v", got.status, got.err)
			}
		})
	}
}
