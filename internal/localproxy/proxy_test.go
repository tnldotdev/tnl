package localproxy

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
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/diagnostic"
)

func TestProxyForwardsOnlyExactTrustedRequests(t *testing.T) {
	type received struct {
		Host           string
		Forwarded      string
		ForwardedFor   string
		ForwardedHost  string
		ForwardedProto string
		RealIP         string
	}
	requests := make(chan received, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests <- received{
			Host: request.Host, Forwarded: request.Header.Get("Forwarded"), ForwardedFor: request.Header.Get("X-Forwarded-For"),
			ForwardedHost:  request.Header.Get("X-Forwarded-Host"),
			ForwardedProto: request.Header.Get("X-Forwarded-Proto"), RealIP: request.Header.Get("X-Real-IP"),
		}
		response.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	handler, err := New(upstream.URL, "route.example", 0)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequestWithContext(proxyContext(t), http.MethodGet, "/test", nil)
	request.Host = "route.example"
	request.RemoteAddr = "192.0.2.10:1234"
	request.TLS = &tls.ConnectionState{ServerName: "ROUTE.EXAMPLE"}
	request.Header.Set("Forwarded", "for=attacker")
	request.Header.Set("X-Forwarded-For", "198.51.100.1")
	request.Header.Set("X-Real-IP", "198.51.100.1")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	got := <-requests
	if got.Host != "route.example" || got.Forwarded != "" || got.ForwardedFor != "192.0.2.10" || got.ForwardedHost != "route.example" || got.ForwardedProto != "https" || got.RealIP != "" {
		t.Fatalf("upstream request = %#v", got)
	}

	for name, mutate := range map[string]func(*http.Request){
		"wrong host": func(request *http.Request) { request.Host = "other.example" },
		"wrong SNI":  func(request *http.Request) { request.TLS.ServerName = "other.example" },
		"CONNECT":    func(request *http.Request) { request.Method = http.MethodConnect },
		"absolute": func(request *http.Request) {
			request.RequestURI = "http://127.0.0.1/private"
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequestWithContext(proxyContext(t), http.MethodGet, "/test", nil)
			request.Host = "route.example"
			request.TLS = &tls.ConnectionState{ServerName: "route.example"}
			mutate(request)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d", response.Code)
			}
			if response.Header().Get("Tnl-Error-Code") != "TNL_REQUEST_REJECTED" {
				t.Fatalf("diagnostic code = %q", response.Header().Get("Tnl-Error-Code"))
			}
		})
	}
}

func TestNewDiagnosesInvalidRouteHostname(t *testing.T) {
	if _, err := New("3000", "INVALID.example", 0); err == nil {
		t.Fatal("New accepted a noncanonical route hostname")
	} else if code, ok := diagnostic.CodeOf(err); !ok || code != diagnostic.PublicURLInvalid {
		t.Fatalf("New diagnostic = %q, %t", code, ok)
	}
}

func TestProxyDiagnosesUnavailableTarget(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target := "http://" + listener.Addr().String()
	t.Cleanup(func() { _ = listener.Close() })
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	handler, err := New(target, "route.example", 0)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequestWithContext(proxyContext(t), http.MethodGet, "/", nil)
	request.Host = "route.example"
	request.TLS = &tls.ConnectionState{ServerName: "route.example"}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadGateway || response.Header().Get("Tnl-Error-Code") != "TNL_TARGET_UNAVAILABLE" {
		t.Fatalf("response = %d, %#v", response.Code, response.Header())
	}
	body := response.Body.String()
	if !strings.HasPrefix(body, "+--[ tnl ]-- local service unavailable ") ||
		!strings.Contains(body, "+-- TNL_TARGET_UNAVAILABLE ") || !strings.Contains(body, "https://tnl.dev/e/target") {
		t.Fatalf("body = %q", body)
	}
}

func TestProxyPreservesLocalServiceErrors(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("X-Application-Error", "true")
		http.Error(response, "application failure", http.StatusBadGateway)
	}))
	defer upstream.Close()
	handler, err := New(upstream.URL, "route.example", 0)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequestWithContext(proxyContext(t), http.MethodGet, "/", nil)
	request.Host = "route.example"
	request.TLS = &tls.ConnectionState{ServerName: "route.example"}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadGateway || response.Body.String() != "application failure\n" ||
		response.Header().Get("X-Application-Error") != "true" || response.Header().Get("Tnl-Error-Code") != "" {
		t.Fatalf("response = %d, %#v, %q", response.Code, response.Header(), response.Body.String())
	}
}

func TestProxyForwardsWebSocketUpgrade(t *testing.T) {
	started, done := make(chan struct{}), make(chan struct{})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	result := make(chan error, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		close(started)
		defer close(done)
		if request.Header.Get("Connection") != "Upgrade" || request.Header.Get("Upgrade") != "websocket" {
			http.Error(response, "missing upgrade", http.StatusBadRequest)
			return
		}
		connection, buffer, err := response.(http.Hijacker).Hijack()
		if err != nil {
			result <- err
			return
		}
		defer connection.Close()
		stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
		defer stop()
		_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
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
			_, err = connection.Write([]byte("ack"))
		}
		result <- err
	}))
	t.Cleanup(upstream.Close)
	t.Cleanup(func() {
		cancel()
		select {
		case <-started:
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("upgrade worker did not stop")
			}
		default:
		}
	})
	handler, err := New(upstream.URL, "route.example", 1)
	if err != nil {
		t.Fatal(err)
	}
	frontend := httptest.NewUnstartedServer(handler)
	t.Cleanup(frontend.Close)
	frontend.StartTLS()

	connection, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", frontend.Listener.Addr().String(), &tls.Config{
		ServerName: "route.example", InsecureSkipVerify: true, // Test certificate is self-signed.
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, err = io.WriteString(connection, "GET /hmr HTTP/1.1\r\nHost: route.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://route.example/hmr", nil)
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(connection)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d", response.StatusCode)
	}
	payload := make([]byte, len("hot"))
	if _, err := io.ReadFull(reader, payload); err != nil {
		t.Fatal(err)
	}
	if string(payload) != "hot" {
		t.Fatalf("payload = %q", payload)
	}
	// An upgraded connection still occupies a request slot even though the
	// HTTP transport no longer owns it as an ordinary pooled connection.
	overloadClient := frontend.Client()
	overloadClient.Timeout = 2 * time.Second
	overloadClient.Transport.(*http.Transport).TLSClientConfig.ServerName = "route.example"
	overloadClient.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true // Self-signed test certificate for another host.
	overloadRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, frontend.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	overloadRequest.Host = "route.example"
	overloadResponse, err := overloadClient.Do(overloadRequest)
	if err != nil {
		t.Fatal(err)
	}
	_ = overloadResponse.Body.Close()
	if overloadResponse.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("request during upgrade = %d", overloadResponse.StatusCode)
	}
	if _, err := io.WriteString(connection, "client upgrade bytes"); err != nil {
		t.Fatal(err)
	}
	ack := make([]byte, 3)
	if _, err := io.ReadFull(reader, ack); err != nil || string(ack) != "ack" {
		t.Fatalf("upgrade acknowledgement = %q, %v", ack, err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestProxyFlushesStreamingResponses(t *testing.T) {
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(response, "first\n")
		response.(http.Flusher).Flush()
		<-release
		_, _ = io.WriteString(response, "second\n")
	}))
	t.Cleanup(upstream.Close)
	t.Cleanup(unblock)
	handler, err := New(upstream.URL, "route.example", 0)
	if err != nil {
		t.Fatal(err)
	}
	frontend := httptest.NewTLSServer(handler)
	t.Cleanup(frontend.Close)
	// Release the handler before either HTTP server's Close waits for it.
	t.Cleanup(unblock)
	client := frontend.Client()
	client.Timeout = 2 * time.Second
	client.Transport.(*http.Transport).TLSClientConfig.ServerName = "route.example"
	client.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true // Test certificate is self-signed for a different host.
	request, err := http.NewRequest(http.MethodGet, frontend.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "route.example"
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	first := make([]byte, len("first\n"))
	if _, err := io.ReadFull(response.Body, first); err != nil {
		t.Fatal(err)
	}
	if string(first) != "first\n" {
		t.Fatalf("first chunk = %q", first)
	}
	unblock()
	second := make([]byte, len("second\n"))
	if _, err := io.ReadFull(response.Body, second); err != nil {
		t.Fatal(err)
	}
	if string(second) != "second\n" {
		t.Fatalf("second chunk = %q", second)
	}
}

func TestNormalizeTarget(t *testing.T) {
	accepted := map[string]string{
		"3000":                           "http://127.0.0.1:3000",
		"03000":                          "http://127.0.0.1:3000",
		"localhost:3000":                 "http://127.0.0.1:3000",
		"LOCALHOST:03000":                "http://127.0.0.1:3000",
		"http://localhost:3000":          "http://127.0.0.1:3000",
		"HTTP://LOCALHOST:03000":         "http://127.0.0.1:3000",
		"http://127.0.0.1:3000":          "http://127.0.0.1:3000",
		"http://127.0.0.2:03000":         "http://127.0.0.2:3000",
		"http://[::1]:3000":              "http://[::1]:3000",
		"http://[0:0:0:0:0:0:0:1]:03000": "http://[::1]:3000",
		"HTTP://[0:0:0:0:0:0:0:1]:3000":  "http://[::1]:3000",
	}
	for target, want := range accepted {
		t.Run(target, func(t *testing.T) {
			got, err := NormalizeTarget(target)
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("NormalizeTarget(%q) = %q, want %q", target, got, want)
			}
		})
	}

	rejected := []string{
		"", "0", "65536", "+3000", "-3000", "30x00", "127.0.0.1:3000",
		" 3000", "3000 ", "3 000", "\t3000",
		"localhost", "localhost:", "localhost:3000/path", "localhost:3000:4000",
		"http://localhost.:3000", "http://192.0.2.1:3000", "http://[::2]:3000",
		"https://127.0.0.1:3000", "http://127.0.0.1", "http://127.0.0.1:0",
		"http://127.0.0.1:65536", "http://127.0.0.1:bad",
		"http://127.0.0.1:3000/", "http://127.0.0.1:3000/path",
		"http://user@127.0.0.1:3000", "http://127.0.0.1:3000?query",
		"http://127.0.0.1:3000#fragment",
	}
	for _, target := range rejected {
		t.Run(target, func(t *testing.T) {
			if got, err := NormalizeTarget(target); err == nil {
				t.Fatalf("NormalizeTarget(%q) = %q, want error", target, got)
			} else if code, ok := diagnostic.CodeOf(err); !ok || code != diagnostic.TargetInvalid {
				t.Fatalf("NormalizeTarget(%q) diagnostic = %q, %t", target, code, ok)
			}
		})
	}
}

func TestPreflightRequiresAvailableTarget(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(upstream.Close)
	if err := Preflight(proxyContext(t), upstream.URL); err != nil {
		t.Fatal(err)
	}
	upstream.Close()
	if err := Preflight(proxyContext(t), upstream.URL); err == nil {
		t.Fatal("Preflight accepted unavailable target")
	} else if code, ok := diagnostic.CodeOf(err); !ok || code != diagnostic.TargetUnavailable {
		t.Fatalf("Preflight diagnostic = %q, %t", code, ok)
	}
}

func TestWaitForTargetAllowsDevelopmentServerStartup(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	failed, release := make(chan struct{}), make(chan struct{})
	result, done := make(chan error, 1), make(chan struct{})
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("target waiter did not stop")
		}
	})
	go func() {
		defer close(done)
		first := true
		result <- waitForTarget(ctx, "http://"+address, func(ctx context.Context, target string) error {
			err := Preflight(ctx, target)
			if first {
				first = false
				if err == nil {
					return errors.New("target unexpectedly available before startup")
				}
				close(failed)
				select {
				case <-release:
				case <-ctx.Done():
				}
			}
			return err
		})
	}()
	select {
	case <-failed:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	started, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = started.Close() })
	_ = started.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second))
	accepted := make(chan error, 1)
	joined := make(chan struct{})
	t.Cleanup(func() {
		_ = started.Close()
		select {
		case <-joined:
		case <-time.After(time.Second):
			t.Error("target listener worker did not stop")
		}
	})
	go func() {
		defer close(joined)
		connection, err := started.Accept()
		if err == nil {
			err = connection.Close()
		}
		accepted <- err
	}()
	close(release)
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case err := <-accepted:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestWaitForTargetPreservesUnavailableDiagnosticOnTimeout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	target := "http://" + listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	err = WaitForTarget(ctx, target)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitForTarget error = %v", err)
	}
	if code, ok := diagnostic.CodeOf(err); !ok || code != diagnostic.TargetUnavailable {
		t.Fatalf("WaitForTarget diagnostic = %q, %t", code, ok)
	}
}

func proxyContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func FuzzNormalizeTarget(f *testing.F) {
	for _, target := range []string{
		"3000",
		"03000",
		"http://127.0.0.1:3000",
		"HTTP://[0:0:0:0:0:0:0:1]:03000",
		"localhost:3000",
		"http://localhost:3000",
		"http://127.0.0.1:3000/path",
		"http://user@127.0.0.1:3000",
		"http://127.0.0.1:3000#fragment",
	} {
		f.Add(target)
	}

	f.Fuzz(func(t *testing.T, target string) {
		canonical, err := NormalizeTarget(target)
		if err != nil {
			return
		}
		roundTrip, err := NormalizeTarget(canonical)
		if err != nil || roundTrip != canonical {
			t.Fatalf("canonical target is not idempotent: %q, %v", roundTrip, err)
		}

		parsed, err := url.Parse(canonical)
		if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.Host == "" ||
			parsed.Path != "" || parsed.RawPath != "" || parsed.ForceQuery || parsed.RawQuery != "" ||
			parsed.Fragment != "" || parsed.RawFragment != "" || parsed.Opaque != "" {
			t.Fatalf("unsafe canonical target %q: %#v, %v", canonical, parsed, err)
		}
		address, err := netip.ParseAddr(parsed.Hostname())
		if err != nil || !address.IsLoopback() || address.Zone() != "" {
			t.Fatalf("canonical target is not local-only: %q", canonical)
		}
		port, err := strconv.ParseUint(parsed.Port(), 10, 16)
		if err != nil || port == 0 {
			t.Fatalf("canonical target has invalid port: %q", canonical)
		}
		want := "http://" + net.JoinHostPort(address.String(), strconv.FormatUint(port, 10))
		if canonical != want {
			t.Fatalf("canonical target = %q, want %q", canonical, want)
		}
	})
}
