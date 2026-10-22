package localproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
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
	handler, err := NewWithMounts(upstream.URL, "route.example", 0, nil)
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

func TestNewWithMountsDiagnosesInvalidPublicURLHostname(t *testing.T) {
	if _, err := NewWithMounts("3000", "INVALID.example", 0, nil); err == nil {
		t.Fatal("NewWithMounts accepted a noncanonical public URL hostname")
	} else if code, ok := diagnostic.CodeOf(err); !ok || code != diagnostic.PublicURLInvalid {
		t.Fatalf("NewWithMounts diagnostic = %q, %t", code, ok)
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
	handler, err := NewWithMounts(target, "route.example", 0, nil)
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
	if !strings.HasPrefix(body, "+--[ tnl ]-- target unavailable ") ||
		!strings.Contains(body, "+-- TNL_TARGET_UNAVAILABLE ") || !strings.Contains(body, "https://tnl.dev/e/target") {
		t.Fatalf("body = %q", body)
	}
}

func TestProxyReportsTargetFailureOnceUntilItRecovers(t *testing.T) {
	var broken atomic.Bool
	broken.Store(true)
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		if broken.Load() {
			connection, _, err := response.(http.Hijacker).Hijack()
			if err == nil {
				_ = connection.Close()
			}
			return
		}
		response.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	var failures atomic.Int32
	handler, err := NewWithMounts(upstream.URL, "route.example", 0, nil, func() { failures.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	request := func() int {
		r := httptest.NewRequestWithContext(proxyContext(t), http.MethodGet, "/", nil)
		r.Host = "route.example"
		r.TLS = &tls.ConnectionState{ServerName: "route.example"}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, r)
		return response.Code
	}
	for _, expected := range []int{http.StatusBadGateway, http.StatusBadGateway} {
		if status := request(); status != expected {
			t.Fatalf("broken target status = %d", status)
		}
	}
	if got := failures.Load(); got != 1 {
		t.Fatalf("first failure count = %d", got)
	}
	broken.Store(false)
	if status := request(); status != http.StatusOK {
		t.Fatalf("recovered status = %d", status)
	}
	broken.Store(true)
	if status := request(); status != http.StatusBadGateway || failures.Load() != 2 {
		t.Fatalf("second failure status = %d, count = %d", status, failures.Load())
	}
}

func TestProxyPreservesLocalServiceErrors(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("X-Application-Error", "true")
		http.Error(response, "application failure", http.StatusBadGateway)
	}))
	defer upstream.Close()
	handler, err := NewWithMounts(upstream.URL, "route.example", 0, nil)
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
	for _, mounted := range []bool{false, true} {
		name := "base"
		if mounted {
			name = "mounted"
		}
		t.Run(name, func(t *testing.T) { testProxyForwardsWebSocketUpgrade(t, mounted) })
	}
}

func testProxyForwardsWebSocketUpgrade(t *testing.T, mounted bool) {
	started, done := make(chan struct{}), make(chan struct{})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	result := make(chan error, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		close(started)
		defer close(done)
		if request.Header.Get("Connection") != "Upgrade" || request.Header.Get("Upgrade") != "websocket" || request.URL.Path != "/hmr" {
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
	base := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(base.Close)
	handler, err := NewWithMounts(upstream.URL, "route.example", 1, nil)
	path := "/hmr"
	if mounted {
		path = "/api/hmr"
		handler, err = NewWithMounts(base.URL, "route.example", 1, []Mount{{Prefix: "/api", Target: upstream.URL, StripPrefix: true}})
	}
	if err != nil {
		t.Fatal(err)
	}
	frontend := httptest.NewUnstartedServer(handler)
	t.Cleanup(frontend.Close)
	frontend.StartTLS()

	connection, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", frontend.Listener.Addr().String(), &tls.Config{
		ServerName: "route.example", InsecureSkipVerify: true, // test certificate is self-signed.
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, err = io.WriteString(connection, "GET "+path+" HTTP/1.1\r\nHost: route.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://route.example"+path, nil)
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
	// an upgraded connection still occupies a request slot even though the
	// HTTP transport no longer owns it as an ordinary pooled connection.
	overloadClient := frontend.Client()
	overloadClient.Timeout = 2 * time.Second
	overloadClient.Transport.(*http.Transport).TLSClientConfig.ServerName = "route.example"
	overloadClient.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true // self-signed test certificate for another host.
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
	handler, err := NewWithMounts(upstream.URL, "route.example", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	frontend := httptest.NewTLSServer(handler)
	t.Cleanup(frontend.Close)
	// release the handler before either HTTP server's Close waits for it.
	t.Cleanup(unblock)
	client := frontend.Client()
	client.Timeout = 2 * time.Second
	client.Transport.(*http.Transport).TLSClientConfig.ServerName = "route.example"
	client.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true // test certificate is self-signed for a different host.
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

func TestPreflightRejectsUntrustedHTTPSTarget(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(upstream.Close)
	if err := Preflight(proxyContext(t), upstream.URL); err == nil {
		t.Fatal("Preflight accepted an untrusted HTTPS certificate")
	} else if code, ok := diagnostic.CodeOf(err); !ok || code != diagnostic.TargetUnavailable {
		t.Fatalf("Preflight diagnostic = %q, %t", code, ok)
	}
}

func TestProxyUsesVerifiedHTTPSTargetAndMountedService(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Host != "route.example" || request.Header.Get("X-Forwarded-Proto") != "https" {
			http.Error(response, "incorrect forwarded request", http.StatusBadRequest)
			return
		}
		_, _ = response.Write([]byte(request.URL.Path))
	}))
	t.Cleanup(upstream.Close)
	path := filepath.Join(t.TempDir(), "target-ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := LoadTargetRootCAs(path)
	if err != nil {
		t.Fatal(err)
	}
	options := TargetOptions{RootCAs: roots}
	if err := PreflightWithOptions(proxyContext(t), upstream.URL, options); err != nil {
		t.Fatalf("verified HTTPS preflight: %v", err)
	}
	handler, err := NewWithMountsHooksOptions(upstream.URL, "route.example", 0,
		[]Mount{{Prefix: "/api", Target: upstream.URL, StripPrefix: true, Options: options}}, ResponseHooks{}, options)
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{"/hello": "/hello", "/api/hello": "/hello"} {
		request := httptest.NewRequestWithContext(proxyContext(t), http.MethodGet, path, nil)
		request.Host = "route.example"
		request.TLS = &tls.ConnectionState{ServerName: "route.example"}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK || response.Body.String() != want {
			t.Fatalf("HTTPS target %s: %d %q", path, response.Code, response.Body.String())
		}
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
