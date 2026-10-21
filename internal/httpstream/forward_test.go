package httpstream

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/privatetrust"
	"github.com/tnldotdev/tnl/internal/streamcopy"
)

type observedLocal struct {
	net.Conn
	reads *atomic.Int64
}

func (c *observedLocal) Read(p []byte) (int, error) { c.reads.Add(1); return c.Conn.Read(p) }

func (c *observedLocal) CloseWrite() error {
	if writer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return writer.CloseWrite()
	}
	return errors.ErrUnsupported
}

func privateHTTPFixture(t *testing.T, handler http.Handler) (*httptest.Server, privatetrust.Snapshot) {
	t.Helper()
	root, certificate := providerCertificate(t)
	target := httptest.NewUnstartedServer(handler)
	target.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
	target.Config.ErrorLog = log.New(io.Discard, "", 0)
	target.StartTLS()
	t.Cleanup(target.Close)
	return target, providerSnapshot(t, root)
}

func httpVisitor(t *testing.T, address string, trust *privatetrust.Snapshot) (string, *atomic.Int64, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	var group sync.WaitGroup
	reads, failures := &atomic.Int64{}, make(chan error, 32)
	group.Go(func() {
		for {
			local, err := listener.Accept()
			if err != nil {
				return
			}
			group.Go(func() {
				defer local.Close()
				provider, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
				if err != nil {
					failures <- err
					return
				}
				defer provider.Close()
				failures <- forwardVerifiedTarget(ctx, &observedLocal{Conn: local, reads: reads}, provider, trust)
			})
		}
	})
	t.Cleanup(func() { cancel(); _ = listener.Close(); group.Wait() })
	return listener.Addr().String(), reads, failures
}

func privateHTTPClient(t *testing.T) *http.Client {
	t.Helper()
	transport := &http.Transport{Proxy: nil}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func TestPrivateHTTPVerifiedTLSHostStreamingAndNoRedirectEscape(t *testing.T) {
	first := make(chan struct{})
	finish := make(chan struct{})
	var calls atomic.Int64
	target, trust := privateHTTPFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Host != "db.example" || r.TLS == nil || r.Header.Get("Authorization") != "Bearer local-only" {
			t.Error("HTTP target identity, TLS or credentials changed")
		}
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "https://escape.invalid/credentials", http.StatusTemporaryRedirect)
			return
		}
		prefix := make([]byte, 4096)
		if _, err := io.ReadFull(r.Body, prefix); err != nil {
			t.Error(err)
			return
		}
		close(first)
		<-finish
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil || n != 2<<20 {
			t.Errorf("streamed request body: %d %v", n, err)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	address, _, _ := httpVisitor(t, target.Listener.Addr().String(), &trust)
	reader, writer := io.Pipe()
	client := privateHTTPClient(t)
	request, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+address+"/stream", reader)
	request.Header.Set("Authorization", "Bearer local-only")
	response := make(chan *http.Response, 1)
	go func() {
		r, err := client.Do(request)
		if err != nil {
			t.Error(err)
		}
		response <- r
	}()
	if _, err := writer.Write(bytes.Repeat([]byte{'x'}, 4096)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-first:
	case <-time.After(3 * time.Second):
		t.Fatal("request was buffered instead of streamed")
	}
	close(finish)
	if _, err := writer.Write(bytes.Repeat([]byte{'y'}, 2<<20)); err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()
	r := <-response
	if r == nil {
		t.Fatal("no streaming response")
	}
	line, err := bufio.NewReader(r.Body).ReadString('\n')
	if err != nil || line != "data: first\n" {
		t.Fatalf("SSE did not flush: %q %v", line, err)
	}
	_ = r.Body.Close()
	request, _ = http.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+address+"/redirect", strings.NewReader("secret"))
	request.Header.Set("Authorization", "Bearer local-only")
	r, err = client.Do(request)
	if err != nil || r.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("redirect was followed: %v", err)
	}
	_ = r.Body.Close()
	if calls.Load() != 2 {
		t.Fatalf("HTTP operation replayed: %d calls", calls.Load())
	}
}

func TestPrivateHTTPWrongCAOrNameReadsNoLocalCredentials(t *testing.T) {
	for _, wrongName := range []bool{false, true} {
		t.Run(fmt.Sprint(wrongName), func(t *testing.T) {
			var calls atomic.Int64
			target, trust := privateHTTPFixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
			if wrongName {
				name := "wrong.example"
				// capture a different valid hostname using the same public CA.
				trust = providerSnapshot(t, trust.PEM, name)
			} else {
				root, _ := providerCertificate(t)
				trust = providerSnapshot(t, root)
			}
			address, reads, failures := httpVisitor(t, target.Listener.Addr().String(), &trust)
			local, err := net.DialTimeout("tcp", address, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer local.Close()
			_, _ = io.WriteString(local, "POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret\r\nContent-Length: 6\r\n\r\nsecret")
			select {
			case err := <-failures:
				if err == nil || reads.Load() != 0 || calls.Load() != 0 {
					t.Fatalf("invalid TLS read credentials: reads=%d calls=%d err=%v", reads.Load(), calls.Load(), err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("invalid TLS did not fail closed")
			}
		})
	}
}

func TestPrivateHTTPNativeHTTPSPassThrough(t *testing.T) {
	target, trust := privateHTTPFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "native.example" {
			t.Error("opaque HTTPS Host was rewritten")
		}
		_, _ = io.WriteString(w, "native TLS")
	}))
	address, _, _ := httpVisitor(t, target.Listener.Addr().String(), nil)
	verification, err := trust.Verifier()
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{TLSClientConfig: verification}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	request, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+address, nil)
	request.Host = "native.example"
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil || string(data) != "native TLS" {
		t.Fatalf("native HTTPS: %q %v", data, err)
	}
}

func TestPrivateHTTPUpgradeAndFraming(t *testing.T) {
	for _, protocol := range []string{"websocket", "SPDY/3.1"} {
		t.Run(protocol, func(t *testing.T) {
			target, trust := privateHTTPFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Upgrade") != protocol || r.Host != "db.example" {
					t.Error("upgrade metadata changed")
				}
				conn, buffer, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				defer conn.Close()
				_, _ = fmt.Fprintf(buffer, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: %s\r\n\r\n", protocol)
				_ = buffer.Flush()
				_, _ = io.Copy(conn, buffer)
				_, _ = io.WriteString(conn, "finished")
			}))
			address, _, _ := httpVisitor(t, target.Listener.Addr().String(), &trust)
			local, err := net.DialTimeout("tcp", address, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer local.Close()
			_ = local.SetDeadline(time.Now().Add(3 * time.Second))
			_, _ = fmt.Fprintf(local, "POST /exec HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: %s\r\n\r\n", protocol)
			reader := bufio.NewReader(local)
			response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodPost})
			if err != nil || response.StatusCode != http.StatusSwitchingProtocols {
				t.Fatalf("upgrade response: %v", err)
			}
			payload := []byte{0, 1, 2, 3, 255, 0}
			_, _ = local.Write(payload)
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(reader, got); err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("upgraded bytes: %x %v", got, err)
			}
			if err := local.(*net.TCPConn).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			final, err := io.ReadAll(reader)
			if err != nil || string(final) != "finished" {
				t.Fatalf("upgrade half-close lost the final response: %q %v", final, err)
			}
		})
	}
	target, trust := privateHTTPFixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("ambiguous framing reached target") }))
	address, _, _ := httpVisitor(t, target.Listener.Addr().String(), &trust)
	local, _ := net.DialTimeout("tcp", address, time.Second)
	defer local.Close()
	_ = local.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.WriteString(local, "POST / HTTP/1.1\r\nHost: local\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nxx")
	response, err := http.ReadResponse(bufio.NewReader(local), &http.Request{Method: http.MethodPost})
	if err != nil || response.StatusCode != http.StatusBadRequest {
		t.Fatalf("ambiguous framing accepted: %v", err)
	}
	_ = response.Body.Close()
	local, err = net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	_ = local.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = fmt.Fprintf(local, "GET / HTTP/1.1\r\nHost: local\r\nX-Large: %s\r\n\r\n", strings.Repeat("x", 80<<10))
	response, err = http.ReadResponse(bufio.NewReader(local), &http.Request{Method: http.MethodGet})
	if err != nil || response.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("HTTP header bound was not enforced: %v", err)
	}
	_ = response.Body.Close()
}

func TestPrivateHTTPPOSTPathLossNeverReplays(t *testing.T) {
	var calls atomic.Int64
	target, trust := privateHTTPFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		conn, _, _ := w.(http.Hijacker).Hijack()
		_ = conn.Close()
	}))
	address, _, _ := httpVisitor(t, target.Listener.Addr().String(), &trust)
	request, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+address, strings.NewReader("one operation"))
	response, err := privateHTTPClient(t).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadGateway || !response.Close || calls.Load() != 1 {
		t.Fatalf("failed POST replayed: status=%d calls=%d", response.StatusCode, calls.Load())
	}
}

func TestPrivateHTTPExhaustedUpstreamClosesAfterBoundedError(t *testing.T) {
	var calls atomic.Int64
	target, trust := privateHTTPFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		connection, buffer, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer connection.Close()
		_, _ = io.WriteString(buffer, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		_ = buffer.Flush()
	}))
	address, _, _ := httpVisitor(t, target.Listener.Addr().String(), &trust)
	local, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	_ = local.SetDeadline(time.Now().Add(3 * time.Second))
	reader := bufio.NewReader(local)
	for i := range 2 {
		_, _ = io.WriteString(local, "GET / HTTP/1.1\r\nHost: loopback\r\n\r\n")
		response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if i == 1 && (response.StatusCode != http.StatusBadGateway || !response.Close) {
			t.Fatal("exhausted stream kept the local connection alive")
		}
	}
	if _, err := reader.ReadByte(); !errors.Is(err, io.EOF) || calls.Load() != 1 {
		t.Fatalf("error response did not close or replayed a request: calls=%d err=%v", calls.Load(), err)
	}
}

// keep the direct forwarding boundary independently cancelable, including
// a verified HTTP connection on which the client has not sent headers yet.
func TestPrivateHTTPIdleCancellationJoins(t *testing.T) {
	target, trust := privateHTTPFixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	address, _, failures := httpVisitor(t, target.Listener.Addr().String(), &trust)
	local, _ := net.DialTimeout("tcp", address, time.Second)
	_ = local.Close()
	select {
	case err := <-failures:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("idle HTTP connection did not join")
	}
}

// this fixture supplies an already-verified target to the shared HTTP stream
// boundary. serving code owns mandatory visitor TLS and admission separately.
func forwardVerifiedTarget(ctx context.Context, local, target net.Conn, trust *privatetrust.Snapshot) error {
	stop := context.AfterFunc(ctx, func() { _ = local.Close(); _ = target.Close() })
	defer stop()
	if trust == nil {
		_, err := streamcopy.Copy(local, target)
		return err
	}
	verification, err := trust.Verifier()
	if err != nil {
		return err
	}
	secure := tls.Client(target, verification)
	if err = secure.HandshakeContext(ctx); err != nil {
		return err
	}
	return Forward(ctx, local, secure, &url.URL{Scheme: "https", Host: trust.Hostname})
}
