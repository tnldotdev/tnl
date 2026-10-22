package httpstream_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	publisherproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/transport/httpstream"
)

const uploadTestTimeout = 250 * time.Millisecond

// shorten only the production body budget; keep header and cleanup bounds real.
type uploadDeadlineConn struct{ net.Conn }

func (c uploadDeadlineConn) SetReadDeadline(deadline time.Time) error {
	if remaining := time.Until(deadline); remaining > 20*time.Second && remaining <= 30*time.Second {
		deadline = time.Now().Add(uploadTestTimeout)
	}
	return c.Conn.SetReadDeadline(deadline)
}

func (c uploadDeadlineConn) CloseWrite() error {
	return c.Conn.(interface{ CloseWrite() error }).CloseWrite()
}

func streamingProxy(t *testing.T, kind string, h2 bool, backend string) (*http.Client, string) {
	t.Helper()
	transport := &http.Transport{ForceAttemptHTTP2: h2}
	address := ""
	if kind == "localproxy" {
		handler, err := publisherproxy.NewWithMounts(backend, "proxy.example.test", 4, []publisherproxy.Mount{{Prefix: "/mounted", StripPrefix: true, Target: backend}})
		if err != nil {
			t.Fatal(err)
		}
		server := httptest.NewUnstartedServer(handler)
		root, certificate := testutil.TLSCertificate(t, []string{"proxy.example.test"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
		roots := x509.NewCertPool()
		roots.AppendCertsFromPEM(root)
		server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
		server.EnableHTTP2 = h2
		server.StartTLS()
		t.Cleanup(server.Close)
		transport.TLSClientConfig = &tls.Config{ServerName: "proxy.example.test", RootCAs: roots}
		address = server.URL
	} else {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		target, err := url.Parse(backend)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		var workers sync.WaitGroup
		workers.Go(func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				workers.Go(func() {
					defer conn.Close()
					if err := httpstream.Serve(ctx, uploadDeadlineConn{conn}, target, func(ctx context.Context) (net.Conn, error) {
						return (&net.Dialer{}).DialContext(ctx, "tcp", target.Host)
					}, nil); err != nil {
						t.Error(err)
					}
				})
			}
		})
		t.Cleanup(func() { cancel(); _ = listener.Close(); workers.Wait() })
		address = "http://" + listener.Addr().String()
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 3 * time.Second}, address
}

func boundaryAwait[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(2 * time.Second):
		t.Fatal("streaming boundary did not make progress")
		var zero T
		return zero
	}
}

func TestStreamingUploadEarlyResponseAndTrailers(t *testing.T) {
	for _, protocol := range []struct {
		kind string
		h2   bool
	}{{"httpstream", false}, {"localproxy", false}, {"localproxy", true}} {
		t.Run(fmt.Sprintf("%s/http2=%t", protocol.kind, protocol.h2), func(t *testing.T) {
			var calls atomic.Int32
			seen := make(chan http.Header, 1)
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Header.Get("Authorization") != "Bearer application" || r.Header.Get("X-Api-Key") != "application-key" {
					t.Error("application credentials changed")
				}
				if err := http.NewResponseController(w).EnableFullDuplex(); err != nil {
					t.Error(err)
					return
				}
				prefix := make([]byte, 5)
				if _, err := io.ReadFull(r.Body, prefix); err != nil || string(prefix) != "first" {
					t.Error("upload prefix changed", string(prefix), err)
					return
				}
				w.Header().Set("Content-Type", "text/event-stream")
				w.Header().Set("Trailer", "X-Response-Digest")
				_, _ = io.WriteString(w, "data: early\n\n")
				_ = http.NewResponseController(w).Flush()
				rest, err := io.ReadAll(r.Body)
				if err != nil || string(rest) != "last" {
					t.Error("upload remainder changed", string(rest), err)
					return
				}
				seen <- r.Trailer.Clone()
				_, _ = io.WriteString(w, "data: done\n\n")
				w.Header().Set("X-Response-Digest", "complete")
			}))
			t.Cleanup(target.Close)
			client, address := streamingProxy(t, protocol.kind, protocol.h2, target.URL)
			reader, writer := io.Pipe()
			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(func() { cancel(); _ = writer.Close() })
			request, err := http.NewRequestWithContext(ctx, "POST", address+"/mounted/upload", reader)
			if err != nil {
				t.Fatal(err)
			}
			request.Host = "proxy.example.test"
			request.Header.Set("Authorization", "Bearer application")
			request.Header.Set("X-Api-Key", "application-key")
			request.Trailer = http.Header{"X-Upload-Digest": nil}
			type result struct {
				response *http.Response
				err      error
			}
			responses := make(chan result, 1)
			go func() { response, err := client.Do(request); responses <- result{response, err} }()
			if _, err := io.WriteString(writer, "first"); err != nil {
				t.Fatal(err)
			}
			got := boundaryAwait(t, responses)
			if got.err != nil {
				t.Fatal("response before upload EOF", got.err)
			}
			defer got.response.Body.Close()
			wantProtocol := 1
			if protocol.h2 {
				wantProtocol = 2
			}
			if got.response.StatusCode != 200 || got.response.ProtoMajor != wantProtocol {
				t.Fatal("wrong response precondition", got.response.Status, got.response.Proto)
			}
			responseReader := bufio.NewReader(got.response.Body)
			line, err := responseReader.ReadString('\n')
			if err != nil || line != "data: early\n" {
				t.Fatal("early response did not flush", line, err)
			}
			request.Trailer["X-Upload-Digest"] = []string{"one", "two"}
			if _, err := io.WriteString(writer, "last"); err != nil {
				t.Fatal(err)
			}
			_ = writer.Close()
			trailer := boundaryAwait(t, seen)
			if strings.Join(trailer.Values("X-Upload-Digest"), ",") != "one,two" {
				t.Fatal("streamed request trailer lost", trailer)
			}
			rest, err := io.ReadAll(responseReader)
			if err != nil || string(rest) != "\ndata: done\n\n" || calls.Load() != 1 || got.response.Trailer.Get("X-Response-Digest") != "complete" {
				t.Fatal("stream completion or replay", string(rest), calls.Load(), err)
			}
		})
	}
}

func TestHTTPStreamIncompleteUploadDeadline(t *testing.T) {
	for _, trickle := range []bool{false, true} {
		t.Run(fmt.Sprintf("trickle=%t", trickle), func(t *testing.T) {
			started, ended := make(chan struct{}), make(chan error, 1)
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(started)
				_, err := io.Copy(io.Discard, r.Body)
				ended <- err
				w.WriteHeader(204)
			}))
			t.Cleanup(target.Close)
			client, address := streamingProxy(t, "httpstream", false, target.URL)
			reader, writer := io.Pipe()
			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(func() { cancel(); _ = writer.Close() })
			request, _ := http.NewRequestWithContext(ctx, "POST", address, reader)
			type result struct {
				status int
				err    error
			}
			done := make(chan result, 1)
			joined := make(chan struct{})
			go func() {
				defer close(joined)
				response, err := client.Do(request)
				status := 0
				if err == nil {
					defer response.Body.Close()
					status = response.StatusCode
				}
				done <- result{status, err}
			}()
			t.Cleanup(func() { cancel(); _ = writer.Close(); boundaryAwait(t, joined) })
			if _, err := writer.Write([]byte("a")); err != nil {
				t.Fatal(err)
			}
			boundaryAwait(t, started)
			if trickle {
				joined := make(chan struct{})
				go func() {
					defer close(joined)
					ticker := time.NewTicker(20 * time.Millisecond)
					defer ticker.Stop()
					for {
						select {
						case <-ctx.Done():
							return
						case <-ticker.C:
							if _, err := writer.Write([]byte("b")); err != nil {
								return
							}
						}
					}
				}()
				t.Cleanup(func() { cancel(); _ = writer.Close(); boundaryAwait(t, joined) })
			}
			got := boundaryAwait(t, done)
			if got.err == nil && got.status < 400 {
				t.Fatalf("incomplete upload succeeded: %+v", got)
			}
			if err := boundaryAwait(t, ended); err == nil {
				t.Fatal("incomplete target upload was not interrupted")
			}
		})
	}
}

func TestHTTPStreamCompletedUploadAllowsLongSSE(t *testing.T) {
	for _, chunked := range []bool{false, true} {
		t.Run(fmt.Sprintf("chunked=%t", chunked), func(t *testing.T) {
			testHTTPStreamCompletedUploadAllowsLongSSE(t, chunked)
		})
	}
}

func testHTTPStreamCompletedUploadAllowsLongSSE(t *testing.T, chunked bool) {
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if (r.ContentLength == -1) != chunked {
			t.Error("wrong upload framing", r.ContentLength, r.TransferEncoding)
		}
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: first\n\n")
		_ = http.NewResponseController(w).Flush()
		<-release
		_, _ = io.WriteString(w, "data: last\n\n")
	}))
	t.Cleanup(target.Close)
	client, address := streamingProxy(t, "httpstream", false, target.URL)
	t.Cleanup(unblock)
	var body io.Reader = strings.NewReader("complete")
	if chunked {
		body = io.NopCloser(body)
	}
	response, err := client.Post(address, "text/plain", body)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	first := make([]byte, len("data: first\n\n"))
	_, err = io.ReadFull(response.Body, first)
	if err != nil || response.StatusCode != 200 || string(first) != "data: first\n\n" {
		t.Fatal("SSE precondition", response.Status, string(first), err)
	}
	time.Sleep(2 * uploadTestTimeout)
	unblock()
	last, err := io.ReadAll(response.Body)
	if err != nil || string(last) != "data: last\n\n" {
		t.Fatal("completed upload retained its deadline", string(last), err)
	}
}

func TestStreamingEarlyResponseCancellationStopsUpload(t *testing.T) {
	for _, protocol := range []struct {
		kind string
		h2   bool
	}{{"httpstream", false}, {"localproxy", false}, {"localproxy", true}} {
		t.Run(fmt.Sprintf("%s/http2=%t", protocol.kind, protocol.h2), func(t *testing.T) {
			ended := make(chan error, 1)
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = http.NewResponseController(w).EnableFullDuplex()
				first := make([]byte, 1)
				if _, err := io.ReadFull(r.Body, first); err != nil {
					ended <- err
					return
				}
				_, _ = io.WriteString(w, "early\n")
				_ = http.NewResponseController(w).Flush()
				_, err := io.Copy(io.Discard, r.Body)
				ended <- err
			}))
			t.Cleanup(target.Close)
			client, address := streamingProxy(t, protocol.kind, protocol.h2, target.URL)
			reader, writer := io.Pipe()
			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(func() { cancel(); _ = writer.Close() })
			request, _ := http.NewRequestWithContext(ctx, "POST", address, reader)
			request.Host = "proxy.example.test"
			type result struct {
				response *http.Response
				err      error
			}
			done := make(chan result, 1)
			go func() { response, err := client.Do(request); done <- result{response, err} }()
			if _, err := writer.Write([]byte("a")); err != nil {
				t.Fatal(err)
			}
			got := boundaryAwait(t, done)
			if got.err != nil {
				t.Fatal(got.err)
			}
			defer got.response.Body.Close()
			first, err := bufio.NewReader(got.response.Body).ReadString('\n')
			if err != nil || got.response.StatusCode != 200 || first != "early\n" {
				t.Fatal("cancellation precondition", first, err)
			}
			cancel()
			_ = writer.CloseWithError(context.Canceled)
			if err := boundaryAwait(t, ended); err == nil {
				t.Fatal("cancellation allowed a complete target upload")
			}
		})
	}
}
