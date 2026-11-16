package httpstream_test

import (
	"context"
	"crypto/tls"
	"errors"
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
	"testing/synctest"
	"time"

	publisherproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"
	"github.com/tnldotdev/tnl/internal/publisher/requestlimit"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
	"github.com/tnldotdev/tnl/internal/transport/httpstream"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// exercise the shared body owner with real HTTP/1 and HTTP/2 parsers, forwarding,
// and a single application slot. only the upload budget is shortened; the
// in-memory HTTP network keeps the original workloads deterministic under synctest.
func deadlineFrontend(t *testing.T, timeout time.Duration, handler http.Handler) (*httptest.Server, <-chan struct{}) {
	t.Helper()
	target := httptest.NewTestServer(t, handler)
	targetDial := target.Client().Transport.(*http.Transport).DialContext
	forwarder, err := publisherproxy.New(publisherproxy.Config{
		Target: "http://target.example.test", Hostname: "service.example.test", MaxConnsPerHost: 1,
		Transport: func(*url.URL, publisherproxy.TargetOptions, bool) (publisherproxy.Transport, error) {
			return httpstream.NewTargetTransport(t.Context(), func(ctx context.Context) (net.Conn, error) {
				return targetDial(ctx, "tcp", "target.example.test:80")
			}, 1)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := forwarder.Close(); err != nil {
			t.Error(err)
		}
	})
	limit := 1
	budget, err := requestlimit.NewHTTP(&controlv1.ProjectHTTPApplicationLimits{Concurrency: &limit})
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan struct{}, 8)
	server := httptest.NewTestServer(t, httpstream.Requests(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		release, ok := budget.Admit(w, r)
		if !ok {
			return
		}
		defer func() {
			release()
			finished <- struct{}{}
		}()
		forwarder.ServeAdmittedHTTP(w, r)
	}), timeout))
	server.EnableHTTP2 = true
	return server, finished
}

func deadlineClient(t *testing.T, server *httptest.Server, h2 bool) *http.Client {
	t.Helper()
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.ForceAttemptHTTP2 = h2
	transport.TLSClientConfig.NextProtos = nil
	dialTLS := transport.DialTLSContext
	var dialed atomic.Bool
	transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if dialed.Swap(true) {
			return nil, errors.New("deadline client attempted a second visitor connection")
		}
		conn, err := dialTLS(ctx, network, address)
		if err != nil {
			return nil, err
		}
		// httptest supplies an unhandshaken TLS wrapper. use this client's ALPN
		// settings rather than borrowing the original fixture client's settings.
		return tls.Client(conn.(*tls.Conn).NetConn(), transport.TLSClientConfig), nil
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}
}

type deadlineResponse struct {
	status, protocol int
	header           http.Header
	err              error
}

func deadlineDo(client *http.Client, request *http.Request) deadlineResponse {
	response, err := client.Do(request)
	if err != nil {
		return deadlineResponse{err: err}
	}
	defer response.Body.Close()
	_, err = io.Copy(io.Discard, response.Body)
	return deadlineResponse{status: response.StatusCode, protocol: response.ProtoMajor, header: response.Header, err: err}
}

func assertDeadlineAvailable(t *testing.T, client *http.Client, h2 bool) {
	t.Helper()
	request, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://service.example.test/", nil)
	response := deadlineDo(client, request)
	wantProtocol := 1
	if h2 {
		wantProtocol = 2
	}
	if response.err != nil || response.status != http.StatusNoContent || response.protocol != wantProtocol {
		t.Fatal("completed upload did not release its application slot", response)
	}
}

func TestRequestBodyDeadlineInterruptsHTTP1AndHTTP2Uploads(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		for _, trickle := range []bool{false, true} {
			t.Run(fmt.Sprintf("http2=%t/trickle=%t", h2, trickle), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					started, ended := make(chan struct{}), make(chan error, 1)
					frontend, finished := deadlineFrontend(t, 500*time.Millisecond, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if r.Method == http.MethodPost {
							if r.ContentLength != -1 || len(r.TransferEncoding) != 1 || r.TransferEncoding[0] != "chunked" {
								t.Error("unknown-length upload did not remain streamed to the HTTP/1 target", r.ContentLength, r.TransferEncoding)
							}
							close(started)
							_, err := io.Copy(io.Discard, r.Body)
							ended <- err
						}
						w.WriteHeader(http.StatusNoContent)
					}))
					client := deadlineClient(t, frontend, h2)
					reader, writer := io.Pipe()
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					defer writer.Close()
					request, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://service.example.test/hold", reader)
					done, joined := make(chan deadlineResponse, 1), make(chan struct{})
					go func() { defer close(joined); done <- deadlineDo(client, request) }()
					defer func() { cancel(); _ = writer.Close(); <-joined }()
					if _, err := io.WriteString(writer, "a"); err != nil {
						t.Fatal(err)
					}
					boundaryAwait(t, started)
					if trickle {
						trickled := make(chan struct{})
						go func() {
							defer close(trickled)
							ticker := time.NewTicker(25 * time.Millisecond)
							defer ticker.Stop()
							for {
								select {
								case <-ctx.Done():
									return
								case <-ticker.C:
									if _, err := io.WriteString(writer, "a"); err != nil {
										return
									}
								}
							}
						}()
						defer func() { cancel(); _ = writer.Close(); <-trickled }()
					}
					got := boundaryAwait(t, done)
					if got.err == nil && got.status < http.StatusBadRequest {
						t.Fatal("incomplete body succeeded", got)
					}
					if err := boundaryAwait(t, ended); err == nil {
						t.Fatal("upload deadline did not interrupt target work")
					}
					boundaryAwait(t, finished)
					if !h2 {
						client = deadlineClient(t, frontend, false)
					}
					// HTTP/2 must reuse the original visitor connection after one
					// timed-out stream; HTTP/1 uses a new connection after closing.
					assertDeadlineAvailable(t, client, h2)
				})
			})
		}
	}
}

func TestCompletedRequestBodiesAllowLongHTTP1AndHTTP2Responses(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		for _, unknown := range []bool{false, true} {
			t.Run(fmt.Sprintf("http2=%t/unknown_length=%t", h2, unknown), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					release := make(chan struct{})
					unblock := sync.OnceFunc(func() { close(release) })
					defer unblock()
					frontend, finished := deadlineFrontend(t, 100*time.Millisecond, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if r.Method != http.MethodPost {
							w.WriteHeader(http.StatusNoContent)
							return
						}
						if (r.ContentLength == -1) != unknown {
							t.Error("completed body framing changed", r.ContentLength, r.TransferEncoding)
						}
						if body, err := io.ReadAll(r.Body); err != nil || string(body) != "complete body" {
							t.Error("completed upload failed", string(body), err)
							return
						}
						_, _ = io.WriteString(w, "first\n")
						_ = http.NewResponseController(w).Flush()
						<-release
						_, _ = io.WriteString(w, "second\n")
					}))
					client := deadlineClient(t, frontend, h2)
					var body io.Reader = strings.NewReader("complete body")
					if unknown {
						body = io.NopCloser(body)
					}
					response, err := client.Post("https://service.example.test/", "text/plain", body)
					if err != nil {
						t.Fatal(err)
					}
					defer response.Body.Close()
					wantProtocol := 1
					if h2 {
						wantProtocol = 2
					}
					if response.StatusCode != http.StatusOK || response.ProtoMajor != wantProtocol || response.Header.Get("Tnl-Error-Code") != "" {
						t.Fatal("long-response precondition", response.Status, response.Proto, response.Header)
					}
					first := make([]byte, len("first\n"))
					if _, err := io.ReadFull(response.Body, first); err != nil || string(first) != "first\n" {
						t.Fatal("initial response did not stream", string(first), err)
					}
					other := deadlineClient(t, frontend, true)
					excess, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://service.example.test/", nil)
					rejected := deadlineDo(other, excess)
					if rejected.err != nil || rejected.status != http.StatusServiceUnavailable || rejected.protocol != 2 ||
						rejected.header.Get("Tnl-Error-Code") != "TNL_REQUEST_LIMIT_REACHED" || rejected.header.Get("Retry-After") != "1" {
						t.Fatal("active response released its application slot early", rejected)
					}
					time.Sleep(200 * time.Millisecond)
					unblock()
					rest, err := io.ReadAll(response.Body)
					if err != nil || string(rest) != "second\n" {
						t.Fatal("upload deadline became a total response timeout", string(rest), err)
					}
					boundaryAwait(t, finished)
					assertDeadlineAvailable(t, client, h2)
				})
			})
		}
	}
}

func TestHTTPStreamResponseOutlivesProductionUploadBudget(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("http2=%t", h2), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				release := make(chan struct{})
				unblock := sync.OnceFunc(func() { close(release) })
				defer unblock()
				target := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if body, err := io.ReadAll(r.Body); err != nil || string(body) != "complete body" {
						t.Error("completed upload failed", string(body), err)
						return
					}
					_, _ = io.WriteString(w, "first\n")
					_ = http.NewResponseController(w).Flush()
					<-release
					_, _ = io.WriteString(w, "second\n")
				}))
				targetDial := target.Client().Transport.(*http.Transport).DialContext
				certificate := visitorfixture.Certificate(t, "service.example.test")
				incoming, visitor := net.Pipe()
				secured := tls.Server(incoming, &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: []string{"h2", "http/1.1"}})
				ctx, cancel := context.WithCancel(t.Context())
				done := make(chan error, 1)
				go func() {
					done <- httpstream.Serve(ctx, secured, &url.URL{Scheme: "http", Host: "target.example.test"},
						func(ctx context.Context) (net.Conn, error) { return targetDial(ctx, "tcp", "target.example.test:80") },
						nil, httpstream.ResponseHooks{}, httpstream.Drain{})
				}()
				defer func() {
					cancel()
					_ = visitor.Close()
					_ = incoming.Close()
					if err := <-done; err != nil {
						t.Error("HTTP stream did not join", err)
					}
				}()
				transport := &http.Transport{
					ForceAttemptHTTP2: h2,
					TLSClientConfig:   &tls.Config{RootCAs: visitorfixture.Roots(t, certificate)},
					DialContext:       func(context.Context, string, string) (net.Conn, error) { return visitor, nil },
				}
				defer transport.CloseIdleConnections()
				client := &http.Client{Transport: transport}
				response, err := client.Post("https://service.example.test/", "text/plain", strings.NewReader("complete body"))
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				wantProtocol := 1
				if h2 {
					wantProtocol = 2
				}
				first := make([]byte, len("first\n"))
				if _, err := io.ReadFull(response.Body, first); err != nil || string(first) != "first\n" || response.StatusCode != http.StatusOK || response.ProtoMajor != wantProtocol {
					t.Fatal("production HTTP stream response precondition", string(first), response.Proto, err)
				}
				// this uses the unmodified production server and body timeout.
				// an active response is not a new upload or an idle connection.
				time.Sleep(2 * httpstream.RequestBodyTimeout)
				unblock()
				if rest, err := io.ReadAll(response.Body); err != nil || string(rest) != "second\n" {
					t.Fatal("production upload budget limited the response lifetime", string(rest), err)
				}
			})
		})
	}
}
