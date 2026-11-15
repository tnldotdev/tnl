package httpstream_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
	"github.com/tnldotdev/tnl/internal/transport/httpstream"
)

func selectedRequest(t *testing.T, ctx context.Context, address string) *http.Request {
	t.Helper()
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestSelectedTransportRequiresOwnerAndConnect(t *testing.T) {
	connect := func(context.Context) (net.Conn, error) { return nil, httpstream.ErrClosed }
	for _, input := range []struct {
		ctx     context.Context
		connect func(context.Context) (net.Conn, error)
	}{{nil, connect}, {t.Context(), nil}} {
		transport, err := httpstream.NewSelectedTransport(input.ctx, input.connect)
		if transport != nil || !errors.Is(err, httpstream.ErrClosed) {
			t.Fatal("transport accepted missing lifetime facts", transport, err)
		}
	}
	for _, capacity := range []int{0, -1} {
		if transport, err := httpstream.NewTargetTransport(t.Context(), connect, capacity); transport != nil || !errors.Is(err, httpstream.ErrClosed) {
			t.Fatal("transport accepted unbounded or invalid capacity", capacity, transport, err)
		}
	}
}

func TestSelectedTransportConnectsLazilyAndReusesSelectedConnection(t *testing.T) {
	for _, scheme := range []string{"http", "https"} {
		t.Run(scheme, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				upstream, backend := net.Pipe()
				defer upstream.Close()
				defer backend.Close()
				var verification *tls.Config
				if scheme == "https" {
					certificate := visitorfixture.Certificate(t, "target.example.test")
					backend = tls.Server(backend, &tls.Config{Certificates: []tls.Certificate{certificate}})
					verification = &tls.Config{RootCAs: visitorfixture.Roots(t, certificate), ServerName: "target.example.test"}
				}
				backendDone := make(chan struct{})
				go func() {
					defer close(backendDone)
					reader := bufio.NewReader(backend)
					for range 2 {
						request, err := http.ReadRequest(reader)
						if err != nil {
							t.Error("selected target did not receive request", err)
							return
						}
						_ = request.Body.Close()
						if request.Host != "target.example.test" || request.Header.Get("Accept-Encoding") != "" {
							t.Error("transport changed request authority or enabled compression")
						}
						if _, err := io.WriteString(backend, "HTTP/1.1 204 No Content\r\n\r\n"); err != nil {
							t.Error(err)
							return
						}
					}
				}()
				type requestValue struct{}
				var calls atomic.Int32
				transport, err := httpstream.NewSelectedTransport(t.Context(), func(ctx context.Context) (net.Conn, error) {
					calls.Add(1)
					if ctx.Value(requestValue{}) != "kept" {
						t.Error("dial lost request context values")
					}
					if verification != nil {
						secured := tls.Client(upstream, verification)
						if err := secured.HandshakeContext(ctx); err != nil {
							return nil, err
						}
						return secured, nil
					}
					return upstream, nil
				})
				if err != nil {
					t.Fatal(err)
				}
				defer transport.Close()
				synctest.Wait()
				if calls.Load() != 0 {
					t.Fatal("constructor eagerly connected to target")
				}
				ctx := context.WithValue(t.Context(), requestValue{}, "kept")
				for range 2 {
					response, err := transport.RoundTrip(selectedRequest(t, ctx, scheme+"://target.example.test/"))
					if err != nil {
						t.Fatal(err)
					}
					_ = response.Body.Close()
					if response.StatusCode != http.StatusNoContent || (response.TLS != nil) != (scheme == "https") {
						t.Fatal("selected transport changed response or target TLS facts", response.StatusCode, response.TLS)
					}
				}
				<-backendDone
				if calls.Load() != 1 {
					t.Fatal("keepalive replaced the selected connection", calls.Load())
				}
			})
		})
	}
}

func TestSelectedTransportFailedAttemptIsFinal(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		failed := errors.New("selected target setup failed")
		calls := 0
		transport, err := httpstream.NewSelectedTransport(t.Context(), func(context.Context) (net.Conn, error) {
			calls++
			return nil, failed
		})
		if err != nil {
			t.Fatal(err)
		}
		defer transport.Close()
		for i := range 2 {
			response, err := transport.RoundTrip(selectedRequest(t, t.Context(), "http://target.example.test/"))
			want := failed
			if i == 1 {
				want = httpstream.ErrClosed
			}
			if response != nil || !errors.Is(err, want) {
				t.Fatal("failed target attempt was replaced", response, err)
			}
			transport.CloseIdleConnections()
		}
		if calls != 1 {
			t.Fatal("failed target setup was retried", calls)
		}
	})
}

func TestSelectedTransportNeverRedialsOrReplaysAfterReuse(t *testing.T) {
	for _, failure := range []string{"reused_connection", "idle_retirement"} {
		t.Run(failure, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				upstream, backend := net.Pipe()
				defer upstream.Close()
				defer backend.Close()
				backendDone := make(chan struct{})
				var requests atomic.Int32
				go func() {
					defer close(backendDone)
					defer backend.Close()
					reader := bufio.NewReader(backend)
					request, err := http.ReadRequest(reader)
					if err != nil {
						t.Error(err)
						return
					}
					requests.Add(1)
					_ = request.Body.Close()
					if _, err := io.WriteString(backend, "HTTP/1.1 204 No Content\r\n\r\n"); err != nil {
						t.Error(err)
						return
					}
					// a warm GET would be eligible for Transport retry. the
					// selected ClientConn must fail it without another connection.
					request, err = http.ReadRequest(reader)
					if failure == "idle_retirement" {
						if !errors.Is(err, io.EOF) {
							t.Error("idle target did not close", err)
						}
						return
					}
					if err != nil {
						t.Error(err)
						return
					}
					requests.Add(1)
					_ = request.Body.Close()
				}()
				var calls atomic.Int32
				transport, err := httpstream.NewSelectedTransport(t.Context(), func(context.Context) (net.Conn, error) {
					calls.Add(1)
					return upstream, nil
				})
				if err != nil {
					t.Fatal(err)
				}
				defer transport.Close()
				response, err := transport.RoundTrip(selectedRequest(t, t.Context(), "http://target.example.test/"))
				if err != nil {
					t.Fatal(err)
				}
				_ = response.Body.Close()
				if failure == "idle_retirement" {
					transport.CloseIdleConnections()
				}
				for range 2 {
					response, err := transport.RoundTrip(selectedRequest(t, t.Context(), "http://target.example.test/"))
					if response != nil || !errors.Is(err, httpstream.ErrClosed) {
						t.Fatal("retired or failed target was reused or replaced", response, err)
					}
				}
				<-backendDone
				want := int32(2)
				if failure == "idle_retirement" {
					want = 1
				}
				if calls.Load() != 1 || requests.Load() != want {
					t.Fatal("failed request redialed or replayed", calls.Load(), requests.Load())
				}
				if err := transport.Close(); err != nil {
					t.Fatal("already closed target became a cleanup failure", err)
				}
			})
		})
	}
}

type selectedRequestBody struct{ closed bool }

func (*selectedRequestBody) Read([]byte) (int, error) { return 0, io.EOF }
func (b *selectedRequestBody) Close() error           { b.closed = true; return nil }

func TestSelectedTransportShutdownFencesInitialAndLateRequests(t *testing.T) {
	for _, shutdown := range []string{"close", "owner_cancel"} {
		t.Run(shutdown, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				owner, cancel := context.WithCancel(t.Context())
				defer cancel()
				calls := 0
				transport, err := httpstream.NewSelectedTransport(owner, func(context.Context) (net.Conn, error) {
					calls++
					return nil, errors.New("late target work")
				})
				if err != nil {
					t.Fatal(err)
				}
				defer transport.Close()
				if shutdown == "close" {
					if err := transport.Close(); err != nil {
						t.Fatal(err)
					}
				} else {
					cancel()
					synctest.Wait()
				}
				for range 2 {
					body := &selectedRequestBody{}
					request := selectedRequest(t, t.Context(), "http://target.example.test/")
					request.Body = body
					response, err := transport.RoundTrip(request)
					if response != nil || !errors.Is(err, httpstream.ErrClosed) || !body.closed {
						t.Fatal("closed transport accepted a request or leaked its body", response, err, body.closed)
					}
					transport.CloseIdleConnections()
				}
				if calls != 0 {
					t.Fatal("shutdown admitted late target work", calls)
				}
			})
		})
	}
}

func TestSelectedTransportCloseFencesDialFromAlreadyEnteredRoundTrip(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entered, releaseRequest := make(chan struct{}), make(chan struct{})
		release := sync.OnceFunc(func() { close(releaseRequest) })
		defer release()
		var calls atomic.Int32
		transport, err := httpstream.NewSelectedTransport(t.Context(), func(context.Context) (net.Conn, error) {
			calls.Add(1)
			return nil, errors.New("target dial entered after Close")
		})
		if err != nil {
			t.Fatal(err)
		}
		defer transport.Close()
		ctx := httptrace.WithClientTrace(t.Context(), &httptrace.ClientTrace{GetConn: func(string) {
			close(entered)
			<-releaseRequest
		}})
		request := selectedRequest(t, ctx, "http://target.example.test/")
		replied := make(chan error, 1)
		go func() { _, err := transport.RoundTrip(request); replied <- err }()
		// the request passed RoundTrip's entry check, but its transport has
		// not entered target setup. Close must fence that later dial too.
		<-entered
		if err := transport.Close(); err != nil {
			t.Fatal(err)
		}
		release()
		if err := <-replied; !errors.Is(err, httpstream.ErrClosed) || calls.Load() != 0 {
			t.Fatal("late dial entered target work after the join", err, calls.Load())
		}
	})
}

type selectedCloseConn struct {
	net.Conn
	entered chan struct{}
	release <-chan struct{}
	err     error
	once    sync.Once
	calls   atomic.Int32
}

func (c *selectedCloseConn) Close() error {
	c.calls.Add(1)
	c.once.Do(func() {
		_ = c.Conn.Close()
		close(c.entered)
	})
	if c.release != nil {
		<-c.release
	}
	return c.err
}

func TestSelectedTransportCloseJoinsDetachedDialAndLateConnectionClose(t *testing.T) {
	for _, outcome := range []string{"connection", "connection_and_error", "error"} {
		t.Run(outcome, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				raw, backend := net.Pipe()
				defer raw.Close()
				defer backend.Close()
				releaseDial, releaseClose := make(chan struct{}), make(chan struct{})
				finishDial := sync.OnceFunc(func() { close(releaseDial) })
				finishClose := sync.OnceFunc(func() { close(releaseClose) })
				defer finishDial()
				defer finishClose()
				cleanup := errors.New("late target close failed")
				conn := &selectedCloseConn{Conn: raw, entered: make(chan struct{}), release: releaseClose, err: errors.Join(net.ErrClosed, cleanup)}
				entered, canceled, dialDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
				var calls atomic.Int32
				transport, err := httpstream.NewSelectedTransport(t.Context(), func(ctx context.Context) (net.Conn, error) {
					defer close(dialDone)
					calls.Add(1)
					close(entered)
					<-ctx.Done()
					close(canceled)
					<-releaseDial
					switch outcome {
					case "connection_and_error":
						return conn, io.ErrUnexpectedEOF
					case "error":
						return nil, ctx.Err()
					default:
						return conn, nil
					}
				})
				if err != nil {
					t.Fatal(err)
				}
				// release held work before cleanup even on an intermediate failure.
				defer func() { finishDial(); finishClose(); _ = transport.Close() }()
				requestCtx, cancelRequest := context.WithCancel(t.Context())
				defer cancelRequest()
				request := selectedRequest(t, requestCtx, "http://target.example.test/")
				replied := make(chan error, 1)
				go func() { _, err := transport.RoundTrip(request); replied <- err }()
				<-entered
				cancelRequest()
				if err := <-replied; !errors.Is(err, context.Canceled) {
					t.Fatal("request cancellation did not return independently of its dial", err)
				}
				closed := make(chan error, 2)
				for range 2 {
					go func() { closed <- transport.Close() }()
				}
				<-canceled
				synctest.Wait()
				select {
				case err := <-closed:
					t.Fatal("Close returned before entered dial joined", err)
				default:
				}
				if response, err := transport.RoundTrip(selectedRequest(t, t.Context(), "http://target.example.test/late")); response != nil || !errors.Is(err, httpstream.ErrClosed) {
					t.Fatal("close race admitted another request", response, err)
				}
				finishDial()
				<-dialDone
				if outcome != "error" {
					<-conn.entered
					synctest.Wait()
					select {
					case err := <-closed:
						t.Fatal("Close returned before late socket cleanup joined", err)
					default:
					}
				}
				finishClose()
				for range 2 {
					err := <-closed
					if outcome == "error" {
						if err != nil {
							t.Fatal("canceled setup became a cleanup failure", err)
						}
					} else if !errors.Is(err, cleanup) || conn.calls.Load() != 1 {
						t.Fatal("late cleanup failure was lost or socket escaped ownership", err, conn.calls.Load())
					}
				}
				if calls.Load() != 1 {
					t.Fatal("close race replaced the selected target attempt", calls.Load())
				}
			})
		})
	}
}

func TestSelectedTransportOwnerCancellationClosesSocketAndJoinsCleanup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		raw, backend := net.Pipe()
		defer raw.Close()
		defer backend.Close()
		releaseClose := make(chan struct{})
		release := sync.OnceFunc(func() { close(releaseClose) })
		defer release()
		cleanup := errors.New("target close failed")
		conn := &selectedCloseConn{Conn: raw, entered: make(chan struct{}), release: releaseClose, err: cleanup}
		received := make(chan struct{})
		go func() {
			request, err := http.ReadRequest(bufio.NewReader(backend))
			if err != nil {
				t.Error(err)
				return
			}
			_ = request.Body.Close()
			close(received)
		}()
		owner, cancel := context.WithCancel(t.Context())
		defer cancel()
		transport, err := httpstream.NewSelectedTransport(owner, func(context.Context) (net.Conn, error) { return conn, nil })
		if err != nil {
			t.Fatal(err)
		}
		defer func() { release(); _ = transport.Close() }()
		replied := make(chan error, 1)
		request := selectedRequest(t, t.Context(), "http://target.example.test/")
		go func() { _, err := transport.RoundTrip(request); replied <- err }()
		<-received
		cancel()
		<-conn.entered
		closed := make(chan error, 1)
		go func() { closed <- transport.Close() }()
		synctest.Wait()
		select {
		case err := <-closed:
			t.Fatal("Close returned before owner cancellation cleanup joined", err)
		default:
		}
		release()
		if err := <-closed; !errors.Is(err, cleanup) {
			t.Fatal("owner cancellation lost independent socket cleanup failure", err)
		}
		if err := <-replied; err == nil {
			t.Fatal("owner cancellation left target request usable")
		}
		if err := transport.Close(); !errors.Is(err, cleanup) {
			t.Fatal("repeated close lost original cleanup result", err)
		}
	})
}

func TestHTTPStreamServeJoinsTargetDialAfterHandlerReturns(t *testing.T) {
	cleanup := errors.New("late target close failed")
	for _, test := range []struct {
		name, shutdown string
		closeErr       error
		wantCleanup    bool
	}{
		{name: "visitor_close", shutdown: "visitor_close"},
		{name: "owner_cancel", shutdown: "owner_cancel", closeErr: errors.Join(context.Canceled, cleanup), wantCleanup: true},
		{name: "already_closed", shutdown: "owner_cancel", closeErr: net.ErrClosed},
		{name: "closed_with_failure", shutdown: "owner_cancel", closeErr: errors.Join(net.ErrClosed, cleanup), wantCleanup: true},
		{name: "drain_with_failure", shutdown: "drain", closeErr: cleanup, wantCleanup: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				client, visitor := net.Pipe()
				defer client.Close()
				defer visitor.Close()
				upstream, backend := net.Pipe()
				defer upstream.Close()
				defer backend.Close()
				releaseDial := make(chan struct{})
				release := sync.OnceFunc(func() { close(releaseDial) })
				defer release()
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				var drain httpstream.Drain
				draining := make(chan struct{})
				if test.shutdown == "drain" {
					until := time.Now().Add(-time.Second)
					drain = httpstream.Drain{Started: draining, Deadline: func() time.Time { return until }}
				}
				entered, canceled, handlerDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
				conn := &selectedCloseConn{Conn: upstream, entered: make(chan struct{}), err: test.closeErr}
				served := make(chan error, 1)
				go func() {
					served <- httpstream.Serve(ctx, client, &url.URL{Scheme: "http", Host: "target.example.test"}, func(ctx context.Context) (net.Conn, error) {
						close(entered)
						<-ctx.Done()
						close(canceled)
						<-releaseDial
						return conn, nil
					}, func(next http.Handler) http.Handler {
						return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							defer close(handlerDone)
							next.ServeHTTP(w, r)
						})
					}, httpstream.ResponseHooks{}, drain)
				}()
				if _, err := io.WriteString(visitor, "GET / HTTP/1.1\r\nHost: visitor.example.test\r\n\r\n"); err != nil {
					t.Fatal(err)
				}
				<-entered
				switch test.shutdown {
				case "owner_cancel":
					cancel()
				case "drain":
					close(draining)
				default:
					_ = visitor.Close()
				}
				<-handlerDone
				<-canceled
				synctest.Wait()
				select {
				case err := <-served:
					t.Fatal("Serve returned before its detached target dial joined", err)
				default:
				}
				release()
				err := <-served
				if test.wantCleanup {
					if !errors.Is(err, cleanup) {
						t.Fatal("Serve discarded an independent target cleanup failure", err)
					}
					if errors.Is(test.closeErr, context.Canceled) && !errors.Is(err, context.Canceled) {
						t.Fatal("Serve replaced joined cancellation with its cleanup failure", err)
					}
				} else if err != nil {
					t.Fatal("joined target cleanup changed successful or idempotent completion", err)
				}
				if test.shutdown == "drain" && !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("target cleanup replaced the serving failure", err)
				}
				select {
				case <-conn.entered:
				default:
					t.Fatal("Serve left a late returned target connection open")
				}
				if conn.calls.Load() != 1 {
					t.Fatal("Serve closed a late target more than once", conn.calls.Load())
				}
			})
		})
	}
}
