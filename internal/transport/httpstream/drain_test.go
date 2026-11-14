package httpstream_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
	"github.com/tnldotdev/tnl/internal/transport/httpstream"
)

func TestHTTPStreamDrainRejectsMismatchedFacts(t *testing.T) {
	for _, mode := range []string{"handler", "proxy"} {
		for _, fact := range []string{"signal_only", "deadline_only"} {
			t.Run(mode+"/"+fact, func(t *testing.T) {
				raw, visitor := net.Pipe()
				defer raw.Close()
				defer visitor.Close()
				// invalid input must be rejected at entry, not as successful
				// serving canceled by the caller.
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				var deadlines, handlers, targets atomic.Int32
				drain := httpstream.Drain{}
				if fact == "signal_only" {
					drain.Started = make(chan struct{})
				} else {
					drain.Deadline = func() time.Time {
						deadlines.Add(1)
						return time.Now().Add(time.Minute)
					}
				}
				handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { handlers.Add(1) })
				var err error
				if mode == "handler" {
					err = httpstream.ServeHandler(ctx, raw, handler, drain)
				} else {
					err = httpstream.Serve(ctx, raw, &url.URL{Scheme: "http", Host: "target.test"}, func(context.Context) (net.Conn, error) {
						targets.Add(1)
						return nil, httpstream.ErrClosed
					}, func(http.Handler) http.Handler { return handler }, httpstream.ResponseHooks{}, drain)
				}
				if !errors.Is(err, httpstream.ErrClosed) || deadlines.Load() != 0 || handlers.Load() != 0 || targets.Load() != 0 {
					t.Fatal("mismatched drain facts were accepted or used", err, deadlines.Load(), handlers.Load(), targets.Load())
				}
			})
		}
	}
}

func TestHTTPStreamDrainPublishedDeadlineFailsClosed(t *testing.T) {
	for _, mode := range []string{"handler", "proxy"} {
		for _, deadline := range []string{"zero", "expired"} {
			t.Run(mode+"/"+deadline, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					raw, visitor := net.Pipe()
					defer raw.Close()
					defer visitor.Close()
					started, entered, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
					var deadlines atomic.Int32
					until := time.Time{}
					if deadline == "expired" {
						until = time.Now().Add(-time.Second)
					}
					drain := httpstream.Drain{Started: started, Deadline: func() time.Time {
						deadlines.Add(1)
						return until
					}}
					handler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
						defer close(finished)
						close(entered)
						<-r.Context().Done()
					})
					served := make(chan error, 1)
					go func() {
						if mode == "handler" {
							served <- httpstream.ServeHandler(t.Context(), raw, handler, drain)
						} else {
							served <- httpstream.Serve(t.Context(), raw, &url.URL{Scheme: "http", Host: "target.test"}, func(context.Context) (net.Conn, error) {
								t.Error("inline drain fixture opened a target")
								return nil, httpstream.ErrClosed
							}, func(http.Handler) http.Handler { return handler }, httpstream.ResponseHooks{}, drain)
						}
					}()
					transport := &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) { return visitor, nil }}
					defer transport.CloseIdleConnections()
					replied := make(chan struct{})
					go func() {
						defer close(replied)
						request, err := http.NewRequestWithContext(t.Context(), "GET", "http://service.example.test/", nil)
						if err != nil {
							t.Error(err)
							return
						}
						response, err := transport.RoundTrip(request)
						if err == nil {
							response.Body.Close()
						}
					}()
					<-entered
					synctest.Wait()
					if deadlines.Load() != 0 {
						t.Fatal("deadline was evaluated before the run published drain")
					}
					select {
					case err := <-served:
						t.Fatal("deadline was applied before actual drain", err)
					default:
					}
					before := time.Now()
					close(started)
					if err := <-served; !errors.Is(err, context.DeadlineExceeded) {
						t.Fatal("invalid published deadline did not fail closed", err)
					}
					if deadlines.Load() != 1 || !time.Now().Equal(before) {
						t.Fatal("drain did not use the single published deadline immediately", deadlines.Load(), time.Since(before))
					}
					select {
					case <-finished:
					default:
						t.Fatal("fail-closed drain did not join its handler")
					}
					<-replied
				})
			})
		}
	}
}

type finalWriteConn struct {
	net.Conn
	armed   atomic.Bool
	blocked chan struct{}
	release <-chan struct{}
	once    sync.Once
}

func (c *finalWriteConn) Write(p []byte) (int, error) {
	if c.armed.Load() {
		c.once.Do(func() { close(c.blocked) })
		<-c.release
	}
	return c.Conn.Write(p)
}

func TestHTTPStreamDrainJoinsFinalFraming(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "http1", true: "http2"}[h2], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				raw, visitor := net.Pipe()
				defer raw.Close()
				defer visitor.Close()
				unblock := make(chan struct{})
				release := sync.OnceFunc(func() { close(unblock) })
				defer release()
				wire := &finalWriteConn{Conn: raw, blocked: make(chan struct{}), release: unblock}
				certificate := visitorfixture.Certificate(t, "service.example.test")
				secured := tls.Server(wire, &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: []string{"h2", "http/1.1"}})
				started, returned := make(chan struct{}), make(chan struct{})
				until := time.Now().Add(time.Minute)
				served := make(chan error, 1)
				go func() {
					served <- httpstream.ServeHandler(t.Context(), secured, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.Header().Set("Trailer", "X-Final")
						_, _ = io.WriteString(w, "first")
						if err := http.NewResponseController(w).Flush(); err != nil {
							t.Error(err)
						}
						_, _ = io.WriteString(w, "-last")
						w.Header().Set("X-Final", "complete")
						wire.armed.Store(true)
						close(started)
						close(returned)
					}), httpstream.Drain{Started: started, Deadline: func() time.Time { return until }})
				}()
				transport := &http.Transport{ForceAttemptHTTP2: h2,
					TLSClientConfig: &tls.Config{RootCAs: visitorfixture.Roots(t, certificate)},
					DialContext:     func(context.Context, string, string) (net.Conn, error) { return visitor, nil }}
				defer transport.CloseIdleConnections()
				replied := make(chan struct{})
				go func() {
					defer close(replied)
					response, err := transport.RoundTrip(mustDrainRequest(t))
					if err != nil {
						t.Error(err)
						return
					}
					defer response.Body.Close()
					body, err := io.ReadAll(response.Body)
					wantProtocol := 1
					if h2 {
						wantProtocol = 2
					}
					if err != nil || string(body) != "first-last" || response.Trailer.Get("X-Final") != "complete" || response.ProtoMajor != wantProtocol {
						t.Error("final response lost protocol framing, body, or trailers", string(body), response.Trailer, response.Proto, err)
					}
				}()
				<-returned
				<-wire.blocked
				synctest.Wait()
				select {
				case err := <-served:
					t.Fatal("returned at handler completion before final framing flushed", err)
				default:
				}
				release()
				<-replied
				if err := <-served; err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}

func mustDrainRequest(t *testing.T) *http.Request {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), "GET", "https://service.example.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func TestHTTPStreamDrainDeadlineAndCancellationJoinHandlers(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		for _, revoke := range []bool{false, true} {
			name := map[bool]string{false: "http1", true: "http2"}[h2] + "/" + map[bool]string{false: "deadline", true: "revocation"}[revoke]
			t.Run(name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					raw, visitor := net.Pipe()
					defer raw.Close()
					defer visitor.Close()
					certificate := visitorfixture.Certificate(t, "service.example.test")
					secured := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: []string{"h2", "http/1.1"}})
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					entered, canceled := make(chan struct{}), make(chan struct{})
					finish := make(chan struct{})
					release := sync.OnceFunc(func() { close(finish) })
					defer release()
					started := make(chan struct{})
					until := time.Now().Add(time.Second)
					served := make(chan error, 1)
					go func() {
						served <- httpstream.ServeHandler(ctx, secured, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
							close(entered)
							<-r.Context().Done()
							close(canceled)
							<-finish
						}), httpstream.Drain{Started: started, Deadline: func() time.Time { return until }})
					}()
					transport := &http.Transport{ForceAttemptHTTP2: h2,
						TLSClientConfig: &tls.Config{RootCAs: visitorfixture.Roots(t, certificate)},
						DialContext:     func(context.Context, string, string) (net.Conn, error) { return visitor, nil }}
					defer transport.CloseIdleConnections()
					replied := make(chan struct{})
					go func() {
						defer close(replied)
						response, err := transport.RoundTrip(mustDrainRequest(t))
						if err == nil {
							response.Body.Close()
						}
					}()
					<-entered
					close(started)
					synctest.Wait()
					if revoke {
						cancel()
					} else {
						time.Sleep(time.Second)
					}
					<-canceled
					synctest.Wait()
					select {
					case err := <-served:
						t.Fatal("shutdown returned before canceled handler joined", err)
					default:
					}
					release()
					err := <-served
					if !revoke && !errors.Is(err, context.DeadlineExceeded) {
						t.Fatal("bounded drain did not report its deadline", err)
					}
					<-replied
				})
			})
		}
	}
}

func TestHTTPStreamGracefulDrainKeepsHijackUntilDeadlineAndJoins(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		raw, visitor := net.Pipe()
		defer raw.Close()
		defer visitor.Close()
		started, canceled := make(chan struct{}), make(chan struct{})
		finish := make(chan struct{})
		release := sync.OnceFunc(func() { close(finish) })
		defer release()
		until := time.Now().Add(time.Second)
		served := make(chan error, 1)
		go func() {
			served <- httpstream.ServeHandler(t.Context(), raw, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				connection, buffered, err := http.NewResponseController(w).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				defer connection.Close()
				_, _ = buffered.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: test\r\n\r\n")
				if err := buffered.Flush(); err != nil {
					t.Error(err)
					return
				}
				<-r.Context().Done()
				close(canceled)
				<-finish
			}), httpstream.Drain{Started: started, Deadline: func() time.Time { return until }})
		}()
		go func() {
			_, _ = io.WriteString(visitor, "GET / HTTP/1.1\r\nHost: service.example.test\r\nConnection: Upgrade\r\nUpgrade: test\r\n\r\n")
		}()
		response, err := http.ReadResponse(bufio.NewReader(visitor), &http.Request{Method: "GET"})
		if err != nil || response.StatusCode != http.StatusSwitchingProtocols {
			t.Fatal("upgrade failed", err)
		}
		close(started)
		synctest.Wait()
		select {
		case <-canceled:
			t.Fatal("graceful drain immediately revoked a hijacked connection")
		default:
		}
		time.Sleep(time.Second)
		<-canceled
		synctest.Wait()
		select {
		case err := <-served:
			t.Fatal("drain forgot a hijacked handler before its joined cleanup", err)
		default:
		}
		release()
		if err := <-served; !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("hijack did not retain the bounded drain failure", err)
		}
	})
}
