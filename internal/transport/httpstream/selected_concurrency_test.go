package httpstream_test

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
	"github.com/tnldotdev/tnl/internal/transport/httpstream"
)

func selectedConcurrentTarget(t *testing.T, capacity int, handler http.Handler) (*httpstream.SelectedTransport, *atomic.Int32) {
	t.Helper()
	owner, cancel := context.WithCancel(t.Context())
	var servers sync.WaitGroup
	var calls atomic.Int32
	transport, err := httpstream.NewTargetTransport(owner, func(context.Context) (net.Conn, error) {
		calls.Add(1)
		upstream, backend := net.Pipe()
		servers.Go(func() {
			defer backend.Close()
			if err := httpstream.ServeHandler(owner, backend, handler, httpstream.Drain{}, 0); err != nil {
				t.Error("target serving failed", err)
			}
		})
		return upstream, nil
	}, capacity)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := transport.Close(); err != nil {
			t.Error(err)
		}
		cancel()
		servers.Wait()
	})
	return transport, &calls
}

func TestTargetTransportConcurrentHTTP2SSEAndShortRequest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		finishStream := make(chan struct{})
		finish := sync.OnceFunc(func() { close(finishStream) })
		defer finish()
		target, calls := selectedConcurrentTarget(t, 64, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/events" {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, "first\n")
				_ = http.NewResponseController(w).Flush()
				select {
				case <-finishStream:
				case <-r.Context().Done():
				}
				_, _ = io.WriteString(w, "last\n")
				return
			}
			_, _ = io.WriteString(w, "api")
		}))
		const hostname = "visitor.example.test"
		certificate := visitorfixture.Certificate(t, hostname)
		raw, visitor := net.Pipe()
		defer raw.Close()
		defer visitor.Close()
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		forward := &httputil.ReverseProxy{Transport: target, FlushInterval: -1, Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(&url.URL{Scheme: "http", Host: "target.example.test"})
		}}
		served := make(chan error, 1)
		go func() {
			secured := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: []string{"h2", "http/1.1"}})
			served <- httpstream.ServeHandler(ctx, secured, forward, httpstream.Drain{}, 0)
		}()
		var visitors atomic.Int32
		transport := &http.Transport{ForceAttemptHTTP2: true,
			TLSClientConfig: &tls.Config{RootCAs: visitorfixture.Roots(t, certificate)},
			DialContext: func(context.Context, string, string) (net.Conn, error) {
				if visitors.Add(1) != 1 {
					return nil, errors.New("visitor connection was replaced")
				}
				return visitor, nil
			}}
		client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
		defer func() {
			finish()
			cancel()
			_ = visitor.Close()
			transport.CloseIdleConnections()
			if err := <-served; err != nil {
				t.Error(err)
			}
		}()
		stream, err := client.Do(selectedRequest(t, t.Context(), "https://"+hostname+"/events"))
		if err != nil {
			t.Fatal(err)
		}
		defer stream.Body.Close()
		prefix := make([]byte, len("first\n"))
		if _, err := io.ReadFull(stream.Body, prefix); err != nil || string(prefix) != "first\n" || stream.ProtoMajor != 2 {
			t.Fatal("SSE did not flush on HTTP/2", string(prefix), stream.Proto, err)
		}
		for range 2 {
			response, err := client.Do(selectedRequest(t, t.Context(), "https://"+hostname+"/api"))
			if err != nil {
				t.Fatal("SSE blocked independent HTTP/2 work", err)
			}
			body, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if err != nil || string(body) != "api" || response.ProtoMajor != 2 {
				t.Fatal("short HTTP/2 response changed", string(body), response.Proto, err)
			}
		}
		if calls.Load() != 2 || visitors.Load() != 1 {
			t.Fatal("concurrency lost the visitor or healthy target keepalive", calls.Load(), visitors.Load())
		}
		finish()
		suffix, err := io.ReadAll(stream.Body)
		if err != nil || string(suffix) != "last\n" {
			t.Fatal("concurrent request interrupted SSE", string(suffix), err)
		}
	})
}

func TestTargetTransportCapacityWaitCancellationAndClose(t *testing.T) {
	for _, stop := range []string{"cancel_waiter", "close"} {
		t.Run(stop, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var releases [2]chan struct{}
				var finish [2]func()
				for i := range releases {
					releases[i] = make(chan struct{})
					finish[i] = sync.OnceFunc(func() { close(releases[i]) })
					defer finish[i]()
				}
				target, calls := selectedConcurrentTarget(t, 2, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if strings.HasPrefix(r.URL.Path, "/hold/") {
						i := int(r.URL.Path[len(r.URL.Path)-1] - '0')
						_, _ = io.WriteString(w, "first\n")
						_ = http.NewResponseController(w).Flush()
						select {
						case <-releases[i]:
						case <-r.Context().Done():
						}
						_, _ = io.WriteString(w, "last\n")
						return
					}
					_, _ = io.WriteString(w, "short")
				}))
				var active [2]*http.Response
				for i := range active {
					path := "http://target.example.test/hold/" + string(rune('0'+i))
					var err error
					active[i], err = target.RoundTrip(selectedRequest(t, t.Context(), path))
					if err != nil {
						t.Fatal(err)
					}
					defer active[i].Body.Close()
				}
				waiting := make(chan struct{})
				requestCtx, cancel := context.WithCancel(httptrace.WithClientTrace(t.Context(), &httptrace.ClientTrace{GetConn: func(string) { close(waiting) }}))
				defer cancel()
				request := selectedRequest(t, requestCtx, "http://target.example.test/short")
				replied := make(chan error, 1)
				go func() {
					response, err := target.RoundTrip(request)
					if response != nil {
						_ = response.Body.Close()
					}
					replied <- err
				}()
				<-waiting
				synctest.Wait()
				select {
				case err := <-replied:
					t.Fatal("busy target capacity did not wait", err)
				default:
				}
				if calls.Load() != 2 {
					t.Fatal("target exceeded its total setup capacity", calls.Load())
				}
				switch stop {
				case "cancel_waiter":
					cancel()
					if err := <-replied; !errors.Is(err, context.Canceled) {
						t.Fatal("capacity wait ignored request cancellation", err)
					}
				default:
					if err := target.Close(); err != nil {
						t.Fatal(err)
					}
					if err := <-replied; !errors.Is(err, httpstream.ErrClosed) {
						t.Fatal("Close did not unblock capacity wait", err)
					}
					// body cleanup can still call standard connection hooks after
					// Close has detached and joined the owner's notifications.
					for _, response := range active {
						_ = response.Body.Close()
					}
					return
				}
				finish[0]()
				body, err := io.ReadAll(active[0].Body)
				_ = active[0].Body.Close()
				if err != nil || string(body) != "first\nlast\n" {
					t.Fatal("waiting request interrupted active response", string(body), err)
				}
				response, err := target.RoundTrip(selectedRequest(t, t.Context(), "http://target.example.test/short"))
				if err != nil {
					t.Fatal("canceled waiter poisoned a healthy target", err)
				}
				body, err = io.ReadAll(response.Body)
				_ = response.Body.Close()
				if err != nil || string(body) != "short" {
					t.Fatal("released connection was not reused", string(body), err)
				}
				finish[1]()
				body, err = io.ReadAll(active[1].Body)
				_ = active[1].Body.Close()
				if err != nil || string(body) != "first\nlast\n" || calls.Load() != 2 {
					t.Fatal("capacity release replaced a connection or lost active bytes", string(body), calls.Load(), err)
				}
			})
		})
	}
}

func TestTargetTransportFailedRequestDoesNotReplayOrPoisonIndependentWork(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		finishStream := make(chan struct{})
		finish := sync.OnceFunc(func() { close(finishStream) })
		defer finish()
		canceled := make(chan struct{})
		var failures atomic.Int32
		target, calls := selectedConcurrentTarget(t, 2, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/events":
				_, _ = io.WriteString(w, "first\n")
				_ = http.NewResponseController(w).Flush()
				select {
				case <-finishStream:
				case <-r.Context().Done():
				}
				_, _ = io.WriteString(w, "last\n")
			case "/cancel":
				_, _ = io.WriteString(w, "active\n")
				_ = http.NewResponseController(w).Flush()
				<-r.Context().Done()
				close(canceled)
			case "/fail":
				failures.Add(1)
				conn, _, err := http.NewResponseController(w).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				_ = conn.Close()
			default:
				w.WriteHeader(http.StatusNoContent)
			}
		}))
		stream, err := target.RoundTrip(selectedRequest(t, t.Context(), "http://target.example.test/events"))
		if err != nil {
			t.Fatal(err)
		}
		defer stream.Body.Close()
		requestCtx, cancel := context.WithCancel(t.Context())
		defer cancel()
		active, err := target.RoundTrip(selectedRequest(t, requestCtx, "http://target.example.test/cancel"))
		if err != nil {
			t.Fatal(err)
		}
		cancel()
		_, err = io.ReadAll(active.Body)
		_ = active.Body.Close()
		if !errors.Is(err, context.Canceled) {
			t.Fatal("active response did not observe its own cancellation", err)
		}
		<-canceled
		warm, err := target.RoundTrip(selectedRequest(t, t.Context(), "http://target.example.test/warm"))
		if err != nil {
			t.Fatal(err)
		}
		_ = warm.Body.Close()
		response, err := target.RoundTrip(selectedRequest(t, t.Context(), "http://target.example.test/fail"))
		if response != nil || err == nil {
			t.Fatal("failed request was retried on a replacement", response, err)
		}
		if failures.Load() != 1 || calls.Load() != 3 {
			t.Fatal("eligible GET was replayed", failures.Load(), calls.Load())
		}
		for range 3 {
			response, err := target.RoundTrip(selectedRequest(t, t.Context(), "http://target.example.test/later"))
			if err != nil {
				t.Fatal("failed request poisoned a later independent request", err)
			}
			_ = response.Body.Close()
		}
		if calls.Load() != 4 {
			t.Fatal("later work did not replace once and retain healthy keepalive", calls.Load())
		}
		finish()
		body, err := io.ReadAll(stream.Body)
		if err != nil || string(body) != "first\nlast\n" {
			t.Fatal("target failure interrupted an independent active request", string(body), err)
		}
	})
}

func TestTargetTransportCapturedRequestSurvivesCloseIdleConnections(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		target, calls := selectedConcurrentTarget(t, 1, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
		warm, err := target.RoundTrip(selectedRequest(t, t.Context(), "http://target.example.test/"))
		if err != nil {
			t.Fatal(err)
		}
		_ = warm.Body.Close()
		captured, resume := make(chan struct{}), make(chan struct{})
		release := sync.OnceFunc(func() { close(resume) })
		defer release()
		ctx := httptrace.WithClientTrace(t.Context(), &httptrace.ClientTrace{GetConn: func(string) {
			close(captured)
			<-resume
		}})
		request := selectedRequest(t, ctx, "http://target.example.test/captured")
		replied := make(chan error, 1)
		go func() {
			response, err := target.RoundTrip(request)
			if response != nil {
				_ = response.Body.Close()
			}
			replied <- err
		}()
		<-captured
		target.CloseIdleConnections()
		release()
		if err := <-replied; err != nil || calls.Load() != 2 {
			t.Fatal("idle cleanup fenced a captured request or failed to replace the idle socket", err, calls.Load())
		}
	})
}

func TestTargetTransportCloseJoinsEveryEnteredDial(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		contexts := make(chan context.Context, 2)
		canceled := make(chan struct{}, 2)
		var conns [2]*selectedCloseConn
		var releases [2]func()
		var waits [2]chan struct{}
		var failures [2]error
		for i := range conns {
			raw, backend := net.Pipe()
			defer raw.Close()
			defer backend.Close()
			waits[i] = make(chan struct{})
			releases[i] = sync.OnceFunc(func() { close(waits[i]) })
			defer releases[i]()
			failures[i] = errors.New("target cleanup " + string(rune('0'+i)))
			conns[i] = &selectedCloseConn{Conn: raw, entered: make(chan struct{}), err: failures[i]}
		}
		target, err := httpstream.NewTargetTransport(t.Context(), func(ctx context.Context) (net.Conn, error) {
			index := int(calls.Add(1) - 1)
			contexts <- ctx
			<-ctx.Done()
			canceled <- struct{}{}
			<-waits[index]
			return conns[index], nil
		}, 2)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { releases[0](); releases[1](); _ = target.Close() }()
		requestCtx, cancel := context.WithCancel(t.Context())
		defer cancel()
		replied := make(chan error, 2)
		for range 2 {
			request := selectedRequest(t, requestCtx, "http://target.example.test/")
			go func() { _, err := target.RoundTrip(request); replied <- err }()
		}
		first, second := <-contexts, <-contexts
		cancel()
		for range 2 {
			if err := <-replied; !errors.Is(err, context.Canceled) {
				t.Fatal("request stayed joined to setup after cancellation", err)
			}
		}
		if first.Err() != nil || second.Err() != nil {
			t.Fatal("request cancellation abandoned owner-bound setup")
		}
		closed := make(chan error, 1)
		go func() { closed <- target.Close() }()
		<-canceled
		<-canceled
		synctest.Wait()
		select {
		case err := <-closed:
			t.Fatal("Close returned before its entered dials", err)
		default:
		}
		releases[0]()
		<-conns[0].entered
		synctest.Wait()
		select {
		case err := <-closed:
			t.Fatal("Close joined only one of its entered dials", err)
		default:
		}
		releases[1]()
		err = <-closed
		if !errors.Is(err, failures[0]) || !errors.Is(err, failures[1]) || calls.Load() != 2 {
			t.Fatal("multi-dial cleanup lost failures or exceeded capacity", err, calls.Load())
		}
		for _, conn := range conns {
			if conn.calls.Load() != 1 {
				t.Fatal("late target was not closed exactly once", conn.calls.Load())
			}
		}
	})
}
