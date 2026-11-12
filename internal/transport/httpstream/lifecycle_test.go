package httpstream_test

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/transport/httpstream"
)

func TestHTTPStreamServeJoinsHijackedHandlerAfterSocketClose(t *testing.T) {
	for _, shutdown := range []string{"backend_close", "cancel"} {
		t.Run(shutdown, func(t *testing.T) {
			testHTTPStreamServeJoinsHijackedHandlerAfterSocketClose(t, shutdown == "cancel")
		})
	}
}

func testHTTPStreamServeJoinsHijackedHandlerAfterSocketClose(t *testing.T, cancelStream bool) {
	m := observability.New("publisher")
	defer func() {
		if err := m.Shutdown(context.Background()); err != nil {
			t.Error(err)
		}
	}()
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(observability.WithMetrics(t.Context(), m))
		defer cancel()
		client, visitor := net.Pipe()
		defer client.Close()
		defer visitor.Close()
		upstream, backend := net.Pipe()
		defer upstream.Close()
		defer backend.Close()
		backendDone := make(chan struct{})
		go func() {
			defer close(backendDone)
			defer backend.Close()
			request, err := http.ReadRequest(bufio.NewReader(backend))
			if err != nil {
				t.Error(err)
				return
			}
			if err := request.Body.Close(); err != nil {
				t.Error(err)
			}
			if _, err := io.WriteString(backend, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"); err != nil {
				t.Error(err)
				return
			}
			if cancelStream {
				var payload [1]byte
				if _, err := backend.Read(payload[:]); !errors.Is(err, io.EOF) {
					t.Error("cancellation did not close the upstream connection", err)
				}
			}
		}()
		handlerReturned := make(chan struct{})
		releaseHandler := make(chan struct{})
		release := sync.OnceFunc(func() { close(releaseHandler) })
		defer release()
		handlerDone := make(chan struct{})
		served := make(chan error, 1)
		go func() {
			served <- httpstream.Serve(ctx, client, &url.URL{Scheme: "http", Host: "target.test"}, func(context.Context) (net.Conn, error) {
				return upstream, nil
			}, func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					defer close(handlerDone)
					next.ServeHTTP(w, r)
					close(handlerReturned)
					<-releaseHandler
				})
			})
		}()
		if _, err := io.WriteString(visitor, "GET / HTTP/1.1\r\nHost: proxy.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(bufio.NewReader(visitor), &http.Request{Method: "GET"})
		if err != nil || response.StatusCode != http.StatusSwitchingProtocols {
			t.Fatal("upgrade failed", err)
		}
		if cancelStream {
			cancel()
		}
		<-backendDone
		<-handlerReturned
		// the proxy has closed the hijacked visitor socket, but its owning
		// handler is still running. quiescence makes an early return observable.
		synctest.Wait()
		if observedMetric(t, m, "tnl_publisher_http_requests_active", nil) != 1 || observedMetric(t, m, "tnl_publisher_http_request_duration_seconds", nil) != 0 {
			t.Fatal("gated HTTP handler was not active")
		}
		select {
		case err := <-served:
			t.Error("HTTP stream returned before its hijacked handler joined", err)
			release()
			<-handlerDone
			return
		default:
		}
		release()
		if err := <-served; err != nil {
			t.Fatal(err)
		}
		select {
		case <-handlerDone:
		default:
			t.Fatal("HTTP stream returned before its handler completed")
		}
		if observedMetric(t, m, "tnl_publisher_http_requests_active", nil) != 0 || observedMetric(t, m, "tnl_publisher_http_request_duration_seconds", map[string]string{"http_response_status_code": "101", "tnl_response_origin": "local_service"}) != 1 {
			t.Fatal("HTTP stream returned before its completion observations")
		}
	})
}

type gatedFirstCloseConn struct {
	net.Conn
	closing atomic.Bool
	started chan struct{}
	release <-chan struct{}
}

func (c *gatedFirstCloseConn) Close() error {
	first := !c.closing.Swap(true)
	err := c.Conn.Close()
	if first {
		close(c.started)
		<-c.release
	}
	return err
}

func TestHTTPStreamServeJoinsCancellationClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client, visitor := net.Pipe()
		defer client.Close()
		defer visitor.Close()
		releaseClose := make(chan struct{})
		release := sync.OnceFunc(func() { close(releaseClose) })
		defer release()
		connection := &gatedFirstCloseConn{Conn: client, started: make(chan struct{}), release: releaseClose}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		served := make(chan error, 1)
		go func() {
			served <- httpstream.Serve(ctx, connection, &url.URL{Scheme: "http", Host: "target.test"}, func(context.Context) (net.Conn, error) {
				t.Error("idle visitor opened the target")
				return nil, httpstream.ErrClosed
			}, nil)
		}()
		synctest.Wait()
		cancel()
		<-connection.started
		// cancellation has closed the socket and the HTTP worker can finish,
		// but the cancellation callback still owns its gated Close call.
		synctest.Wait()
		select {
		case err := <-served:
			t.Error("HTTP stream returned before its cancellation callback joined", err)
			return
		default:
		}
		release()
		if err := <-served; err != nil {
			t.Fatal(err)
		}
	})
}

func TestHTTPStreamApplicationFailureKeepsAuthoredMessage(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client, visitor := net.Pipe()
		defer client.Close()
		defer visitor.Close()
		served := make(chan error, 1)
		calls := 0
		go func() {
			served <- httpstream.Serve(t.Context(), client, &url.URL{Scheme: "http", Host: "target.test"}, func(context.Context) (net.Conn, error) {
				calls++
				return nil, errors.New("private target credentials must not reach the visitor")
			}, nil)
		}()
		if _, err := io.WriteString(visitor, "GET / HTTP/1.1\r\nHost: proxy.test\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(bufio.NewReader(visitor), &http.Request{Method: "GET"})
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		if err := response.Body.Close(); err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusBadGateway || !response.Close || string(body) != "service connection closed\n" {
			t.Fatal("application failure changed the safe HTTP response", response.StatusCode, response.Close, string(body))
		}
		if err := <-served; err != nil {
			t.Fatal(err)
		}
		if calls != 1 {
			t.Fatal("application failure retried the target", calls)
		}
	})
}
