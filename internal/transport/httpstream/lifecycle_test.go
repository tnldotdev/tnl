package httpstream_test

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/transport/httpstream"
)

func TestHTTPStreamServeJoinsHijackedHandlerAfterSocketClose(t *testing.T) {
	m := observability.New("publisher")
	defer m.Shutdown(context.Background())
	synctest.Test(t, func(t *testing.T) {
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
			_ = request.Body.Close()
			_, _ = io.WriteString(backend, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		}()
		handlerReturned := make(chan struct{})
		releaseHandler := make(chan struct{})
		release := sync.OnceFunc(func() { close(releaseHandler) })
		defer release()
		handlerDone := make(chan struct{})
		served := make(chan error, 1)
		go func() {
			served <- httpstream.Serve(observability.WithMetrics(t.Context(), m), client, &url.URL{Scheme: "http", Host: "target.test"}, func(context.Context) (net.Conn, error) {
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
		_, _ = io.WriteString(visitor, "GET / HTTP/1.1\r\nHost: proxy.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		response, err := http.ReadResponse(bufio.NewReader(visitor), &http.Request{Method: "GET"})
		if err != nil || response.StatusCode != http.StatusSwitchingProtocols {
			t.Fatal("upgrade failed", err)
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
