package httpstream_test

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/tnldotdev/tnl/internal/publisher/proxy"
	"github.com/tnldotdev/tnl/internal/transport/httpstream"
)

type upgradeOwnerBody struct {
	io.ReadWriteCloser
	close func() error
}

func (b *upgradeOwnerBody) Close() error { return b.close() }

func TestHTTPStreamServeRetainsJoinedUpgradeCleanupFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		visitor, server := net.Pipe()
		defer visitor.Close()
		defer server.Close()
		upstream, backend := net.Pipe()
		defer upstream.Close()
		defer backend.Close()
		backendDone := make(chan error, 1)
		go func() {
			defer backend.Close()
			request, err := http.ReadRequest(bufio.NewReader(backend))
			if err == nil {
				err = request.Body.Close()
			}
			if err == nil {
				_, err = io.WriteString(backend, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: test\r\n\r\nhot")
			}
			backendDone <- err
		}()
		cleanup := errors.New("upgrade cleanup failed after copying")
		entered, release := make(chan struct{}), make(chan struct{})
		unblock := sync.OnceFunc(func() { close(release) })
		defer unblock()
		served := make(chan error, 1)
		go func() {
			served <- httpstream.Serve(t.Context(), server, &url.URL{Scheme: "http", Host: "target.test"}, func(context.Context) (net.Conn, error) {
				return upstream, nil
			}, nil, httpstream.ResponseHooks{Observe: func(response *http.Response) error {
				body := response.Body.(io.ReadWriteCloser)
				response.Body = &upgradeOwnerBody{ReadWriteCloser: body, close: func() error {
					err := body.Close()
					close(entered)
					<-release
					return errors.Join(err, cleanup)
				}}
				return nil
			}}, httpstream.Drain{})
		}()
		if _, err := io.WriteString(visitor, "GET /socket HTTP/1.1\r\nHost: visitor.test\r\nConnection: Upgrade\r\nUpgrade: test\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		reader := bufio.NewReader(visitor)
		response, err := http.ReadResponse(reader, nil)
		if err != nil || response.StatusCode != http.StatusSwitchingProtocols {
			t.Fatal("upgrade failed", response, err)
		}
		var hot [3]byte
		if _, err := io.ReadFull(reader, hot[:]); err != nil || string(hot[:]) != "hot" {
			t.Fatal("upgrade bytes changed", string(hot[:]), err)
		}
		<-entered
		synctest.Wait()
		select {
		case err := <-served:
			t.Fatal("stream returned before request upgrade cleanup joined", err)
		default:
		}
		unblock()
		if err := <-served; !errors.Is(err, cleanup) {
			t.Fatal("stream discarded its request's upgrade cleanup failure", err)
		}
		if err := <-backendDone; err != nil {
			t.Fatal(err)
		}
	})
}

type upgradeOwnerTransport struct{ body io.ReadCloser }

func (t *upgradeOwnerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusSwitchingProtocols, Header: http.Header{"Connection": {"Upgrade"}, "Upgrade": {"test"}}, Body: t.body, Request: r}, nil
}
func (*upgradeOwnerTransport) CloseIdleConnections() {}
func (*upgradeOwnerTransport) Close() error          { return nil }

func TestProxyCloseRetainsUpgradeCleanupIncludingHandlerPanic(t *testing.T) {
	for _, abort := range []bool{false, true} {
		t.Run(map[bool]string{false: "hijack failure", true: "handler panic"}[abort], func(t *testing.T) {
			cleanup := errors.New("upgrade owner cleanup failure")
			body, peer := net.Pipe()
			defer body.Close()
			defer peer.Close()
			transport := &upgradeOwnerTransport{body: &upgradeOwnerBody{ReadWriteCloser: body, close: func() error {
				return errors.Join(body.Close(), cleanup)
			}}}
			hooks := httpstream.ResponseHooks{}
			if abort {
				hooks.Observe = func(*http.Response) error { panic(http.ErrAbortHandler) }
			}
			owner, err := proxy.New(proxy.Config{Hostname: "proxy.example.test", Target: "http://target.test", Hooks: hooks,
				Transport: func(*url.URL, proxy.TargetOptions, bool) (proxy.Transport, error) { return transport, nil }})
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			request := httptest.NewRequest(http.MethodGet, "/socket", nil)
			request.Header.Set("Connection", "Upgrade")
			request.Header.Set("Upgrade", "test")
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				owner.ServeAdmittedHTTP(httptest.NewRecorder(), request)
			}()
			if abort && recovered != http.ErrAbortHandler || !abort && recovered != nil {
				t.Fatal("upgrade cleanup changed the original handler panic", recovered)
			}
			first := owner.Close()
			if !errors.Is(first, cleanup) || owner.Close() != first {
				t.Fatal("proxy owner discarded or changed its retained upgrade cleanup failure", first)
			}
		})
	}
}
