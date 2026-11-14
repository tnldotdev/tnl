// package httpstream serves HTTP over one already-selected upstream connection.
// it never dials, retries another connection, or selects a different publisher.
package httpstream

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
)

var ErrClosed = errors.New("selected HTTP upstream connection is closed")

func Forward(ctx context.Context, client, upstream net.Conn, target *url.URL) error {
	if client == nil || upstream == nil || target == nil || target.Host == "" || target.Scheme != "http" && target.Scheme != "https" {
		return ErrClosed
	}
	defer upstream.Close()
	return Serve(ctx, client, target, func(context.Context) (net.Conn, error) { return upstream, nil }, nil)
}

// Serve checks each request before the first target dial or any target bytes.
// wrap can serve bounded authentication endpoints without opening the target.
// one failed/closed upstream is final, including on an idempotent HTTP request.
func Serve(ctx context.Context, client net.Conn, target *url.URL, connect func(context.Context) (net.Conn, error), wrap func(http.Handler) http.Handler) error {
	if client == nil || target == nil || target.Host == "" || connect == nil || target.Scheme != "http" && target.Scheme != "https" {
		return ErrClosed
	}
	var mu sync.Mutex
	dialed := false
	closed := false
	var upstream net.Conn
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		mu.Lock()
		if dialed || closed {
			mu.Unlock()
			return nil, ErrClosed
		}
		dialed = true
		mu.Unlock()
		conn, err := connect(ctx)
		mu.Lock()
		if closed {
			mu.Unlock()
			if conn != nil {
				_ = conn.Close()
			}
			return nil, ErrClosed
		}
		upstream = conn
		mu.Unlock()
		return conn, err
	}
	transport := &http.Transport{Proxy: nil, MaxConnsPerHost: 1, MaxResponseHeaderBytes: 64 << 10, ExpectContinueTimeout: time.Second, DialContext: dial, DialTLSContext: dial}
	defer transport.CloseIdleConnections()
	defer func() {
		mu.Lock()
		closed = true
		conn := upstream
		upstream = nil
		mu.Unlock()
		if conn != nil {
			_ = conn.Close()
		}
	}()
	proxy := &httputil.ReverseProxy{Transport: transport, FlushInterval: -1,
		Rewrite: func(request *httputil.ProxyRequest) {
			ForwardTrailers(request.In, request.Out)
			observability.PublisherHTTPForward(request.Out.Context())
			request.SetURL(target)
			request.Out.Host = target.Host
		}, ModifyResponse: func(response *http.Response) error {
			observability.PublisherHTTPResponse(response.Request.Context())
			observability.PublisherHTTPUpgrade(response)
			if response.StatusCode != http.StatusSwitchingProtocols && response.Close {
				response.Header.Set("Connection", "close")
			}
			return nil
		}, ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			observability.PublisherHTTPError(r.Context(), err)
			w.Header().Set("Connection", "close")
			_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(5 * time.Second))
			http.Error(w, "service connection closed", http.StatusBadGateway)
		}, ErrorLog: log.New(io.Discard, "", 0)}
	var handler http.Handler = proxy
	if wrap != nil {
		handler = wrap(handler)
	}
	return ServeHandler(ctx, client, handler)
}

// ServeHandler serves an in-process HTTP application on the admitted visitor
// connection. TLS negotiation is preserved; no target socket or local listener
// is created. completion joins HTTP/1 upgrades and concurrent HTTP/2 handlers.
func ServeHandler(ctx context.Context, client net.Conn, handler http.Handler) error {
	if client == nil || handler == nil {
		return ErrClosed
	}
	var workers sync.WaitGroup
	workers.Add(1)
	stop := context.AfterFunc(ctx, func() { defer workers.Done(); _ = client.Close() })
	defer func() {
		if stop() {
			workers.Done()
		}
		// listener cleanup must unblock the connection before joining.
		workers.Wait()
	}()
	listener := &singleListener{connection: client, done: make(chan struct{})}
	handler = Requests(observability.PublisherHTTP(handler), RequestBodyTimeout)
	// HTTP/2 closes its connection before all handlers necessarily return.
	// close admission before joining so a late stream cannot add another worker.
	var handlerMu sync.Mutex
	var handlers sync.WaitGroup
	acceptHandlers := true
	defer func() {
		handlerMu.Lock()
		acceptHandlers = false
		handlerMu.Unlock()
		handlers.Wait()
	}()
	// net/http forgets hijacked HTTP/1 connections before their handlers return.
	// HTTP/2 cannot hijack; this flag is used only by the HTTP/1 connection worker.
	hijacked := false
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerMu.Lock()
		if !acceptHandlers {
			handlerMu.Unlock()
			return
		}
		handlers.Add(1)
		handlerMu.Unlock()
		defer handlers.Done()
		defer func() {
			if hijacked {
				listener.finish()
				workers.Done()
			}
		}()
		handler.ServeHTTP(w, r)
	}), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 32 << 10,
		ConnState: func(_ net.Conn, state http.ConnState) {
			switch state {
			case http.StateNew:
				// StateNew runs before Serve starts the connection worker, so no
				// worker can be added after Serve returns and the join begins.
				workers.Add(1)
			case http.StateHijacked:
				hijacked = true
			case http.StateClosed:
				listener.finish()
				workers.Done()
			}
		},
		BaseContext: func(net.Listener) context.Context { return ctx }, ErrorLog: log.New(io.Discard, "", 0),
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}}}
	defer server.Close()
	err := server.Serve(listener)
	if errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

type singleListener struct {
	connection net.Conn
	done       chan struct{}
	once       sync.Once
	accepted   bool
}

func (l *singleListener) Accept() (net.Conn, error) {
	if !l.accepted {
		l.accepted = true
		return l.connection, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *singleListener) finish() { l.once.Do(func() { close(l.done) }) }

func (l *singleListener) Close() error {
	err := l.connection.Close()
	l.finish()
	return err
}

func (l *singleListener) Addr() net.Addr { return l.connection.LocalAddr() }
