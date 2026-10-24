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

// Serve checks each request before target work. HTTP/1 retains its one selected
// keepalive connection. HTTP/2 requests own separate target connections so one
// canceled request cannot close another stream's target. no request is retried.
func Serve(ctx context.Context, client net.Conn, target *url.URL, connect func(context.Context) (net.Conn, error), wrap func(http.Handler) http.Handler) error {
	if client == nil || target == nil || target.Host == "" || connect == nil || target.Scheme != "http" && target.Scheme != "https" {
		return ErrClosed
	}
	stop := context.AfterFunc(ctx, func() { _ = client.Close() })
	defer stop()
	defer client.Close()
	h2 := false
	if secured, ok := client.(interface{ ConnectionState() tls.ConnectionState }); ok {
		state := secured.ConnectionState()
		h2 = state.HandshakeComplete && state.NegotiatedProtocol == "h2"
	}
	var handler http.Handler
	if h2 {
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			proxy, closeTarget := selectedProxy(target, connect)
			defer closeTarget()
			proxy.ServeHTTP(w, r)
		})
	} else {
		var closeTarget func()
		handler, closeTarget = selectedProxy(target, connect)
		defer closeTarget()
	}
	if wrap != nil {
		handler = wrap(handler)
	}
	handler = Requests(observability.PublisherHTTP(handler), RequestBodyTimeout)
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 32 << 10,
		BaseContext: func(net.Listener) context.Context { return ctx }, ErrorLog: log.New(io.Discard, "", 0)}
	defer server.Close()
	// net/http recognizes the already-negotiated TLS ALPN and serves HTTP/2 on
	// this single connection; its request contexts stay independent.
	done := make(chan struct{})
	var connection net.Conn = &ownedConn{Conn: client, done: done}
	if h2 {
		// preserve *tls.Conn's handshake and ConnectionState methods. hiding
		// them behind a net.Conn wrapper makes net/http parse h2 as HTTP/1.
		secured, ok := client.(*tls.Conn)
		if !ok {
			return ErrClosed
		}
		connection = &ownedTLSConn{Conn: secured, done: done}
	}
	err := server.Serve(&singleListener{connection: connection, done: done})
	if errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// selectedProxy permits exactly one target dial for this request or HTTP/1
// connection. a transport failure cannot replay on a fresh target connection.
func selectedProxy(target *url.URL, connect func(context.Context) (net.Conn, error)) (http.Handler, func()) {
	var mu sync.Mutex
	dialed := false
	var upstream net.Conn
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		mu.Lock()
		defer mu.Unlock()
		if dialed {
			return nil, ErrClosed
		}
		dialed = true
		var err error
		upstream, err = connect(ctx)
		return upstream, err
	}
	transport := &http.Transport{Proxy: nil, MaxConnsPerHost: 1, MaxResponseHeaderBytes: 64 << 10, ExpectContinueTimeout: time.Second, DialContext: dial, DialTLSContext: dial}
	closeTarget := func() {
		transport.CloseIdleConnections()
		mu.Lock()
		defer mu.Unlock()
		if upstream != nil {
			_ = upstream.Close()
		}
	}
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
	return proxy, closeTarget
}

type ownedConn struct {
	net.Conn
	done chan struct{}
	once sync.Once
}

type ownedTLSConn struct {
	*tls.Conn
	done chan struct{}
	once sync.Once
}

func (c *ownedTLSConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.done) })
	return err
}

func (c *ownedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.done) })
	return err
}

func (c *ownedConn) CloseWrite() error {
	if writer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return writer.CloseWrite()
	}
	return errors.ErrUnsupported
}

type singleListener struct {
	connection net.Conn
	done       <-chan struct{}
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

func (l *singleListener) Close() error   { return l.connection.Close() }
func (l *singleListener) Addr() net.Addr { return l.connection.LocalAddr() }
