// package httpstream serves HTTP over one already-selected upstream connection.
// it never dials, retries another connection, or selects a different publisher.
package httpstream

import (
	"context"
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
	stop := context.AfterFunc(ctx, func() { _ = client.Close() })
	defer stop()
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
	defer transport.CloseIdleConnections()
	defer func() {
		mu.Lock()
		defer mu.Unlock()
		if upstream != nil {
			_ = upstream.Close()
		}
	}()
	proxy := &httputil.ReverseProxy{Transport: transport, FlushInterval: -1,
		Rewrite: func(request *httputil.ProxyRequest) {
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
	connection := &ownedConn{Conn: client, done: make(chan struct{})}
	listener := &singleListener{connection: connection}
	var handler http.Handler = proxy
	if wrap != nil {
		handler = wrap(handler)
	}
	handler = observability.PublisherHTTP(handler)
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 32 << 10,
		BaseContext: func(net.Listener) context.Context { return ctx }, ErrorLog: log.New(io.Discard, "", 0)}
	defer server.Close()
	err := server.Serve(listener)
	if errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

type ownedConn struct {
	net.Conn
	done chan struct{}
	once sync.Once
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
	connection *ownedConn
	accepted   bool
}

func (l *singleListener) Accept() (net.Conn, error) {
	if !l.accepted {
		l.accepted = true
		return l.connection, nil
	}
	<-l.connection.done
	return nil, net.ErrClosed
}

func (l *singleListener) Close() error   { return l.connection.Close() }
func (l *singleListener) Addr() net.Addr { return l.connection.LocalAddr() }
