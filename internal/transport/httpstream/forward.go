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

	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/observability"
)

var ErrClosed = errors.New("selected HTTP upstream connection is closed")

// drain is an optional run-owned signal, not a server registry. the owner
// publishes a fixed deadline before closing Started. cancellation of the serving
// context always closes immediately, even while graceful shutdown is in progress.
// Started and Deadline must be supplied together; the zero value disables drain.
type Drain struct {
	Started  <-chan struct{}
	Deadline func() time.Time
}

func Forward(ctx context.Context, client, upstream net.Conn, target *url.URL) error {
	if client == nil || upstream == nil || target == nil || target.Host == "" || target.Scheme != "http" && target.Scheme != "https" {
		return ErrClosed
	}
	defer upstream.Close()
	return Serve(ctx, client, target, func(context.Context) (net.Conn, error) { return upstream, nil }, nil, ResponseHooks{}, Drain{})
}

// Serve checks each request before the first target dial or any target bytes.
// wrap can serve bounded authentication endpoints without opening the target.
// one failed/closed upstream is final, including on an idempotent HTTP request.
func Serve(ctx context.Context, client net.Conn, target *url.URL, connect func(context.Context) (net.Conn, error), wrap func(http.Handler) http.Handler, hooks ResponseHooks, drain Drain) error {
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
	transport := &http.Transport{Proxy: nil, DisableCompression: true, MaxConnsPerHost: 1, MaxResponseHeaderBytes: 64 << 10, ExpectContinueTimeout: time.Second, DialContext: dial, DialTLSContext: dial}
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
			hooks.Rewrite(request)
		}, ModifyResponse: func(response *http.Response) error {
			if err := hooks.ModifyResponse(response); err != nil {
				return err
			}
			if response.StatusCode != http.StatusSwitchingProtocols && response.Close {
				response.Header.Set("Connection", "close")
			}
			return nil
		}, ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			observability.PublisherHTTPError(r.Context(), err)
			hooks.ForwardingFailed(r)
			w.Header().Set("Connection", "close")
			_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(5 * time.Second))
			if code, ok := diagnostic.CodeOf(err); ok {
				diagnostic.WriteHTTP(w, r, code, "")
				return
			}
			http.Error(w, "service connection closed", http.StatusBadGateway)
		}, ErrorLog: log.New(io.Discard, "", 0)}
	var handler http.Handler = proxy
	if wrap != nil {
		handler = wrap(handler)
	}
	return ServeHandler(ctx, client, handler, drain)
}

// ServeHandler serves an in-process HTTP application on the admitted visitor
// connection. TLS negotiation is preserved; no target socket or local listener
// is created. completion joins HTTP/1 upgrades and concurrent HTTP/2 handlers.
func ServeHandler(ctx context.Context, client net.Conn, handler http.Handler, drain Drain) (result error) {
	if client == nil || handler == nil || (drain.Started == nil) != (drain.Deadline == nil) {
		return ErrClosed
	}
	life, cancel := context.WithCancel(ctx)
	defer cancel()
	var workers sync.WaitGroup
	var callbacks sync.WaitGroup
	callbacks.Add(1)
	stop := context.AfterFunc(life, func() { defer callbacks.Done(); _ = client.Close() })
	defer func() {
		if stop() {
			callbacks.Done()
		}
		// listener cleanup must unblock the connection before joining.
		workers.Wait()
		callbacks.Wait()
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
		select {
		case <-drain.Started:
			w.Header().Set("Connection", "close")
			http.Error(w, "service is draining", http.StatusServiceUnavailable)
			return
		default:
		}
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
		BaseContext: func(net.Listener) context.Context { return life }, ErrorLog: log.New(io.Discard, "", 0),
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}}}
	// Shutdown closes the listener before responses finish. Serve returning must
	// not run Close until Shutdown and the connection/handler joins have finished.
	servingDone := make(chan struct{})
	shutdownDone := make(chan error, 1)
	go func() {
		select {
		case <-servingDone:
			shutdownDone <- nil
		case <-life.Done():
			shutdownDone <- nil
		case <-drain.Started:
			until := drain.Deadline()
			// a zero or expired published deadline fails closed at actual drain.
			shutdown, stop := context.WithDeadline(life, until)
			defer stop()
			// Shutdown does not track hijacked HTTP/1 connections. retain the
			// deadline fence until those handlers and the connection worker join.
			forced := make(chan struct{})
			force := context.AfterFunc(shutdown, func() { defer close(forced); cancel() })
			err := server.Shutdown(shutdown)
			if err != nil {
				cancel()
				err = errors.Join(err, server.Close())
			}
			<-servingDone
			workers.Wait()
			handlerMu.Lock()
			acceptHandlers = false
			handlerMu.Unlock()
			handlers.Wait()
			if !force() {
				<-forced
			}
			if err == nil {
				err = shutdown.Err()
			}
			shutdownDone <- err
		}
	}()
	err := server.Serve(listener)
	close(servingDone)
	result = <-shutdownDone
	cancel()
	result = errors.Join(result, server.Close())
	if errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) {
		return result
	}
	return errors.Join(result, err)
}

type singleListener struct {
	connection net.Conn
	done       chan struct{}
	once       sync.Once
	mu         sync.Mutex
	accepted   bool
	closed     bool
}

func (l *singleListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, net.ErrClosed
	}
	if !l.accepted {
		l.accepted = true
		l.mu.Unlock()
		return l.connection, nil
	}
	l.mu.Unlock()
	<-l.done
	return nil, net.ErrClosed
}

func (l *singleListener) finish() { l.once.Do(func() { close(l.done) }) }

func (l *singleListener) Close() error {
	l.mu.Lock()
	l.closed = true
	l.mu.Unlock()
	l.finish()
	return nil
}

func (l *singleListener) Addr() net.Addr { return l.connection.LocalAddr() }
