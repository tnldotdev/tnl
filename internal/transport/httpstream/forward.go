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
	"net/http/httptrace"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
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
	// Finish joins delivery after HTTP workers and close callbacks return.
	// it does not own net.Conn.Close or grant more serving authority.
	Finish func() error
}

func Forward(ctx context.Context, client, upstream net.Conn, target *url.URL) error {
	if client == nil || upstream == nil || target == nil || target.Host == "" || target.Scheme != "http" && target.Scheme != "https" {
		return ErrClosed
	}
	defer upstream.Close()
	return Serve(ctx, client, target, func(context.Context) (net.Conn, error) { return upstream, nil }, nil, ResponseHooks{}, Drain{})
}

// SelectedTransport owns connections to one target without replaying requests.
// constructors select strict single-attempt or bounded concurrent ownership.
// the caller owns requests and response bodies; Close joins entered target work.
type SelectedTransport struct {
	life         context.Context
	connect      func(context.Context) (net.Conn, error)
	capacity     int
	strict       bool
	mu           sync.Mutex
	closed       bool
	terminal     error
	slots        map[*selectedSlot]struct{}
	wake         chan struct{}
	stopped      chan struct{}
	work         sync.WaitGroup
	shutdownDone chan struct{}
	stopOwner    func() bool
	ownerDone    chan struct{}
	closeErr     error
}

type selectedSlot struct {
	client   *http.ClientConn
	socket   net.Conn
	cancel   context.CancelFunc
	ready    chan struct{}
	err      error
	retiring bool
	used     bool
	headers  int
	upgraded bool
}

// NewSelectedTransport permits one connection attempt total. failed setup,
// connection loss, or idle retirement fences every later request.
func NewSelectedTransport(ctx context.Context, connect func(context.Context) (net.Conn, error)) (*SelectedTransport, error) {
	return newSelectedTransport(ctx, connect, 1, true)
}

// NewTargetTransport bounds live connections and setup to one captured target.
// a failed request is never retried; later requests may open replacements.
// connect returns a connection already secured when the target uses HTTPS.
func NewTargetTransport(ctx context.Context, connect func(context.Context) (net.Conn, error), capacity int) (*SelectedTransport, error) {
	return newSelectedTransport(ctx, connect, capacity, false)
}

func newSelectedTransport(ctx context.Context, connect func(context.Context) (net.Conn, error), capacity int, strict bool) (*SelectedTransport, error) {
	if ctx == nil || connect == nil || capacity < 1 {
		return nil, ErrClosed
	}
	t := &SelectedTransport{life: ctx, connect: connect, capacity: capacity, strict: strict, slots: make(map[*selectedSlot]struct{}), wake: make(chan struct{}, 1), stopped: make(chan struct{}), shutdownDone: make(chan struct{}), ownerDone: make(chan struct{})}
	t.stopOwner = context.AfterFunc(ctx, func() { defer close(t.ownerDone); t.shutdown() })
	return t, nil
}

func (t *SelectedTransport) notify() {
	select {
	case t.wake <- struct{}{}:
	default:
	}
}

func (t *SelectedTransport) stopLocked(err error) {
	if t.terminal == nil {
		t.terminal = err
		close(t.stopped)
	}
}

func (t *SelectedTransport) currentLocked() error {
	if t.closed || t.life.Err() != nil {
		return ErrClosed
	}
	for slot := range t.slots {
		if slot.client != nil && slot.client.Err() != nil {
			if t.strict {
				t.stopLocked(ErrClosed)
			} else if slot.headers == 0 && !slot.upgraded {
				t.retireLocked(slot)
			}
		}
	}
	return t.terminal
}

func (t *SelectedTransport) RoundTrip(r *http.Request) (response *http.Response, result error) {
	defer func() {
		// a canceled waiter must not consume the only availability signal.
		t.notify()
		if result != nil && r.Body != nil {
			_ = r.Body.Close()
		}
	}()
	t.mu.Lock()
	err := t.currentLocked()
	t.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if r.URL == nil || r.URL.Scheme != "http" && r.URL.Scheme != "https" || r.URL.Hostname() == "" {
		return nil, ErrClosed
	}
	port := r.URL.Port()
	if port == "" {
		port = "80"
		if r.URL.Scheme == "https" {
			port = "443"
		}
	}
	address := net.JoinHostPort(r.URL.Hostname(), port)
	trace := httptrace.ContextClientTrace(r.Context())
	if trace != nil && trace.GetConn != nil {
		trace.GetConn(address)
	}
	var started *selectedSlot
	for {
		t.mu.Lock()
		if err := t.currentLocked(); err != nil {
			t.mu.Unlock()
			return nil, err
		}
		if err := r.Context().Err(); err != nil {
			t.mu.Unlock()
			return nil, err
		}
		if started != nil {
			select {
			case <-started.ready:
				if started.err != nil {
					t.mu.Unlock()
					return nil, errors.Join(ErrClosed, started.err)
				}
				if started.client == nil || started.client.Err() != nil {
					t.mu.Unlock()
					return nil, ErrClosed
				}
			default:
			}
		}
		for slot := range t.slots {
			client := slot.client
			if slot.retiring || client == nil || client.Available() == 0 || client.Reserve() != nil {
				continue
			}
			socket, reused := slot.socket, slot.used
			slot.used = true
			slot.headers++
			t.mu.Unlock()
			t.notify()
			if trace != nil && trace.GotConn != nil {
				trace.GotConn(httptrace.GotConnInfo{Conn: socket, Reused: reused})
			}
			response, err := client.RoundTrip(r)
			t.mu.Lock()
			slot.headers--
			// ClientConn hands a 101 socket to Body and reports it unusable.
			// keep its slot until the upgrade owner closes Body, then retire it
			// so a run-owned pool can serve later independent requests.
			slot.upgraded = response != nil && response.StatusCode == http.StatusSwitchingProtocols
			if slot.upgraded {
				body, ok := response.Body.(io.ReadWriteCloser)
				if !ok {
					err = errors.Join(err, ErrClosed)
				} else {
					owned := &selectedUpgradeBody{ReadWriteCloser: body, owner: t, slot: slot}
					if writer, ok := body.(interface{ CloseWrite() error }); ok {
						response.Body = &selectedUpgradeHalfClose{selectedUpgradeBody: owned, writer: writer}
					} else {
						response.Body = owned
					}
				}
			}
			if err != nil && client.Err() != nil {
				if t.strict {
					t.stopLocked(errors.Join(ErrClosed, err))
				} else if !t.closed {
					t.retireLocked(slot)
				}
			}
			t.mu.Unlock()
			if err != nil {
				return nil, errors.Join(ErrClosed, err)
			}
			return response, nil
		}
		if err := t.currentLocked(); err != nil {
			t.mu.Unlock()
			return nil, err
		}
		if started == nil && len(t.slots) < t.capacity {
			started = &selectedSlot{ready: make(chan struct{})}
			t.slots[started] = struct{}{}
			// preserve request values without letting a departed handler abandon
			// entered setup. shutdown owns cancellation and the completion join.
			setup, cancel := context.WithCancel(context.WithoutCancel(r.Context()))
			started.cancel = cancel
			t.work.Add(1)
			go t.open(setup, cancel, started, r.URL.Scheme, address)
		}
		t.mu.Unlock()
		select {
		case <-r.Context().Done():
			return nil, context.Cause(r.Context())
		case <-t.life.Done():
			return nil, ErrClosed
		case <-t.stopped:
		case <-t.wake:
		}
	}
}

type selectedUpgradeBody struct {
	io.ReadWriteCloser
	owner *SelectedTransport
	slot  *selectedSlot
	once  sync.Once
	err   error
}

type selectedUpgradeHalfClose struct {
	*selectedUpgradeBody
	writer interface{ CloseWrite() error }
}

func (b *selectedUpgradeHalfClose) CloseWrite() error { return b.writer.CloseWrite() }

func (b *selectedUpgradeBody) Close() error {
	b.once.Do(func() {
		b.err = b.ReadWriteCloser.Close()
		b.owner.closeError(b.err)
		b.owner.mu.Lock()
		if b.owner.strict {
			b.owner.stopLocked(ErrClosed)
		}
		if !b.owner.closed {
			b.owner.retireLocked(b.slot)
		}
		b.owner.mu.Unlock()
	})
	return b.err
}

// CloseIdleConnections closes current idle sockets without interrupting responses.
// strict ownership also retires admission; concurrent targets remain usable until Close.
func (t *SelectedTransport) CloseIdleConnections() {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	if t.strict {
		t.stopLocked(ErrClosed)
	}
	var idle []*selectedSlot
	for slot := range t.slots {
		if t.strict && slot.cancel != nil {
			slot.cancel()
		}
		if !slot.retiring && slot.client != nil && !slot.upgraded && slot.headers == 0 && slot.client.Err() == nil && slot.client.InFlight() == 0 {
			slot.retiring = true
			t.work.Add(1)
			idle = append(idle, slot)
		}
	}
	t.mu.Unlock()
	for _, slot := range idle {
		t.retire(slot)
	}
}

// Close fences new target work before joining dials and owner cancellation.
// repeated or concurrent closes return the same cleanup failures.
func (t *SelectedTransport) Close() error {
	t.shutdown()
	if t.stopOwner() {
		close(t.ownerDone)
	}
	<-t.ownerDone
	t.work.Wait()
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closeErr
}

func (t *SelectedTransport) shutdown() {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		<-t.shutdownDone
		return
	}
	t.closed = true
	t.stopLocked(ErrClosed)
	var slots []*selectedSlot
	for slot := range t.slots {
		if slot.cancel != nil {
			slot.cancel()
		}
		slots = append(slots, slot)
	}
	t.mu.Unlock()
	// potentially blocking cleanup runs outside the entry fence. concurrent
	// closers join the same completion rather than holding its lock.
	defer close(t.shutdownDone)
	for _, slot := range slots {
		t.closeSlot(slot)
	}
}

func (t *SelectedTransport) closeError(err error) {
	// net/http may already have closed the same socket. do not hide an
	// independent cleanup failure joined with that expected closed result.
	if err != nil && !failure.Only(err, net.ErrClosed) {
		t.mu.Lock()
		t.closeErr = errors.Join(t.closeErr, err)
		t.mu.Unlock()
	}
}

func (t *SelectedTransport) closeSlot(slot *selectedSlot) {
	t.mu.Lock()
	socket, client := slot.socket, slot.client
	slot.socket = nil
	t.mu.Unlock()
	if client != nil {
		// the hook only makes a nonblocking notification. the standard API
		// detaches it here, with no separate callback worker or body ownership.
		client.SetStateHook(nil)
	}
	if socket != nil {
		t.closeError(socket.Close())
	}
	if client != nil {
		t.closeError(client.Close())
	}
}

func (t *SelectedTransport) retireLocked(slot *selectedSlot) {
	if !slot.retiring {
		slot.retiring = true
		t.work.Add(1)
		go t.retire(slot)
	}
}

func (t *SelectedTransport) retire(slot *selectedSlot) {
	defer t.work.Done()
	t.closeSlot(slot)
	t.mu.Lock()
	delete(t.slots, slot)
	t.mu.Unlock()
	t.notify()
}

func (t *SelectedTransport) open(ctx context.Context, cancel context.CancelFunc, slot *selectedSlot, scheme, address string) {
	defer t.work.Done()
	defer cancel()
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		t.mu.Lock()
		if t.currentLocked() != nil {
			t.mu.Unlock()
			return nil, ErrClosed
		}
		t.mu.Unlock()
		conn, err := t.connect(ctx)
		t.mu.Lock()
		stopped := t.currentLocked() != nil
		if !stopped {
			slot.socket = conn
		}
		t.mu.Unlock()
		if stopped {
			if conn != nil {
				t.closeError(conn.Close())
			}
			return nil, ErrClosed
		}
		return conn, err
	}
	transport := &http.Transport{Proxy: nil, DisableCompression: true, MaxResponseHeaderBytes: 64 << 10, ExpectContinueTimeout: time.Second, DialContext: dial, DialTLSContext: dial}
	client, err := transport.NewClientConn(ctx, scheme, address)
	t.mu.Lock()
	if err != nil {
		slot.err = err
		if t.strict {
			t.stopLocked(errors.Join(ErrClosed, err))
		}
	}
	stopped := t.currentLocked() != nil || err != nil
	if !stopped {
		slot.client = client
		client.SetStateHook(func(*http.ClientConn) { t.notify() })
	}
	close(slot.ready)
	t.mu.Unlock()
	if stopped {
		if client != nil {
			client.SetStateHook(nil)
			t.closeError(client.Close())
		}
		t.closeSlot(slot)
		t.mu.Lock()
		delete(t.slots, slot)
		t.mu.Unlock()
	}
	t.notify()
}

// Serve checks each request before the first target dial or any target bytes.
// wrap can serve bounded authentication endpoints without opening the target.
// one failed/closed upstream is final, including on an idempotent HTTP request.
func Serve(ctx context.Context, client net.Conn, target *url.URL, connect func(context.Context) (net.Conn, error), wrap func(http.Handler) http.Handler, hooks ResponseHooks, drain Drain) (result error) {
	if client == nil || target == nil || target.Host == "" || connect == nil || target.Scheme != "http" && target.Scheme != "https" {
		return ErrClosed
	}
	transport, err := NewSelectedTransport(ctx, connect)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, transport.Close()) }()
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
	var cleanupMu sync.Mutex
	var cleanupErr error
	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ServeProxy(proxy, w, r, func(err error) {
			cleanupMu.Lock()
			cleanupErr = errors.Join(cleanupErr, err)
			cleanupMu.Unlock()
		})
	})
	if wrap != nil {
		handler = wrap(handler)
	}
	result = ServeHandler(ctx, client, handler, drain, 0)
	cleanupMu.Lock()
	result = errors.Join(result, cleanupErr)
	cleanupMu.Unlock()
	return result
}

// ServeHandler serves an in-process HTTP application on the admitted visitor
// connection. TLS negotiation is preserved; no target socket or local listener
// is created. completion joins HTTP/1 upgrades and concurrent HTTP/2 handlers.
func ServeHandler(ctx context.Context, client net.Conn, handler http.Handler, drain Drain, requestBodyIdleTimeout time.Duration) (result error) {
	if client == nil || handler == nil || requestBodyIdleTimeout < 0 || (drain.Started == nil) != (drain.Deadline == nil) || drain.Finish != nil && drain.Started == nil {
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
		if drain.Finish != nil {
			result = errors.Join(result, drain.Finish())
		}
	}()
	listener := &singleListener{connection: client, done: make(chan struct{})}
	handler = Requests(observability.PublisherHTTP(handler), requestBodyIdleTimeout)
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
