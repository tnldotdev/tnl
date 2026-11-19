package muxsession

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"math"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall/js"
	"time"
)

const (
	webSocketBufferedBytes = 1 << 20
	webSocketReadMessages  = 256
	webSocketPollInterval  = 10 * time.Millisecond
)

// the host API exposes neither a native socket nor TLS facts. hiding the yamux
// implementation's AcceptedPeer methods prevents callers from inventing source
// authority from synthetic addresses.
type hostWebSocketSession struct{ Session }

func (c WebSocketConnector) Connect(ctx context.Context, endpoint Endpoint) (Session, error) {
	if cause := context.Cause(ctx); cause != nil {
		return nil, cause
	}
	if c.TLSConfig != nil || c.Config.Dialer != nil || c.Config.DisableProxy {
		return nil, &WebSocketError{Code: "host_options_unsupported", Err: errors.ErrUnsupported}
	}
	host, port, err := net.SplitHostPort(endpoint.Address)
	number, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || number < 1 || number > 65535 ||
		host == "" || !strings.EqualFold(host, endpoint.ServerName) {
		return nil, &WebSocketError{Code: "endpoint_invalid", Err: err}
	}
	address := &url.URL{Scheme: "wss", Host: net.JoinHostPort(host, port), Path: WebSocketPath}
	// reject URL syntax in a purported hostname before invoking the host API.
	parsed, err := url.Parse(address.String())
	if err != nil || parsed.Hostname() != host || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, &WebSocketError{Code: "endpoint_invalid", Err: err}
	}
	network, err := dialHostWebSocket(ctx, address.String())
	if err != nil {
		return nil, err
	}
	var bounded net.Conn = network
	if network.receipts {
		bounded = newYamuxReceiptConn(network)
	}
	session, err := newYamuxSession(bounded, true, c.Config.MaxIncomingStreams)
	if err != nil {
		return nil, err
	}
	if cause := context.Cause(ctx); cause != nil {
		return nil, errors.Join(cause, session.Close())
	}
	return hostWebSocketSession{Session: session}, nil
}

// AcceptWebSocket is native-only: js hosts cannot attest an accepted TCP source
// or enforce the relay's native TLS policy. fail closed and release the input.
func AcceptWebSocket(_ context.Context, network net.Conn, _ *tls.Config, _ WebSocketConfig) (Session, error) {
	var cleanup error
	if network != nil {
		cleanup = network.Close()
	}
	return nil, errors.Join(errors.ErrUnsupported, cleanup)
}

// hostWebSocketNetwork bounds Go-owned receive storage. browser writes use
// bufferedAmount; hosts without it require yamuxReceiptConn before session
// startup. browsers deliver complete messages before Go sees them, so the host's
// own allocation for a single oversized message cannot be bounded here.
type hostWebSocketNetwork struct {
	socket   js.Value
	hooks    map[string]js.Func
	open     chan struct{}
	done     chan struct{}
	released chan struct{}
	wake     chan struct{}
	readMu   sync.Mutex
	writeMu  sync.Mutex
	receipts bool

	mu            sync.Mutex
	err           error
	closeErr      error
	queue         [][]byte
	buffered      int
	readDeadline  time.Time
	writeDeadline time.Time
}

func dialHostWebSocket(ctx context.Context, address string) (*hostWebSocketNetwork, error) {
	constructor := js.Global().Get("WebSocket")
	if constructor.Type() != js.TypeFunction {
		return nil, &WebSocketError{Code: "host_unavailable", Err: errors.ErrUnsupported}
	}
	c := &hostWebSocketNetwork{
		hooks: make(map[string]js.Func), open: make(chan struct{}),
		done: make(chan struct{}), released: make(chan struct{}), wake: make(chan struct{}, 1),
	}
	err := hostWebSocketCall(func() {
		c.socket = constructor.New(address, []any{WebSocketProtocol})
		c.socket.Set("binaryType", "arraybuffer")
	})
	if err != nil {
		if !c.socket.IsUndefined() {
			_ = hostWebSocketCall(func() { c.socket.Call("close") })
		}
		return nil, &WebSocketError{Code: "upgrade_failed", Err: err}
	}
	c.on("open", func(js.Value) {
		if c.socket.Get("protocol").String() != WebSocketProtocol {
			c.finish(&WebSocketError{Code: "subprotocol_invalid"})
			return
		}
		if extensions := c.socket.Get("extensions"); extensions.Type() == js.TypeString && extensions.String() != "" {
			c.finish(&WebSocketError{Code: "extensions_invalid"})
			return
		}
		amount := c.socket.Get("bufferedAmount")
		c.receipts = amount.IsUndefined()
		if !c.receipts && !hostWebSocketCapacity(amount) {
			c.finish(&WebSocketError{Code: "host_send_unsupported", Err: errors.ErrUnsupported})
			return
		}
		close(c.open)
	})
	c.on("message", c.message)
	c.on("error", func(js.Value) { c.finish(&WebSocketError{Code: "host_upgrade_failed"}) })
	c.on("close", func(event js.Value) {
		err := error(io.ErrUnexpectedEOF)
		if code := event.Get("code").Int(); code == 1000 || code == 1001 {
			err = io.EOF
		}
		c.finish(err)
	})
	select {
	case <-c.open:
		if cause := context.Cause(ctx); cause != nil {
			return nil, errors.Join(cause, c.Close())
		}
		return c, nil
	case <-ctx.Done():
		return nil, errors.Join(context.Cause(ctx), c.Close())
	case <-c.done:
		<-c.released
		return nil, errors.Join(c.failure(), c.Close())
	}
}

func (c *hostWebSocketNetwork) on(name string, fn func(js.Value)) {
	hook := js.FuncOf(func(_ js.Value, args []js.Value) any {
		fn(args[0])
		return nil
	})
	c.hooks[name] = hook
	c.socket.Call("addEventListener", name, hook)
}

func (c *hostWebSocketNetwork) message(event js.Value) {
	data := event.Get("data")
	if data.Type() != js.TypeObject || !data.InstanceOf(js.Global().Get("ArrayBuffer")) {
		c.finish(errors.New("muxsession: websocket requires binary ArrayBuffer messages"))
		return
	}
	size := data.Get("byteLength").Int()
	c.mu.Lock()
	if c.err != nil {
		c.mu.Unlock()
		return
	}
	if size < 0 || size > WebSocketMaxBytes || size > webSocketBufferedBytes-c.buffered || len(c.queue) >= webSocketReadMessages {
		c.mu.Unlock()
		c.finish(errors.New("muxsession: websocket receive limit exceeded"))
		return
	}
	// empty messages carry no stream bytes and must not accumulate queue entries.
	if size > 0 {
		p := make([]byte, size)
		js.CopyBytesToGo(p, js.Global().Get("Uint8Array").New(data))
		c.queue = append(c.queue, p)
		c.buffered += size
	}
	c.mu.Unlock()
	c.signal()
}

func (c *hostWebSocketNetwork) finish(err error) {
	c.mu.Lock()
	if c.err != nil {
		c.mu.Unlock()
		return
	}
	c.err = err
	if err != io.EOF {
		c.queue = nil
		c.buffered = 0
	}
	close(c.done)
	c.mu.Unlock()
	// never wait for a close event: hosts may delay or omit it. detach every Go
	// callback before releasing it, including when called from an event handler.
	for name, hook := range c.hooks {
		c.socket.Call("removeEventListener", name, hook)
		hook.Release()
	}
	c.closeErr = hostWebSocketCall(func() { c.socket.Call("close", 1000, "") })
	close(c.released)
}

func (c *hostWebSocketNetwork) failure() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

func (c *hostWebSocketNetwork) signal() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (c *hostWebSocketNetwork) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	for {
		c.mu.Lock()
		err, deadline := c.err, c.readDeadline
		if err == nil && !deadline.IsZero() && !time.Now().Before(deadline) {
			err = os.ErrDeadlineExceeded
		}
		if err != nil && (err != io.EOF || len(c.queue) == 0) {
			c.mu.Unlock()
			return 0, err
		}
		if len(c.queue) > 0 {
			n := copy(p, c.queue[0])
			c.queue[0] = c.queue[0][n:]
			c.buffered -= n
			if len(c.queue[0]) == 0 {
				c.queue[0] = nil
				c.queue = c.queue[1:]
			}
			c.mu.Unlock()
			return n, nil
		}
		c.mu.Unlock()
		var expired <-chan time.Time
		var timer *time.Timer
		if !deadline.IsZero() {
			timer = time.NewTimer(time.Until(deadline))
			expired = timer.C
		}
		select {
		case <-c.wake:
		case <-c.done:
		case <-expired:
		}
		if timer != nil {
			timer.Stop()
		}
	}
}

func (c *hostWebSocketNetwork) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	written := 0
	for len(p) > 0 {
		size := min(len(p), WebSocketMaxBytes)
		for {
			c.mu.Lock()
			err, deadline := c.err, c.writeDeadline
			c.mu.Unlock()
			if err != nil {
				return written, err
			}
			if !deadline.IsZero() && !time.Now().Before(deadline) {
				return written, os.ErrDeadlineExceeded
			}
			var sent bool
			err = hostWebSocketCall(func() {
				if c.socket.Get("readyState").Int() != 1 {
					panic("websocket is not open")
				}
				if !c.receipts {
					amount := c.socket.Get("bufferedAmount")
					if !hostWebSocketCapacity(amount) {
						panic("bufferedAmount unavailable")
					}
					if amount.Float() > float64(webSocketBufferedBytes-size) {
						return
					}
				}
				data := js.Global().Get("Uint8Array").New(size)
				js.CopyBytesToJS(data, p[:size])
				c.socket.Call("send", data)
				sent = true
			})
			if err != nil {
				c.finish(err)
				return written, err
			}
			if sent {
				break
			}
			timer := time.NewTimer(webSocketPollInterval)
			select {
			case <-c.done:
			case <-timer.C:
			}
			timer.Stop()
		}
		written += size
		p = p[size:]
	}
	return written, nil
}

func hostWebSocketCapacity(amount js.Value) bool {
	return amount.Type() == js.TypeNumber && amount.Float() >= 0 &&
		!math.IsNaN(amount.Float()) && !math.IsInf(amount.Float(), 0)
}

func (c *hostWebSocketNetwork) Close() error {
	c.finish(net.ErrClosed)
	<-c.released
	return c.closeErr
}

type hostWebSocketAddr struct{}

func (hostWebSocketAddr) Network() string { return "websocket" }
func (hostWebSocketAddr) String() string  { return "host-managed" }

func (*hostWebSocketNetwork) LocalAddr() net.Addr  { return hostWebSocketAddr{} }
func (*hostWebSocketNetwork) RemoteAddr() net.Addr { return hostWebSocketAddr{} }
func (c *hostWebSocketNetwork) SetDeadline(at time.Time) error {
	return errors.Join(c.SetReadDeadline(at), c.SetWriteDeadline(at))
}
func (c *hostWebSocketNetwork) SetReadDeadline(at time.Time) error {
	c.mu.Lock()
	c.readDeadline = at
	c.mu.Unlock()
	c.signal()
	return nil
}
func (c *hostWebSocketNetwork) SetWriteDeadline(at time.Time) error {
	c.mu.Lock()
	c.writeDeadline = at
	c.mu.Unlock()
	return nil
}

func hostWebSocketCall(fn func()) (err error) {
	defer func() {
		if recover() != nil {
			// JS exception messages can include endpoint URLs or host details.
			err = errors.New("muxsession: host websocket operation failed")
		}
	}()
	fn()
	return nil
}
