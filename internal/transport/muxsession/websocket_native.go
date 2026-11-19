//go:build !js

package muxsession

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sync"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/net/http/httpproxy"
)

func (c WebSocketConnector) Connect(ctx context.Context, endpoint Endpoint) (Session, error) {
	if c.TLSConfig == nil || c.TLSConfig.InsecureSkipVerify {
		return nil, &WebSocketError{Code: "trust_required"}
	}
	_, port, err := net.SplitHostPort(endpoint.Address)
	if err != nil || endpoint.ServerName == "" {
		return nil, &WebSocketError{Code: "endpoint_invalid", Err: err}
	}
	trust, err := transportTLSConfigForALPN(c.TLSConfig, endpoint.ServerName, false, "http/1.1")
	if err != nil {
		return nil, err
	}
	logical := net.JoinHostPort(endpoint.ServerName, port)
	// net/http derives each TLS hostname from the URL, including HTTPS proxies.
	// a fixed relay ServerName would incorrectly apply to the proxy's TLS hop.
	trust.ServerName = ""
	dialer := c.Config.Dialer
	if dialer == nil {
		dialer = new(net.Dialer)
	}
	transport := &http.Transport{
		TLSClientConfig: trust, ForceAttemptHTTP2: false,
		MaxResponseHeaderBytes: 16 << 10,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address == logical {
				address = endpoint.Address
			}
			return dialer.DialContext(ctx, network, address)
		},
	}
	if !c.Config.DisableProxy {
		proxy := httpproxy.FromEnvironment().ProxyFunc()
		transport.Proxy = func(request *http.Request) (*url.URL, error) { return proxy(request.URL) }
	}
	defer transport.CloseIdleConnections()
	var accepted net.Conn
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { accepted = info.Conn }})
	connection, response, err := websocket.Dial(ctx, (&url.URL{Scheme: "wss", Host: logical, Path: WebSocketPath}).String(), &websocket.DialOptions{
		HTTPClient:   &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		Subprotocols: []string{WebSocketProtocol}, CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		status := 0
		if response != nil {
			status = response.StatusCode
			if response.Body != nil {
				_ = response.Body.Close()
			}
		}
		return nil, &WebSocketError{Code: "upgrade_failed", Status: status, Err: err}
	}
	if connection.Subprotocol() != WebSocketProtocol {
		_ = connection.CloseNow()
		return nil, &WebSocketError{Code: "subprotocol_invalid"}
	}
	return newWebSocketSession(ctx, connection, accepted, true, c.Config.MaxIncomingStreams)
}

// AcceptWebSocket owns one accepted socket through TLS, HTTP upgrade and yamux.
// net/http parses the bounded handshake; after hijacking the returned session
// owns the socket. setup cancellation never becomes an established lifetime.
func AcceptWebSocket(ctx context.Context, network net.Conn, config *tls.Config, options WebSocketConfig) (_ Session, result error) {
	if network == nil {
		return nil, &WebSocketError{Code: "socket_required"}
	}
	owned := false
	defer func() {
		if !owned {
			_ = network.Close()
		}
	}()
	trust, err := webSocketServerTLSConfig(config)
	if err != nil {
		return nil, err
	}
	secure := tls.Server(network, trust)
	if err := secure.HandshakeContext(ctx); err != nil {
		return nil, &WebSocketError{Code: "tls_failed", Err: err}
	}
	listener := &webSocketHandshakeListener{connection: secure, done: make(chan struct{})}
	stop := context.AfterFunc(ctx, func() { _ = network.Close(); _ = listener.Close() })
	defer stop()
	var session Session
	var upgradeErr error
	finished := make(chan struct{})
	var finishOnce sync.Once
	finish := func() { finishOnce.Do(func() { close(finished) }) }
	server := &http.Server{
		ReadHeaderTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second,
		MaxHeaderBytes: 16 << 10, ErrorLog: log.New(io.Discard, "", 0),
		ConnState: func(_ net.Conn, state http.ConnState) {
			if state == http.StateClosed {
				_ = listener.Close()
				finish()
			}
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer finish()
			defer listener.Close()
			host := r.Host
			if name, _, err := net.SplitHostPort(host); err == nil {
				host = name
			}
			serverName := secure.ConnectionState().ServerName
			// TLS omits SNI for literal IP addresses.
			matchesHost := host == serverName || serverName == "" && net.ParseIP(host) != nil
			if r.Method != http.MethodGet || r.URL.Path != WebSocketPath || r.URL.RawQuery != "" ||
				!matchesHost || r.ContentLength > 0 || len(r.TransferEncoding) != 0 ||
				r.Header.Get("Sec-WebSocket-Protocol") != WebSocketProtocol {
				http.Error(w, "invalid relay websocket request", http.StatusBadRequest)
				_ = http.NewResponseController(w).Flush()
				upgradeErr = &WebSocketError{Code: "request_invalid", Status: http.StatusBadRequest}
				return
			}
			connection, err := websocket.Accept(w, r, &websocket.AcceptOptions{
				Subprotocols: []string{WebSocketProtocol}, CompressionMode: websocket.CompressionDisabled,
				// cookies and Origin grant no authority; every client must supply
				// the existing signed or credential-bearing tnl hello.
				InsecureSkipVerify: true,
			})
			if err != nil {
				_ = http.NewResponseController(w).Flush()
				upgradeErr = &WebSocketError{Code: "upgrade_failed", Err: err}
				return
			}
			session, upgradeErr = newWebSocketSession(ctx, connection, secure, false, options.MaxIncomingStreams)
		}),
	}
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = server.Serve(listener)
	}()
	select {
	case <-finished:
	case <-ctx.Done():
		_ = server.Close()
		_ = listener.Close()
		<-served
		// a connection accepted before cancellation still has an owned handler.
		if listener.used {
			<-finished
		}
		if session != nil {
			_ = session.Close()
		}
		return nil, context.Cause(ctx)
	}
	<-served
	if upgradeErr != nil {
		return nil, upgradeErr
	}
	if session == nil {
		return nil, &WebSocketError{Code: "upgrade_failed"}
	}
	if !stop() {
		_ = session.Close()
		return nil, context.Cause(ctx)
	}
	owned = true
	return session, nil
}

// only the outer WSS server permits platform TLS key agreement. native clients
// still offer hybrid only; QUIC and inner peer TLS retain RequirePostQuantum.
// clone dynamic certificate configurations too, without changing their owners.
func webSocketServerTLSConfig(config *tls.Config) (*tls.Config, error) {
	if config == nil {
		return nil, errors.New("muxsession: TLS configuration is required")
	}
	result := config.Clone()
	result.MinVersion = tls.VersionTLS13
	result.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256, tls.CurveP384}
	result.NextProtos = []string{"http/1.1"}
	if selectConfig := config.GetConfigForClient; selectConfig != nil {
		result.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			selected, err := selectConfig(hello)
			if selected == nil || err != nil {
				return nil, err
			}
			return webSocketServerTLSConfig(selected)
		}
	}
	return result, nil
}

// the HTTP server accepts exactly one connection; closing this listener does not
// close the hijacked socket. the session, not HTTP shutdown, owns that socket.
type webSocketHandshakeListener struct {
	connection net.Conn
	done       chan struct{}
	once       sync.Once
	used       bool
}

func (l *webSocketHandshakeListener) Accept() (net.Conn, error) {
	if !l.used {
		l.used = true
		return l.connection, nil
	}
	<-l.done
	return nil, net.ErrClosed
}
func (l *webSocketHandshakeListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *webSocketHandshakeListener) Addr() net.Addr { return l.connection.LocalAddr() }

type webSocketNetwork struct {
	net.Conn
	websocket *websocket.Conn
	peer      net.Conn
}

func (c *webSocketNetwork) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		n, err := c.Conn.Write(p[:min(len(p), WebSocketMaxBytes)])
		written += n
		p = p[n:]
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

func (c *webSocketNetwork) Close() error {
	// abort the socket before TLS close-notify or the websocket close handshake.
	// CloseNow then joins the websocket's readers and writers.
	if secure, ok := c.peer.(*tls.Conn); ok {
		_ = secure.NetConn().Close()
	}
	err := c.websocket.CloseNow()
	_ = c.Conn.Close() // stop NetConn's deadline timers after the socket is closed
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
func (c *webSocketNetwork) LocalAddr() net.Addr  { return c.peer.LocalAddr() }
func (c *webSocketNetwork) RemoteAddr() net.Addr { return c.peer.RemoteAddr() }
func (c *webSocketNetwork) TLSConnectionState() tls.ConnectionState {
	if peer, ok := c.peer.(*tls.Conn); ok {
		return peer.ConnectionState()
	}
	return tls.ConnectionState{}
}

func newWebSocketSession(ctx context.Context, connection *websocket.Conn, peer net.Conn, client bool, maxStreams int) (Session, error) {
	if peer == nil {
		_ = connection.CloseNow()
		return nil, &WebSocketError{Code: "peer_required"}
	}
	network := websocket.NetConn(context.WithoutCancel(ctx), connection, websocket.MessageBinary)
	_ = peer.SetDeadline(time.Time{})
	// NetConn disables the library's read limit during construction.
	connection.SetReadLimit(WebSocketMaxBytes)
	session, err := newYamuxSession(&webSocketNetwork{Conn: network, websocket: connection, peer: peer}, client, maxStreams)
	if err != nil {
		return nil, errors.Join(err, connection.CloseNow())
	}
	return session, nil
}
