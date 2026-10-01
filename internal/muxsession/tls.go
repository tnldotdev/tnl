package muxsession

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	yamux "github.com/libp2p/go-yamux/v5"
)

const defaultMaxIncomingStreams = 4096

// FIN/RST queueing in yamux ignores stream deadlines. if even a control
// frame cannot be queued within this interval, abort the owned transport.
const streamCloseTimeout = time.Second

var errStreamCleanupBlocked = errors.New("muxsession: stream cleanup blocked transport writer")

// TLSYamuxConfig configures the raw TLS/TCP plus yamux transport.
type TLSYamuxConfig struct {
	MaxIncomingStreams int
	Dialer             *net.Dialer
}

// TLSYamuxConnector establishes raw TLS/TCP plus yamux sessions.
type TLSYamuxConnector struct {
	TLSConfig *tls.Config
	Config    TLSYamuxConfig
}

func (c TLSYamuxConnector) Connect(ctx context.Context, endpoint Endpoint) (Session, error) {
	if endpoint.Address == "" || endpoint.ServerName == "" {
		return nil, errors.New("muxsession: TLS/yamux endpoint requires address and server name")
	}
	tlsConfig, err := transportTLSConfig(c.TLSConfig, endpoint.ServerName, false)
	if err != nil {
		return nil, err
	}
	dialer := c.Config.Dialer
	if dialer == nil {
		dialer = new(net.Dialer)
	}
	network, err := dialer.DialContext(ctx, "tcp", endpoint.Address)
	if err != nil {
		return nil, fmt.Errorf("muxsession: dial TLS/yamux: %w", err)
	}
	secure := tls.Client(network, tlsConfig)
	if err := secure.HandshakeContext(ctx); err != nil {
		_ = network.Close()
		return nil, fmt.Errorf("muxsession: TLS/yamux handshake: %w", err)
	}
	if err := requireALPN(secure.ConnectionState()); err != nil {
		_ = secure.Close()
		return nil, err
	}
	return newYamuxSession(secure, true, c.Config.MaxIncomingStreams)
}

// AcceptTLSYamux authenticates an accepted TCP connection and starts yamux.
// the caller must dispatch by SNI before calling this function when TCP 443
// is shared with visitor ingress.
func AcceptTLSYamux(
	ctx context.Context,
	network net.Conn,
	tlsConfig *tls.Config,
	config TLSYamuxConfig,
) (Session, error) {
	if network == nil {
		return nil, errors.New("muxsession: accepted TLS/yamux connection is nil")
	}
	serverConfig, err := transportTLSConfig(tlsConfig, "", true)
	if err != nil {
		_ = network.Close()
		return nil, err
	}
	secure := tls.Server(network, serverConfig)
	if err := secure.HandshakeContext(ctx); err != nil {
		_ = network.Close()
		return nil, fmt.Errorf("muxsession: accept TLS/yamux handshake: %w", err)
	}
	if err := requireALPN(secure.ConnectionState()); err != nil {
		_ = secure.Close()
		return nil, err
	}
	return newYamuxSession(secure, false, config.MaxIncomingStreams)
}

func transportTLSConfig(config *tls.Config, serverName string, server bool) (*tls.Config, error) {
	if config == nil {
		return nil, errors.New("muxsession: TLS configuration is required")
	}
	result := config.Clone()
	result.MinVersion = tls.VersionTLS13
	result.NextProtos = []string{ALPN}
	if !server {
		result.ServerName = serverName
	}
	return result, nil
}

func requireALPN(state tls.ConnectionState) error {
	if state.NegotiatedProtocol != ALPN {
		return fmt.Errorf("muxsession: negotiated ALPN %q; want %q", state.NegotiatedProtocol, ALPN)
	}
	return nil
}

func yamuxConfig(maxIncoming int) *yamux.Config {
	if maxIncoming <= 0 {
		maxIncoming = defaultMaxIncomingStreams
	}
	config := yamux.DefaultConfig()
	config.AcceptBacklog = min(maxIncoming, 256)
	config.MaxIncomingStreams = uint32(maxIncoming)
	config.InitialStreamWindowSize = 256 << 10
	config.MaxStreamWindowSize = 1 << 20
	config.MaxMessageSize = 64 << 10
	config.ConnectionWriteTimeout = 10 * time.Second
	config.KeepAliveInterval = 30 * time.Second
	config.LogOutput = io.Discard
	return config
}

type acceptResult struct {
	stream Stream
	err    error
}

type yamuxSession struct {
	session   *yamux.Session
	network   net.Conn
	accepted  chan acceptResult
	done      <-chan struct{}
	closeOnce sync.Once
	closeErr  error

	mu       sync.Mutex
	err      error
	abortErr error
}

func newYamuxSession(network net.Conn, client bool, maxIncoming int) (Session, error) {
	var (
		session *yamux.Session
		err     error
	)
	if client {
		session, err = yamux.Client(network, yamuxConfig(maxIncoming), nil)
	} else {
		session, err = yamux.Server(network, yamuxConfig(maxIncoming), nil)
	}
	if err != nil {
		_ = network.Close()
		return nil, fmt.Errorf("muxsession: start yamux: %w", err)
	}
	result := &yamuxSession{
		session:  session,
		network:  network,
		accepted: make(chan acceptResult),
		done:     session.CloseChan(),
	}
	go result.acceptLoop()
	return result, nil
}

func (s *yamuxSession) OpenStream(ctx context.Context) (Stream, error) {
	stream, err := s.session.OpenStream(ctx)
	if err != nil {
		s.recordError(err)
		return nil, normalizeYamuxError(err)
	}
	return &yamuxStream{Stream: stream, owner: s}, nil
}

func (s *yamuxSession) AcceptStream(ctx context.Context) (Stream, error) {
	select {
	case result := <-s.accepted:
		return result.stream, result.err
	case <-s.done:
		return nil, ErrClosed
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	}
}

func (s *yamuxSession) Close() error {
	s.closeOnce.Do(func() {
		// close the socket before TLS close-notify or yamux cleanup can block
		// behind a write. session shutdown joins its I/O loops.
		network := s.network
		if secure, ok := network.(*tls.Conn); ok {
			network = secure.NetConn()
		}
		err := network.Close()
		if errors.Is(err, net.ErrClosed) {
			err = nil
		}
		s.closeErr = normalizeYamuxError(errors.Join(err, s.session.Close()))
		s.recordError(s.closeErr)
	})
	return s.closeErr
}

func (s *yamuxSession) Done() <-chan struct{} { return s.done }

func (s *yamuxSession) Err() error {
	select {
	case <-s.done:
	default:
		return nil
	}
	s.mu.Lock()
	abortErr := s.abortErr
	recorded := s.err
	s.mu.Unlock()
	if abortErr != nil {
		return abortErr
	}
	// a closed yamux session reports its reason even if the accept loop has
	// not yet observed the close.
	_, err := s.session.OpenStream(context.Background())
	if err != nil {
		return normalizeYamuxError(err)
	}
	if recorded != nil {
		return normalizeYamuxError(recorded)
	}
	return ErrClosed
}

func (s *yamuxSession) acceptLoop() {
	for {
		stream, err := s.session.AcceptStream()
		if err != nil {
			s.recordError(err)
			return
		}
		select {
		case s.accepted <- acceptResult{stream: &yamuxStream{Stream: stream, owner: s}}:
		case <-s.done:
			_ = stream.Close()
			return
		}
	}
}

func (s *yamuxSession) recordError(err error) {
	if err == nil {
		return
	}
	s.mu.Lock()
	if s.err == nil {
		s.err = err
	}
	s.mu.Unlock()
}

func (s *yamuxSession) recordAbort(err error) {
	s.mu.Lock()
	s.abortErr = err
	s.mu.Unlock()
}

func normalizeYamuxError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, yamux.ErrSessionShutdown) ||
		errors.Is(err, yamux.ErrRemoteGoAway) ||
		errors.Is(err, yamux.ErrStreamClosed) {
		return ErrClosed
	}
	return normalizeClosed(err)
}

type yamuxStream struct {
	*yamux.Stream
	owner *yamuxSession
}

func (s *yamuxStream) Close() error {
	return s.closeBounded(s.Stream.Close)
}

func (s *yamuxStream) CloseWrite() error {
	return s.closeBounded(s.Stream.CloseWrite)
}

func (s *yamuxStream) Reset(code uint32) error {
	return s.closeBounded(func() error { return s.Stream.ResetWithError(code) })
}

func (s *yamuxStream) closeBounded(closeStream func() error) error {
	done := make(chan struct{})
	var abortErr error
	timer := time.AfterFunc(streamCloseTimeout, func() {
		s.owner.recordAbort(errStreamCleanupBlocked)
		abortErr = errors.Join(errStreamCleanupBlocked, s.owner.Close())
		close(done)
	})
	err := closeStream()
	if !timer.Stop() {
		<-done
	}
	return errors.Join(normalizeYamuxError(err), abortErr)
}
