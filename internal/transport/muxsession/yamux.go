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
	"github.com/tnldotdev/tnl/internal/security/tlspolicy"
)

const defaultMaxIncomingStreams = 4096

// FIN/RST queueing in yamux ignores stream deadlines. if even a control
// frame cannot be queued within this interval, abort the owned transport.
const streamCloseTimeout = time.Second

var errStreamCleanupBlocked = errors.New("muxsession: stream cleanup blocked transport writer")

func transportTLSConfig(config *tls.Config, serverName string, server bool) (*tls.Config, error) {
	return transportTLSConfigForALPN(config, serverName, server, ALPN)
}

func transportTLSConfigForALPN(config *tls.Config, serverName string, server bool, alpn string) (*tls.Config, error) {
	if config == nil {
		return nil, errors.New("muxsession: TLS configuration is required")
	}
	result := tlspolicy.RequirePostQuantum(config)
	result.NextProtos = []string{alpn}
	if !server {
		result.ServerName = serverName
	}
	return result, nil
}

func requireTransportALPN(state tls.ConnectionState, alpn string) error {
	if state.NegotiatedProtocol != alpn {
		return fmt.Errorf("muxsession: negotiated ALPN %q; want %q", state.NegotiatedProtocol, alpn)
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
	session    *yamux.Session
	network    net.Conn
	owned      *yamuxNetwork
	accepted   chan acceptResult
	acceptDone chan struct{}
	done       <-chan struct{}
	closeOnce  sync.Once
	closeErr   error

	mu       sync.Mutex
	err      error
	abortErr error
}

func newYamuxSession(network net.Conn, client bool, maxIncoming int) (Session, error) {
	var (
		session *yamux.Session
		err     error
	)
	// yamux closes its connection from inside the failed writer before publishing
	// shutdown. TLS close-notify can block there and make OpenStream ignore its
	// context while waiting for shutdown; close the owned socket without an alert.
	owned := &yamuxNetwork{Conn: network}
	if client {
		session, err = yamux.Client(owned, yamuxConfig(maxIncoming), nil)
	} else {
		session, err = yamux.Server(owned, yamuxConfig(maxIncoming), nil)
	}
	if err != nil {
		_ = owned.Close()
		return nil, fmt.Errorf("muxsession: start yamux: %w", err)
	}
	result := &yamuxSession{
		session:    session,
		network:    network,
		owned:      owned,
		accepted:   make(chan acceptResult),
		acceptDone: make(chan struct{}),
		done:       session.CloseChan(),
	}
	go result.acceptLoop()
	return result, nil
}

type yamuxNetwork struct {
	net.Conn
	closeOnce sync.Once
	closeErr  error
}

func (c *yamuxNetwork) Close() error {
	c.closeOnce.Do(func() {
		network := c.Conn
		if secure, ok := network.(*tls.Conn); ok {
			network = secure.NetConn()
		}
		c.closeErr = socketCloseError(network.Close())
	})
	return c.closeErr
}

func socketCloseError(err error) error {
	for leaf := err; leaf != nil; leaf = errors.Unwrap(leaf) {
		if leaf == net.ErrClosed {
			return nil
		}
		if timeout, ok := leaf.(net.Error); ok && timeout.Timeout() {
			break
		}
	}
	return err
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
		// let yamux publish its local shutdown reason before its abortive
		// socket close wakes the reader. yamux joins I/O but discards the
		// result of closing the socket; read that result from the owner.
		s.closeErr = errors.Join(s.session.Close(), s.owned.Close())
		<-s.acceptDone
		s.recordError(s.closeErr)
	})
	return s.closeErr
}

func (s *yamuxSession) Done() <-chan struct{} { return s.done }

func (s *yamuxSession) LocalAddr() net.Addr  { return s.network.LocalAddr() }
func (s *yamuxSession) RemoteAddr() net.Addr { return s.network.RemoteAddr() }
func (s *yamuxSession) TLSConnectionState() tls.ConnectionState {
	if secure, ok := s.network.(interface{ TLSConnectionState() tls.ConnectionState }); ok {
		return secure.TLSConnectionState()
	}
	if secure, ok := s.network.(*tls.Conn); ok {
		return secure.ConnectionState()
	}
	return tls.ConnectionState{}
}

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
	defer close(s.acceptDone)
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

// JoinedLocalClose reports an I/O result from explicit local shutdown after
// the stream's socket and workers have closed without error. only yamux
// currently provides this evidence; peer resets are not local close results.
func JoinedLocalClose(stream Stream, err error) bool {
	s, ok := stream.(*yamuxStream)
	if !ok || err != yamux.ErrSessionShutdown {
		return false
	}
	select {
	case <-s.owner.Done():
	default:
		return false
	}
	if s.owner.Close() != nil {
		return false
	}
	s.owner.mu.Lock()
	aborted := s.owner.abortErr != nil
	s.owner.mu.Unlock()
	// a failing yamux writer can publish its own reason before a concurrent
	// local close stops the streams. inspect the unnormalized session reason.
	_, reason := s.owner.session.OpenStream(context.Background())
	return !aborted && reason == yamux.ErrSessionShutdown
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
