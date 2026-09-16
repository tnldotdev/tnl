package tunnel

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// This fixture models only session closure and ordered stream delivery. Transport
// half-close/reset behavior is tested against real QUIC and TLS/yamux elsewhere.
type memoryPair struct {
	mu       sync.Mutex
	done     chan struct{}
	closed   bool
	streams  []net.Conn
	deadline time.Time
}
type memorySession struct {
	*memoryPair
	incoming chan muxsession.Stream
	peer     *memorySession
}

func newMemoryPair(t *testing.T) (*memorySession, *memorySession) {
	t.Helper()
	pair := &memoryPair{done: make(chan struct{}), deadline: time.Now().Add(5 * time.Second)}
	left := &memorySession{memoryPair: pair, incoming: make(chan muxsession.Stream, 64)}
	right := &memorySession{memoryPair: pair, incoming: make(chan muxsession.Stream, 64)}
	left.peer, right.peer = right, left
	t.Cleanup(func() { _ = left.Close() })
	return left, right
}
func (s *memorySession) OpenStream(ctx context.Context) (muxsession.Stream, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, muxsession.ErrClosed
	}
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	local, remote := net.Pipe()
	s.streams = append(s.streams, local, remote)
	left, right := &memoryStream{Conn: local, deadline: s.deadline}, &memoryStream{Conn: remote, deadline: s.deadline}
	_ = left.SetDeadline(s.deadline)
	_ = right.SetDeadline(s.deadline)
	select {
	case s.peer.incoming <- right:
		return left, nil
	default:
		_ = local.Close()
		_ = remote.Close()
		return nil, errors.New("memory fixture stream capacity exceeded")
	}
}
func (s *memorySession) AcceptStream(ctx context.Context) (muxsession.Stream, error) {
	select {
	case stream := <-s.incoming:
		if err := s.Err(); err != nil {
			return nil, err
		}
		return stream, nil
	case <-s.done:
		return nil, muxsession.ErrClosed
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	}
}
func (s *memorySession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		close(s.done)
		for _, stream := range s.streams {
			_ = stream.Close()
		}
	}
	return nil
}
func (s *memorySession) Done() <-chan struct{} { return s.done }
func (s *memorySession) Err() error {
	select {
	case <-s.done:
		return muxsession.ErrClosed
	default:
		return nil
	}
}

type memoryStream struct {
	net.Conn
	deadline time.Time
}

func (s *memoryStream) SetDeadline(at time.Time) error {
	if at.IsZero() || at.After(s.deadline) {
		at = s.deadline
	}
	return s.Conn.SetDeadline(at)
}
func (s *memoryStream) CloseWrite() error  { return errors.ErrUnsupported }
func (s *memoryStream) Reset(uint32) error { return s.Close() }

func tunnelContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}
func await[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatal("tunnel worker timed out")
		var zero T
		return zero
	}
}

// Allocate ownership on the test goroutine, before Race starts its workers.
func handshakeConnector(t *testing.T, authenticate AuthenticateFunc) (muxsession.Connector, *memorySession) {
	t.Helper()
	client, server := newMemoryPair(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	started, done := make(chan struct{}), make(chan struct{})
	t.Cleanup(func() { cancel(); _ = server.Close(); await(t, done) })
	go func() {
		defer close(done)
		select {
		case <-started:
		case <-ctx.Done():
			return
		case <-server.Done():
			return
		}
		_, _, _ = Accept(ctx, server, authenticate)
	}()
	var once sync.Once
	return muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
		once.Do(func() { close(started) })
		return client, nil
	}), client
}

func TestMemorySessionClosureUnblocksStreamsAndRejectsOpen(t *testing.T) {
	left, right := newMemoryPair(t)
	stream, err := left.OpenStream(tunnelContext(t))
	if err != nil {
		t.Fatal(err)
	}
	peer, err := right.AcceptStream(tunnelContext(t))
	if err != nil {
		t.Fatal(err)
	}
	_ = left.Close()
	for _, s := range []muxsession.Stream{stream, peer} {
		var timeout net.Error
		if _, err := s.Read(make([]byte, 1)); err == nil || errors.As(err, &timeout) && timeout.Timeout() {
			t.Fatalf("closed session retained a live stream: %v", err)
		}
	}
	for _, s := range []*memorySession{left, right} {
		if _, err := s.OpenStream(tunnelContext(t)); !errors.Is(err, muxsession.ErrClosed) {
			t.Fatalf("open after close: %v", err)
		}
	}
}

func tunnelWorker[T any](t *testing.T, unblock func(), run func() T) <-chan T {
	t.Helper()
	result, done := make(chan T, 1), make(chan struct{})
	t.Cleanup(func() { unblock(); await(t, done) })
	go func() { defer close(done); result <- run() }()
	return result
}

func newAuthenticatedPair(t *testing.T) (*Session, *Session) {
	t.Helper()
	a, b := newMemoryPair(t)
	ctx := tunnelContext(t)
	type accepted struct {
		s   *Session
		err error
	}
	result := tunnelWorker(t, func() { _ = b.Close() }, func() accepted {
		s, _, err := Accept(ctx, b, func(context.Context, tunnelv1.Message) error { return nil })
		return accepted{s, err}
	})
	client, err := Dial(ctx, a, publisherHello())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	server := await(t, result)
	if server.err != nil {
		t.Fatal(server.err)
	}
	t.Cleanup(func() { _ = server.s.Close() })
	return client, server.s
}

func authenticatedConnector(t *testing.T, calls *atomic.Int32) muxsession.Connector {
	t.Helper()
	connector, _ := handshakeConnector(t, func(context.Context, tunnelv1.Message) error { return nil })
	return muxsession.ConnectorFunc(func(ctx context.Context, e muxsession.Endpoint) (muxsession.Session, error) {
		calls.Add(1)
		return connector.Connect(ctx, e)
	})
}
func rejectingConnector(t *testing.T, code tunnelv1.ErrorCode) muxsession.Connector {
	t.Helper()
	connector, _ := handshakeConnector(t, func(context.Context, tunnelv1.Message) error { return &ProtocolError{Code: code} })
	return connector
}
func publisherHello() tunnelv1.Message {
	return tunnelv1.Message{
		Type: tunnelv1.Hello, ProtocolVersion: 1, Role: tunnelv1.Publisher, Credential: "credential",
		PublisherConnection: &tunnelv1.PublisherConnectionRef{
			RouteSessionID: "route_session_1", RouteID: "route_1", RouteVersion: 2,
			PublisherConnectionID: "publisher_connection_1", ConnectionSlot: 0,
			ConnectionAssignmentRevision: 3, RelayServiceID: "relay_service_1",
		},
	}
}
func publisherStreamHeader() tunnelv1.PublisherStreamHeader {
	return tunnelv1.PublisherStreamHeader{
		ProtocolVersion: 1, Kind: tunnelv1.VisitorStream, VisitorConnectionID: "visitor_connection_1",
		RouteID: "route_1", RouteSessionID: "route_session_1", RouteVersion: 2,
		PublisherConnectionID: "publisher_connection_1", ConnectionAssignmentRevision: 3,
	}
}
func internalForwardingHeader() tunnelv1.InternalForwardingHeader {
	now := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	return tunnelv1.InternalForwardingHeader{
		ProtocolVersion: 1, Kind: tunnelv1.InternalForwardingStream, VisitorConnectionID: "visitor_connection_1",
		RouteID: "route_1", RouteSessionID: "route_session_1", RouteVersion: 2,
		PublisherConnectionID: "publisher_connection_1", ConnectionSlot: 0, ConnectionAssignmentRevision: 3,
		RelayServiceID: "relay_service_1", RelayID: "relay_1", RelayRunID: "relay_run_1", RelayLeaseRevision: 4,
		RouteExpiresAt: now.Add(time.Minute), LeaseExpiresAt: now.Add(time.Minute),
	}
}
