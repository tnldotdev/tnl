package tunnel

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// this fixture models session closure and ordered directional stream delivery.
// transport half-close/reset behavior is tested against real QUIC and WSS/yamux.
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
	localRead, remoteWrite := net.Pipe()
	remoteRead, localWrite := net.Pipe()
	left := &memoryStream{Conn: localRead, writer: localWrite, deadline: s.deadline}
	right := &memoryStream{Conn: remoteRead, writer: remoteWrite, deadline: s.deadline}
	directions := new(sync.Mutex)
	left.directions, right.directions = directions, directions
	left.peer, right.peer = right, left
	s.streams = append(s.streams, left, right)
	_ = left.SetDeadline(s.deadline)
	_ = right.SetDeadline(s.deadline)
	select {
	case s.peer.incoming <- right:
		return left, nil
	default:
		_ = left.Close()
		_ = right.Close()
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
	writer     net.Conn
	deadline   time.Time
	directions *sync.Mutex
	peer       *memoryStream
	readEnded  bool
	writeEnded bool
	closed     bool
}

func (s *memoryStream) SetDeadline(at time.Time) error {
	if at.IsZero() || at.After(s.deadline) {
		at = s.deadline
	}
	return errors.Join(s.SetReadDeadline(at), s.SetWriteDeadline(at))
}

func (s *memoryStream) Write(p []byte) (int, error) {
	if s.writer != nil {
		return s.writer.Write(p)
	}
	return s.Conn.Write(p)
}

func (s *memoryStream) SetWriteDeadline(at time.Time) error {
	if s.writer != nil {
		s.directions.Lock()
		defer s.directions.Unlock()
		if s.writeEnded && !s.closed {
			return nil
		}
		return s.writer.SetWriteDeadline(at)
	}
	return s.Conn.SetWriteDeadline(at)
}

func (s *memoryStream) SetReadDeadline(at time.Time) error {
	if s.writer != nil {
		s.directions.Lock()
		defer s.directions.Unlock()
		// unlike a tcp stream, a net.Pipe endpoint cannot change deadlines
		// after its writer closes. this direction already has a known EOF.
		if s.readEnded && !s.closed {
			return nil
		}
	}
	return s.Conn.SetReadDeadline(at)
}

func (s *memoryStream) CloseWrite() error {
	if s.writer != nil {
		s.directions.Lock()
		defer s.directions.Unlock()
		s.writeEnded = true
		s.peer.readEnded = true
		return s.writer.Close()
	}
	// single-pipe fixtures exercise a bounded read, not directional closure.
	return nil
}

func (s *memoryStream) Close() error {
	var writeErr error
	if s.writer != nil {
		s.directions.Lock()
		defer s.directions.Unlock()
		s.closed = true
		writeErr = s.writer.Close()
	}
	return errors.Join(s.Conn.Close(), writeErr)
}

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

// allocate ownership on the test goroutine before Race starts its workers.
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
		ServiceConnection: &tunnelv1.ServicePublisherConnectionRef{
			ServiceID: "svc_1234567890123456789012", ServiceRunID: "srun_1234567890123456789012", RunNumber: 2,
			PublisherConnectionID: "pc_1234567890123456789012", ConnectionSlot: 0,
			ConnectionAssignmentRevision: 3, RelayServiceID: "relay_service_1"},
	}
}
func serviceStreamHeader() tunnelv1.ServiceForwardingHeader {
	ref := publisherHello().ServiceConnection
	return tunnelv1.ServiceForwardingHeader{
		ServiceStreamHeader: tunnelv1.ServiceStreamHeader{
			ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.ServiceForwardingStream,
			ServiceID: ref.ServiceID, ServiceRunID: ref.ServiceRunID, RunNumber: ref.RunNumber,
			PublisherConnectionID: ref.PublisherConnectionID, ConnectionAssignmentRevision: ref.ConnectionAssignmentRevision,
			VisitorConnectionID: "vc_1234567890123456789012", SourceIP: "192.0.2.1",
			PublicService: &tunnelv1.PublicServiceAdmission{IngressID: "ingress_1", IngressRunID: "ir_1234567890123456789012", IngressLeaseRevision: 4, DestinationPort: 443},
			ExpiresAt:     time.Now().Add(time.Hour).UTC().Truncate(time.Second),
		},
		ConnectionSlot: ref.ConnectionSlot, RelayServiceID: ref.RelayServiceID,
		RelayID: "relay_1", RelayRunID: "rr_1234567890123456789012", RelayLeaseRevision: 4,
		ServingUntil: time.Now().Add(time.Hour).UTC().Truncate(time.Second),
	}
}
