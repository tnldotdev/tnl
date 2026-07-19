package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestSessionHandshakeAndPublisherStream(t *testing.T) {
	clientTransport, serverTransport := newMemoryPair()
	t.Cleanup(func() { _ = clientTransport.Close() })
	t.Cleanup(func() { _ = serverTransport.Close() })
	hello := publisherHello()

	type accepted struct {
		session *Session
		hello   tunnelv1.Message
		err     error
	}
	serverResult := make(chan accepted, 1)
	go func() {
		session, got, err := Accept(context.Background(), serverTransport, func(_ context.Context, message tunnelv1.Message) error {
			if message.Credential != "credential" {
				return &ProtocolError{Code: tunnelv1.Unauthenticated}
			}
			return nil
		})
		serverResult <- accepted{session: session, hello: got, err: err}
	}()
	client, err := Dial(t.Context(), clientTransport, hello)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	server := <-serverResult
	if server.err != nil {
		t.Fatalf("Accept: %v", server.err)
	}
	if server.hello.Credential != hello.Credential || server.hello.PublisherConnection == nil ||
		*server.hello.PublisherConnection != *hello.PublisherConnection {
		t.Fatalf("accepted hello = %#v; want %#v", server.hello, hello)
	}
	t.Cleanup(func() { _ = server.session.Close() })

	header := publisherStreamHeader()
	routeResult := make(chan error, 1)
	go func() {
		incoming, err := server.session.AcceptPublisherStream(context.Background())
		if err != nil {
			routeResult <- err
			return
		}
		if incoming.Header != header {
			routeResult <- errors.New("unexpected publisher stream header")
			return
		}
		if err := incoming.Accept(); err != nil {
			routeResult <- err
			return
		}
		payload, err := io.ReadAll(io.LimitReader(incoming.Stream, 7))
		if err == nil && string(payload) != "payload" {
			err = errors.New("unexpected route payload")
		}
		routeResult <- err
	}()
	stream, err := client.OpenPublisherStream(t.Context(), header)
	if err != nil {
		t.Fatalf("OpenPublisherStream: %v", err)
	}
	if _, err := stream.Write([]byte("payload")); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := <-routeResult; err != nil {
		t.Fatal(err)
	}
}

func TestSessionRejectsHello(t *testing.T) {
	clientTransport, serverTransport := newMemoryPair()
	serverDone := make(chan error, 1)
	go func() {
		_, _, err := Accept(context.Background(), serverTransport, func(context.Context, tunnelv1.Message) error {
			return &ProtocolError{Code: tunnelv1.StaleConnectionAssignment}
		})
		serverDone <- err
	}()
	_, err := Dial(t.Context(), clientTransport, publisherHello())
	var protocolError *ProtocolError
	if !errors.As(err, &protocolError) || protocolError.Code != tunnelv1.StaleConnectionAssignment {
		t.Fatalf("Dial error = %v; want stale assignment", err)
	}
	if err := <-serverDone; !errors.As(err, &protocolError) || protocolError.Code != tunnelv1.StaleConnectionAssignment {
		t.Fatalf("Accept error = %v; want stale assignment", err)
	}
}

func TestPublisherStreamRejection(t *testing.T) {
	client, server := newAuthenticatedPair(t)
	header := publisherStreamHeader()
	serverDone := make(chan error, 1)
	go func() {
		incoming, err := server.AcceptPublisherStream(context.Background())
		if err == nil {
			err = incoming.Reject(tunnelv1.StaleRouteVersion)
		}
		serverDone <- err
	}()
	_, err := client.OpenPublisherStream(t.Context(), header)
	var protocolError *ProtocolError
	if !errors.As(err, &protocolError) || protocolError.Code != tunnelv1.StaleRouteVersion {
		t.Fatalf("OpenPublisherStream error = %v; want stale route version", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("Reject: %v", err)
	}
}

func TestInternalForwardingStream(t *testing.T) {
	client, server := newAuthenticatedPair(t)
	header := internalForwardingHeader()
	serverDone := make(chan error, 1)
	go func() {
		incoming, err := server.AcceptInternalForwardingStream(context.Background())
		if err != nil {
			serverDone <- err
			return
		}
		if incoming.Header != header {
			serverDone <- errors.New("unexpected internal forwarding header")
			return
		}
		if err := incoming.Accept(); err != nil {
			serverDone <- err
			return
		}
		payload, err := io.ReadAll(io.LimitReader(incoming.Stream, 7))
		if err == nil && string(payload) != "payload" {
			err = errors.New("unexpected internal forwarding payload")
		}
		serverDone <- err
	}()
	stream, err := client.OpenInternalForwardingStream(t.Context(), header)
	if err != nil {
		t.Fatalf("OpenInternalForwardingStream: %v", err)
	}
	if _, err := stream.Write([]byte("payload")); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestSessionPublisherDrainHandshake(t *testing.T) {
	client, server := newAuthenticatedPair(t)
	callbackStarted := make(chan struct{})
	releaseCallback := make(chan struct{})
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- server.HandlePublisherDrain(context.Background(), func(context.Context) error {
			close(callbackStarted)
			<-releaseCallback
			return nil
		})
	}()
	clientDone := make(chan error, 1)
	go func() { clientDone <- client.RequestPublisherDrain(context.Background(), "request_drain_1") }()
	select {
	case <-callbackStarted:
	case <-time.After(time.Second):
		t.Fatal("relay did not begin publisher drain")
	}
	select {
	case err := <-clientDone:
		t.Fatalf("publisher drain returned before relay callback completed: %v", err)
	default:
	}
	close(releaseCallback)
	if err := <-serverDone; err != nil {
		t.Fatalf("HandlePublisherDrain: %v", err)
	}
	if err := <-clientDone; err != nil {
		t.Fatalf("RequestPublisherDrain: %v", err)
	}
}

func TestSessionPublisherDrainRejectsUnexpectedResponses(t *testing.T) {
	for _, test := range []struct {
		name     string
		response tunnelv1.Message
	}{
		{"mismatched request ID", tunnelv1.Message{Type: tunnelv1.Draining, ProtocolVersion: tunnelv1.Version, RequestID: "request_other"}},
		{"unexpected type", tunnelv1.Message{Type: tunnelv1.Drained, ProtocolVersion: tunnelv1.Version, RequestID: "request_drain_1"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, server := newAuthenticatedPair(t)
			serverDone := make(chan error, 1)
			go func() {
				request, err := tunnelv1.ReadControl(server.control)
				if err == nil && (request.Type != tunnelv1.Drain || request.RequestID != "request_drain_1") {
					err = errors.New("unexpected drain request")
				}
				if err == nil {
					err = tunnelv1.WriteControl(server.control, test.response)
				}
				serverDone <- err
			}()
			if err := client.RequestPublisherDrain(t.Context(), "request_drain_1"); err == nil {
				t.Fatal("RequestPublisherDrain accepted an unexpected response")
			}
			if err := <-serverDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSessionPublisherDrainPreservesProtocolError(t *testing.T) {
	client, server := newAuthenticatedPair(t)
	serverDone := make(chan error, 1)
	go func() {
		request, err := tunnelv1.ReadControl(server.control)
		if err == nil {
			err = tunnelv1.WriteControl(server.control, tunnelv1.Message{
				Type: tunnelv1.Error, ProtocolVersion: tunnelv1.Version,
				RequestID: request.RequestID, Code: tunnelv1.Internal,
			})
		}
		serverDone <- err
	}()
	err := client.RequestPublisherDrain(t.Context(), "request_drain_1")
	var protocolError *ProtocolError
	if !errors.As(err, &protocolError) || protocolError.Code != tunnelv1.Internal {
		t.Fatalf("RequestPublisherDrain error = %v; want internal protocol error", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestSessionPublisherDrainCancellationUnblocksRequester(t *testing.T) {
	client, server := newAuthenticatedPair(t)
	drainingSent := make(chan struct{})
	serverDone := make(chan error, 1)
	go func() {
		request, err := tunnelv1.ReadControl(server.control)
		if err == nil {
			err = tunnelv1.WriteControl(server.control, tunnelv1.Message{
				Type: tunnelv1.Draining, ProtocolVersion: tunnelv1.Version, RequestID: request.RequestID,
			})
		}
		if err == nil {
			close(drainingSent)
		}
		serverDone <- err
	}()
	ctx, cancel := context.WithCancel(context.Background())
	clientDone := make(chan error, 1)
	go func() { clientDone <- client.RequestPublisherDrain(ctx, "request_drain_1") }()
	select {
	case <-drainingSent:
	case <-time.After(time.Second):
		t.Fatal("relay did not send draining response")
	}
	cancel()
	select {
	case err := <-clientDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("RequestPublisherDrain error = %v; want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("publisher drain did not unblock on context cancellation")
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestRaceUsesFallbackAfterPrimaryFailure(t *testing.T) {
	var fallbackCalls atomic.Int32
	fallback := authenticatedConnector(t, &fallbackCalls)
	primaryError := errors.New("UDP unavailable")
	primary := muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
		return nil, primaryError
	})
	session, transport, err := Race(
		t.Context(),
		Candidate{Connector: primary, Transport: TransportQUIC},
		Candidate{Connector: fallback, Transport: TransportTLSTCP},
		time.Hour,
		publisherHello(),
	)
	if err != nil {
		t.Fatalf("Race: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	if transport != TransportTLSTCP {
		t.Fatalf("transport = %q; want %q", transport, TransportTLSTCP)
	}
	if fallbackCalls.Load() != 1 {
		t.Fatalf("fallback calls = %d; want 1", fallbackCalls.Load())
	}
}

func TestRaceStopsOnTerminalProtocolError(t *testing.T) {
	var fallbackCalls atomic.Int32
	fallback := authenticatedConnector(t, &fallbackCalls)
	primary := rejectingConnector(t, tunnelv1.Unauthenticated)
	_, _, err := Race(
		t.Context(),
		Candidate{Connector: primary, Transport: TransportQUIC},
		Candidate{Connector: fallback, Transport: TransportTLSTCP},
		time.Hour,
		publisherHello(),
	)
	var protocolError *ProtocolError
	if !errors.As(err, &protocolError) || protocolError.Code != tunnelv1.Unauthenticated {
		t.Fatalf("Race error = %v; want unauthenticated", err)
	}
	if fallbackCalls.Load() != 0 {
		t.Fatalf("fallback calls = %d; want 0", fallbackCalls.Load())
	}
}

func newAuthenticatedPair(t *testing.T) (*Session, *Session) {
	t.Helper()
	clientTransport, serverTransport := newMemoryPair()
	t.Cleanup(func() { _ = clientTransport.Close() })
	t.Cleanup(func() { _ = serverTransport.Close() })
	serverResult := make(chan struct {
		session *Session
		err     error
	}, 1)
	go func() {
		session, _, err := Accept(context.Background(), serverTransport, func(context.Context, tunnelv1.Message) error { return nil })
		serverResult <- struct {
			session *Session
			err     error
		}{session: session, err: err}
	}()
	client, err := Dial(t.Context(), clientTransport, publisherHello())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	result := <-serverResult
	if result.err != nil {
		t.Fatalf("Accept: %v", result.err)
	}
	t.Cleanup(func() { _ = client.Close() })
	t.Cleanup(func() { _ = result.session.Close() })
	return client, result.session
}

func authenticatedConnector(t *testing.T, calls *atomic.Int32) muxsession.Connector {
	t.Helper()
	return muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
		calls.Add(1)
		client, server := newMemoryPair()
		t.Cleanup(func() { _ = server.Close() })
		go func() {
			session, _, err := Accept(context.Background(), server, func(context.Context, tunnelv1.Message) error { return nil })
			if err == nil {
				t.Cleanup(func() { _ = session.Close() })
			}
		}()
		return client, nil
	})
}

func rejectingConnector(t *testing.T, code tunnelv1.ErrorCode) muxsession.Connector {
	t.Helper()
	return muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
		client, server := newMemoryPair()
		t.Cleanup(func() { _ = server.Close() })
		go func() {
			_, _, _ = Accept(context.Background(), server, func(context.Context, tunnelv1.Message) error {
				return &ProtocolError{Code: code}
			})
		}()
		return client, nil
	})
}

func publisherHello() tunnelv1.Message {
	return tunnelv1.Message{
		Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version, Role: tunnelv1.Publisher,
		Credential: "credential",
		PublisherConnection: &tunnelv1.PublisherConnectionRef{
			RouteSessionID: "route_session_1", RouteID: "route_1", RouteVersion: 2,
			PublisherConnectionID: "publisher_connection_1", ConnectionSlot: 0,
			ConnectionAssignmentRevision: 3, RelayServiceID: "relay_service_1",
		},
	}
}

func publisherStreamHeader() tunnelv1.PublisherStreamHeader {
	return tunnelv1.PublisherStreamHeader{
		ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.VisitorStream,
		VisitorConnectionID: "visitor_connection_1", RouteID: "route_1",
		RouteSessionID: "route_session_1", RouteVersion: 2,
		PublisherConnectionID: "publisher_connection_1", ConnectionAssignmentRevision: 3,
	}
}

func internalForwardingHeader() tunnelv1.InternalForwardingHeader {
	now := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	return tunnelv1.InternalForwardingHeader{
		ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.InternalForwardingStream,
		VisitorConnectionID: "visitor_connection_1", RouteID: "route_1",
		RouteSessionID: "route_session_1", RouteVersion: 2,
		PublisherConnectionID: "publisher_connection_1", ConnectionSlot: 0,
		ConnectionAssignmentRevision: 3, RelayServiceID: "relay_service_1",
		RelayID: "relay_1", RelayRunID: "relay_run_1", RelayLeaseRevision: 4,
		RouteExpiresAt: now.Add(time.Minute), LeaseExpiresAt: now.Add(time.Minute),
	}
}

type memorySession struct {
	incoming chan muxsession.Stream
	peer     *memorySession
	done     chan struct{}
	once     sync.Once
}

func newMemoryPair() (*memorySession, *memorySession) {
	left := &memorySession{incoming: make(chan muxsession.Stream, 64), done: make(chan struct{})}
	right := &memorySession{incoming: make(chan muxsession.Stream, 64), done: make(chan struct{})}
	left.peer = right
	right.peer = left
	return left, right
}

func (s *memorySession) OpenStream(ctx context.Context) (muxsession.Stream, error) {
	local, remote := net.Pipe()
	left := &memoryStream{Conn: local}
	right := &memoryStream{Conn: remote}
	select {
	case s.peer.incoming <- right:
		return left, nil
	case <-s.done:
		_ = left.Close()
		_ = right.Close()
		return nil, muxsession.ErrClosed
	case <-s.peer.done:
		_ = left.Close()
		_ = right.Close()
		return nil, muxsession.ErrClosed
	case <-ctx.Done():
		_ = left.Close()
		_ = right.Close()
		return nil, context.Cause(ctx)
	}
}

func (s *memorySession) AcceptStream(ctx context.Context) (muxsession.Stream, error) {
	select {
	case stream := <-s.incoming:
		return stream, nil
	case <-s.done:
		return nil, muxsession.ErrClosed
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	}
}

func (s *memorySession) Close() error {
	s.once.Do(func() { close(s.done) })
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
}

func (s *memoryStream) CloseWrite() error { return errors.ErrUnsupported }

func (s *memoryStream) Reset(uint32) error { return s.Close() }
