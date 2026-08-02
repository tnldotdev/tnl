package relay

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestForwardingAcceptorCancellationClosesActiveStreams(t *testing.T) {
	secrets, err := serviceapi.NewBearerSecrets(strings.Repeat("s", 32), "")
	if err != nil {
		t.Fatal(err)
	}
	acceptor, err := NewForwardingAcceptor(ForwardingAcceptorConfig{
		Registry: NewRegistry(), ClusterSecrets: secrets, StreamCapacity: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	controlServer, controlClient := net.Pipe()
	t.Cleanup(func() { _ = controlServer.Close(); _ = controlClient.Close() })
	forwardServer, forwardClient := net.Pipe()
	t.Cleanup(func() { _ = forwardServer.Close(); _ = forwardClient.Close() })
	for _, c := range []net.Conn{controlServer, controlClient, forwardServer, forwardClient} {
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	}
	t.Cleanup(func() {
		_ = controlClient.Close()
		_ = forwardClient.Close()
	})
	writeStarted := make(chan struct{})
	transport := newForwardingTestSession(
		&forwardingTestStream{Conn: controlServer},
		&forwardingTestStream{Conn: forwardServer, writeStarted: writeStarted},
	)
	t.Cleanup(func() { _ = transport.Close() })

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	result := relayWorker(t, func() { cancel(); _ = transport.Close() }, func() error { return acceptor.Accept(ctx, transport) })

	controlResult := relayWorker(t, func() { _ = controlClient.Close() }, func() error {
		if err := tunnelv1.WriteControl(controlClient, tunnelv1.Message{
			Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version,
			Role: tunnelv1.Ingress, Credential: strings.Repeat("s", 32),
		}); err != nil {
			return err
		}
		_, err := tunnelv1.ReadControl(controlClient)
		return err
	})
	if err := relayAwait(t, controlResult); err != nil {
		t.Fatal(err)
	}

	headerResult := relayWorker(t, func() { _ = forwardClient.Close() }, func() error {
		now := time.Now()
		return tunnelv1.WriteInternalForwardingHeader(forwardClient, tunnelv1.InternalForwardingHeader{
			ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.InternalForwardingStream,
			VisitorConnectionID: "visitor", RouteID: "route", RouteSessionID: "session", RouteVersion: 1,
			PublisherConnectionID: "connection", ConnectionSlot: 0, ConnectionAssignmentRevision: 1,
			RelayServiceID: "relay-service", RelayID: "relay", RelayRunID: "relay-run", RelayLeaseRevision: 1,
			RouteExpiresAt: now.Add(time.Minute), LeaseExpiresAt: now.Add(time.Minute),
		})
	})
	if err := relayAwait(t, headerResult); err != nil {
		t.Fatal(err)
	}
	select {
	case <-writeStarted:
	case <-time.After(time.Second):
		t.Fatal("forwarding rejection did not start")
	}

	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("forwarding acceptor did not close its session before waiting for active streams")
	}
}

type forwardingTestSession struct {
	incoming chan muxsession.Stream
	done     chan struct{}
	streams  []muxsession.Stream
	once     sync.Once
}

func newForwardingTestSession(streams ...muxsession.Stream) *forwardingTestSession {
	incoming := make(chan muxsession.Stream, len(streams))
	for _, stream := range streams {
		incoming <- stream
	}
	return &forwardingTestSession{incoming: incoming, done: make(chan struct{}), streams: streams}
}

func (s *forwardingTestSession) OpenStream(context.Context) (muxsession.Stream, error) {
	return nil, errors.ErrUnsupported
}

func (s *forwardingTestSession) AcceptStream(ctx context.Context) (muxsession.Stream, error) {
	select {
	case stream := <-s.incoming:
		return stream, nil
	case <-s.done:
		return nil, muxsession.ErrClosed
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	}
}

func (s *forwardingTestSession) Close() error {
	s.once.Do(func() {
		close(s.done)
		for _, stream := range s.streams {
			_ = stream.Close()
		}
	})
	return nil
}

func (s *forwardingTestSession) Done() <-chan struct{} { return s.done }

func (s *forwardingTestSession) Err() error {
	select {
	case <-s.done:
		return muxsession.ErrClosed
	default:
		return nil
	}
}

type forwardingTestStream struct {
	net.Conn
	writeStarted chan struct{}
	once         sync.Once
}

func (s *forwardingTestStream) Write(data []byte) (int, error) {
	if s.writeStarted != nil {
		s.once.Do(func() { close(s.writeStarted) })
	}
	return s.Conn.Write(data)
}

func (s *forwardingTestStream) CloseWrite() error { return errors.ErrUnsupported }

func (s *forwardingTestStream) Reset(uint32) error { return s.Close() }
