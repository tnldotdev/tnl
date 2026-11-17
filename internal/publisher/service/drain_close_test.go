package service

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type drainFailureTransport struct {
	muxsession.Session
	mu      sync.Mutex
	failure error
}

func (s *drainFailureTransport) OpenStream(ctx context.Context) (muxsession.Stream, error) {
	stream, err := s.Session.OpenStream(ctx)
	if err != nil {
		return nil, err
	}
	return &drainFailureStream{Stream: stream, owner: s}, nil
}

type drainFailureStream struct {
	muxsession.Stream
	owner *drainFailureTransport
}

func (s *drainFailureStream) Write(p []byte) (int, error) {
	s.owner.mu.Lock()
	err := s.owner.failure
	s.owner.mu.Unlock()
	if err != nil {
		return 0, err
	}
	return s.Stream.Write(p)
}

func TestServiceDrainClassifiesWriteFailuresBeforeSessionNotification(t *testing.T) {
	for _, test := range []struct {
		name   string
		cause  error
		closed bool
		cancel bool
	}{
		{"closed socket", errors.Join(muxsession.ErrClosed, net.ErrClosed), true, false},
		{"remote normal QUIC close", errors.Join(muxsession.ErrClosed, &quic.ApplicationError{Remote: true}), true, false},
		{"short write", io.ErrShortWrite, false, false},
		{"rejected", &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}, false, false},
		{"canceled", context.Canceled, false, false},
		{"deadline", context.DeadlineExceeded, false, false},
		{"incomplete response", io.ErrUnexpectedEOF, false, false},
		{"remote QUIC failure", &quic.ApplicationError{ErrorCode: 7, Remote: true}, false, false},
		{"QUIC transport failure", &quic.TransportError{ErrorCode: 1, Remote: true}, false, false},
		{"QUIC idle timeout", &quic.IdleTimeoutError{}, false, false},
		{"QUIC handshake timeout", &quic.HandshakeTimeoutError{}, false, false},
		{"close with rejection", errors.Join(muxsession.ErrClosed, &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}), false, false},
		{"close with cancellation", errors.Join(muxsession.ErrClosed, context.Canceled), false, false},
		{"close with deadline", errors.Join(muxsession.ErrClosed, context.DeadlineExceeded), false, false},
		{"close with short write", errors.Join(muxsession.ErrClosed, io.ErrShortWrite), false, false},
		{"close with cleanup failure", errors.Join(muxsession.ErrClosed, errors.New("independent slot cleanup failed")), false, false},
		{"caller canceled during normal close", errors.Join(muxsession.ErrClosed, net.ErrClosed), false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, bound, _, _ := privateFixture(t, "127.0.0.1:1")
			relay := newPrivateSlotRelay(t, bound, true, nil, nil)
			options := relay.options(t, relay.roots)
			options.PreferWebSocket = true
			connector := options.WebSocket
			var transport *drainFailureTransport
			options.WebSocket = muxsession.ConnectorFunc(func(ctx context.Context, endpoint muxsession.Endpoint) (muxsession.Session, error) {
				outer, err := connector.Connect(ctx, endpoint)
				if err != nil {
					return nil, err
				}
				transport = &drainFailureTransport{Session: outer}
				return transport, nil
			})
			claimed, err := bound.ConnectSlot(t.Context(), 0, options)
			if err != nil {
				t.Fatal(err)
			}
			defer claimed.Close()
			transport.mu.Lock()
			transport.failure = test.cause
			transport.mu.Unlock()
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			want := test.cause
			if test.cancel {
				cancel()
				want = context.Canceled
			}
			err = claimed.Drain(ctx)
			if test.closed && err != nil {
				t.Fatal("normal transport close became a drain failure", err)
			}
			if !test.closed && !errors.Is(err, want) {
				t.Fatal("drain hid an independent failure", err)
			}
			if claimed.session.Err() != nil {
				t.Fatal("fixture exposed session closure before the stream write failure")
			}
		})
	}
}

type delayedDrainTransport struct {
	privateSlotQUICTransport
	notification chan struct{}
}

func (s *delayedDrainTransport) Done() <-chan struct{} { return s.notification }
func (s *delayedDrainTransport) Err() error            { return nil }

func TestServiceDrainObservesRealQUICCloseBeforeSessionNotification(t *testing.T) {
	_, bound, _, _ := privateFixture(t, "127.0.0.1:1")
	relay := newPrivateSlotRelay(t, bound, true, nil, nil)
	options := relay.options(t, relay.roots)
	connector := options.QUIC
	var transport *delayedDrainTransport
	options.QUIC = muxsession.ConnectorFunc(func(ctx context.Context, endpoint muxsession.Endpoint) (muxsession.Session, error) {
		outer, err := connector.Connect(ctx, endpoint)
		if err != nil {
			return nil, err
		}
		transport = &delayedDrainTransport{privateSlotQUICTransport: outer.(privateSlotQUICTransport), notification: make(chan struct{})}
		return transport, nil
	})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	claimed, err := bound.ConnectSlot(ctx, 0, options)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { close(transport.notification); _ = claimed.Close() }()
	relay.stop()
	awaitPrivateSlot(t, transport.privateSlotQUICTransport.Done())
	if claimed.session.Err() != nil {
		t.Fatal("fixture exposed session notification before stream I/O")
	}
	if err := claimed.Drain(ctx); err != nil {
		t.Fatal("normal remote close became a drain failure before session notification", err)
	}
}
