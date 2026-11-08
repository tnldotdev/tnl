package publisher

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestPublisherDrainObservesClosedConnectionBeforeSessionNotification(t *testing.T) {
	for _, test := range []struct {
		name        string
		failure     error
		cancel      bool
		wantFailure bool
	}{
		{name: "acknowledged"},
		{name: "closed socket", failure: errors.Join(muxsession.ErrClosed, net.ErrClosed)},
		{name: "remote QUIC close", failure: errors.Join(muxsession.ErrClosed, &quic.ApplicationError{Remote: true})},
		{name: "short write", failure: io.ErrShortWrite, wantFailure: true},
		{name: "rejection", failure: &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}, wantFailure: true},
		{name: "canceled", failure: net.ErrClosed, cancel: true, wantFailure: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			transport := &drainWriteFailureTransport{Session: &certificateTestTransport{done: make(chan struct{})}}
			t.Cleanup(func() { _ = transport.Close() })
			session, err := tunnel.Dial(t.Context(), transport, tunnelv1.Message{
				Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version, Role: tunnelv1.Publisher, Credential: "credential",
				PublisherConnection: &tunnelv1.PublisherConnectionRef{PublicURLID: "public_url", PublishRunID: "publish_run", PublishRunNumber: 1,
					PublisherConnectionID: "connection", ConnectionAssignmentRevision: 1, RelayServiceID: "relay"},
			})
			if err != nil {
				t.Fatal(err)
			}
			// a connection-level write failure can arrive before Done and Err
			// publish the peer's shutdown. do not depend on that notification race.
			transport.failure = test.failure
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if test.cancel {
				cancel()
			}
			slot := &publicPublisherSlot{session: session}
			err = slot.Drain(ctx)
			if !test.wantFailure && err != nil {
				t.Fatal("drain did not finish", err)
			}
			if test.wantFailure {
				want := test.failure
				if test.cancel {
					want = context.Canceled
				}
				if !errors.Is(err, want) {
					t.Fatal("drain lost its failure", err)
				}
			}
			if session.Err() != nil {
				t.Fatal("fixture published session closure before the drain result")
			}
		})
	}
}

// stream i/o can observe closure before the session notification is scheduled.
type delayedDrainNotification struct {
	muxsession.Session
	done chan struct{}
}

func (s delayedDrainNotification) Done() <-chan struct{} { return s.done }
func (s delayedDrainNotification) Err() error            { return nil }

func drainSlotFixture(t *testing.T, ctx context.Context, transport muxsession.Session) *publicPublisherSlot {
	t.Helper()
	ref := tunnelv1.PublisherConnectionRef{PublishRunID: "pr_0123456789abcdefghijkl", PublicURLID: certificateTestPublicURLID, PublishRunNumber: 1,
		PublisherConnectionID: "pc_0123456789abcdefghijkl", ConnectionAssignmentRevision: 1, RelayServiceID: "relay_1"}
	session, err := tunnel.Dial(ctx, transport, tunnelv1.Message{Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version, Role: tunnelv1.Publisher, Credential: "test-credential", PublisherConnection: &ref})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return &publicPublisherSlot{session: session}
}

func TestPublisherSlotDrainObservesQUICCloseBeforeSessionNotification(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	relayCtx, stopRelay := context.WithCancel(ctx)
	defer stopRelay()
	control := newCertificateTestControl(t, "route.example", publicURLCertificateTestPlan())
	connector, relays, _ := drainTestConnections(t, relayCtx, control, "quic")
	transport, err := connector.Connect(ctx, muxsession.Endpoint{Address: control.setup.PublisherConnections[0].RelayAddress, ServerName: "relay.example"})
	if err != nil {
		t.Fatal(err)
	}
	slot := drainSlotFixture(t, ctx, delayedDrainNotification{transport, make(chan struct{})})
	if accepted := awaitPublisherTest(t, relays); accepted.err != nil {
		t.Fatal(accepted.err)
	}
	stopRelay()
	awaitPublisherTest(t, transport.Done())
	if slot.session.Err() != nil {
		t.Fatal("fixture exposed the session notification before stream i/o")
	}
	if err := slot.Drain(ctx); err != nil {
		t.Fatal("remote normal close became a drain failure before session notification", err)
	}
}

type drainWriteFailureTransport struct {
	muxsession.Session
	failure error
}

func (s *drainWriteFailureTransport) OpenStream(ctx context.Context) (muxsession.Stream, error) {
	stream, err := s.Session.OpenStream(ctx)
	if err != nil {
		return nil, err
	}
	return &drainWriteFailureStream{Stream: stream, owner: s}, nil
}

type drainWriteFailureStream struct {
	muxsession.Stream
	owner *drainWriteFailureTransport
}

func (s *drainWriteFailureStream) Write(p []byte) (int, error) {
	if s.owner.failure != nil {
		return 0, s.owner.failure
	}
	return s.Stream.Write(p)
}

func TestPublisherSlotDrainPreservesNonClosureFailures(t *testing.T) {
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded, &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}, io.ErrUnexpectedEOF,
		&quic.ApplicationError{ErrorCode: 7, Remote: true}, &quic.TransportError{ErrorCode: 1, Remote: true}, &quic.IdleTimeoutError{}, &quic.HandshakeTimeoutError{}} {
		t.Run(cause.Error(), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			transport := &drainWriteFailureTransport{Session: &certificateTestTransport{done: make(chan struct{})}}
			slot := drainSlotFixture(t, ctx, transport)
			transport.failure = cause
			if err := slot.Drain(ctx); !errors.Is(err, cause) {
				t.Fatal("drain lost the original failure", err)
			}
		})
	}
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded, &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}} {
		t.Run("joined close/"+cause.Error(), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			transport := &drainWriteFailureTransport{Session: &certificateTestTransport{done: make(chan struct{})}}
			slot := drainSlotFixture(t, ctx, transport)
			transport.failure = errors.Join(muxsession.ErrClosed, cause)
			if err := slot.Drain(ctx); !errors.Is(err, cause) {
				t.Fatal("transport close hid the drain rejection or cancellation", err)
			}
		})
	}
}
