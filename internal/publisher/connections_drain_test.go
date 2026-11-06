package publisher

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

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

type drainWriteFailure struct {
	muxsession.Session
	failure error
}

func (s *drainWriteFailure) OpenStream(ctx context.Context) (muxsession.Stream, error) {
	stream, err := s.Session.OpenStream(ctx)
	return &drainFailureStream{Stream: stream, owner: s}, err
}

type drainFailureStream struct {
	muxsession.Stream
	owner *drainWriteFailure
}

func (s *drainFailureStream) Write(b []byte) (int, error) {
	if err := s.owner.failure; err != nil {
		return 0, err
	}
	return s.Stream.Write(b)
}

func TestPublisherSlotDrainPreservesNonClosureFailures(t *testing.T) {
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded, &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}, io.ErrUnexpectedEOF} {
		t.Run(cause.Error(), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			transport := &drainWriteFailure{Session: &certificateTestTransport{done: make(chan struct{})}}
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
			transport := &drainWriteFailure{Session: &certificateTestTransport{done: make(chan struct{})}}
			slot := drainSlotFixture(t, ctx, transport)
			transport.failure = errors.Join(muxsession.ErrClosed, cause)
			if err := slot.Drain(ctx); !errors.Is(err, cause) {
				t.Fatal("transport close hid the drain rejection or cancellation", err)
			}
		})
	}
}
