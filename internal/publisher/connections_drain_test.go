package publisher

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"

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
		{name: "closed socket", failure: net.ErrClosed},
		{name: "remote QUIC close", failure: &quic.ApplicationError{Remote: true}},
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
