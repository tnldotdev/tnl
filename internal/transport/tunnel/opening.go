package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// OpeningError preserves whether initial visitor bytes crossed the retry
// boundary, including a partial write that failed before returning a stream.
type OpeningError struct {
	Committed bool
	Err       error
}

func (e *OpeningError) Error() string { return "start visitor stream: " + e.Err.Error() }
func (e *OpeningError) Unwrap() error { return e.Err }

type ReturnEvents struct {
	Promoted func(tunnelv1.AdmissionHeader) error
	Rejected func(tunnelv1.ErrorCode) error
}

func (s *Session) StartVisitorStream(ctx context.Context, h tunnelv1.VisitorStreamHeader, initial []byte, events *ReturnEvents) (muxsession.Stream, error) {
	h.TraceContext = observability.WireTrace(ctx)
	return s.startStream(ctx, events, func(stream muxsession.Stream) (bool, error) { return tunnelv1.WriteVisitorOpening(stream, h, initial) })
}

// StartConfirmedVisitorStream waits for publisher admission before the relay
// acknowledges ingress. ingress can then try another relay before visitor bytes.
func (s *Session) StartConfirmedVisitorStream(ctx context.Context, h tunnelv1.VisitorStreamHeader, events *ReturnEvents) (muxsession.Stream, error) {
	h.ConfirmBeforeBytes = true
	stream, err := s.StartVisitorStream(ctx, h, nil, events)
	if err != nil {
		return nil, err
	}
	if err := stream.(*returnStream).awaitAccepted(ctx); err != nil {
		return nil, &OpeningError{Err: errors.Join(controlContextError(ctx, err), stream.Close())}
	}
	return stream, nil
}

func (s *Session) StartInternalForwardingStream(ctx context.Context, h tunnelv1.InternalForwardingHeader, proxy, initial []byte, events *ReturnEvents) (muxsession.Stream, error) {
	h.TraceContext = observability.WireTrace(ctx)
	return s.startStream(ctx, events, func(stream muxsession.Stream) (bool, error) {
		return tunnelv1.WriteForwardingOpening(stream, h, proxy, initial)
	})
}

// StartConfirmedInternalForwardingStream sends the opening metadata and waits
// for relay acceptance before sending the initial visitor bytes. use it until
// a new relay session proves it holds the assigned publisher connection.
func (s *Session) StartConfirmedInternalForwardingStream(ctx context.Context, h tunnelv1.InternalForwardingHeader, proxy, initial []byte, events *ReturnEvents) (muxsession.Stream, error) {
	if len(proxy) > tunnelv1.MaxInitialBytes || len(initial) > tunnelv1.MaxInitialBytes-len(proxy) {
		return nil, &OpeningError{Err: errors.New("initial visitor bytes exceed the opening limit")}
	}
	h.ConfirmBeforeBytes = true
	stream, err := s.StartInternalForwardingStream(ctx, h, proxy, nil, events)
	if err != nil {
		return nil, err
	}
	if err := stream.(*returnStream).awaitAccepted(ctx); err != nil {
		return nil, &OpeningError{Err: errors.Join(controlContextError(ctx, err), stream.Close())}
	}
	if len(initial) > 0 {
		finish, err := setupDeadline(ctx, stream)
		if err != nil {
			return nil, &OpeningError{Err: errors.Join(err, stream.Close())}
		}
		n, err := stream.Write(initial)
		if err == nil && n != len(initial) {
			err = io.ErrShortWrite
		}
		err = errors.Join(err, finish(err == nil))
		if err != nil {
			return nil, &OpeningError{Committed: n > 0, Err: errors.Join(controlContextError(ctx, err), stream.Close())}
		}
	}
	return stream, nil
}

func (s *Session) StartServiceForwardingStream(ctx context.Context, h tunnelv1.ServiceForwardingHeader, initial []byte, events *ReturnEvents) (muxsession.Stream, error) {
	h.TraceContext = observability.WireTrace(ctx)
	return s.startStream(ctx, events, func(stream muxsession.Stream) (bool, error) { return tunnelv1.WriteServiceOpening(stream, h, initial) })
}

func (s *Session) startStream(ctx context.Context, events *ReturnEvents, write func(muxsession.Stream) (bool, error)) (result muxsession.Stream, err error) {
	stream, err := s.transport.OpenStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("open visitor stream: %w", err)
	}
	committed := false
	defer func() {
		if err != nil {
			result = nil
			err = &OpeningError{Committed: committed, Err: errors.Join(controlContextError(ctx, err), stream.Close())}
		}
	}()
	finish, err := setupDeadline(ctx, stream)
	if err != nil {
		return nil, err
	}
	committed, err = write(stream)
	err = errors.Join(err, finish(err == nil))
	if err != nil {
		return nil, err
	}
	response := &returnStream{Stream: stream}
	if events != nil {
		response.notify, response.reject = events.Promoted, events.Rejected
	}
	return response, nil
}
