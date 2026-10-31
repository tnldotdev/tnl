package tunnel

import (
	"context"
	"errors"
	"io"

	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// OpeningError retains the exact retry boundary even when no stream is returned.
// VisitorBytes excludes framing and, on ingress openings, PROXY metadata.
type OpeningError struct {
	Committed    bool
	VisitorBytes int64
	Err          error
}

func (e *OpeningError) Error() string { return "open visitor stream: " + e.Err.Error() }
func (e *OpeningError) Unwrap() error { return e.Err }

func (s *Session) OpenVisitorStream(ctx context.Context, h tunnelv1.VisitorStreamHeader, initial []byte, events ReturnEvents) (muxsession.Stream, error) {
	h.TraceContext = observability.WireTrace(ctx)
	return s.openStream(ctx, h.ConfirmBeforeBytes, events, func(w muxsession.Stream) (int, error) { return tunnelv1.WriteVisitorOpening(w, h, initial) }, nil)
}

// confirmation is one phase of the same opening. only an unconfirmed exact
// session/assignment sends metadata first; subsequent openings carry the prefix.
func (s *Session) OpenInternalForwardingStream(ctx context.Context, h tunnelv1.InternalForwardingHeader, proxy, initial []byte, events ReturnEvents) (muxsession.Stream, error) {
	if len(proxy) > tunnelv1.MaxInitialBytes || len(initial) > tunnelv1.MaxInitialBytes-len(proxy) {
		return nil, &OpeningError{Err: tunnelv1.ErrOpeningSize}
	}
	h.TraceContext = observability.WireTrace(ctx)
	first, after := initial, []byte(nil)
	if h.ConfirmBeforeBytes {
		first, after = nil, initial
	}
	return s.openStream(ctx, h.ConfirmBeforeBytes, events, func(w muxsession.Stream) (int, error) { return tunnelv1.WriteForwardingOpening(w, h, proxy, first) }, after)
}

// private service openings retain their metadata-only acceptance boundary.
func (s *Session) OpenServiceForwardingStream(ctx context.Context, h tunnelv1.ServiceForwardingHeader) (muxsession.Stream, error) {
	h.TraceContext = observability.WireTrace(ctx)
	return s.openStream(ctx, true, ReturnEvents{}, func(w muxsession.Stream) (int, error) { return tunnelv1.WriteServiceOpening(w, h) }, nil)
}

func (s *Session) openStream(ctx context.Context, confirm bool, events ReturnEvents, write func(muxsession.Stream) (int, error), after []byte) (result muxsession.Stream, err error) {
	stream, err := s.transport.OpenStream(ctx)
	if err != nil {
		return nil, &OpeningError{Err: err}
	}
	written := 0
	defer func() {
		if err != nil {
			result = nil
			err = &OpeningError{Committed: written > 0, VisitorBytes: int64(written), Err: errors.Join(controlContextError(ctx, err), stream.Close())}
		}
	}()
	finish, err := setupDeadline(ctx, stream)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, finish(err == nil)) }()
	written, err = write(stream)
	if err != nil {
		return nil, err
	}
	response := &returnStream{Stream: stream, events: events}
	if confirm {
		if err := response.accept(); err != nil {
			return nil, err
		}
	}
	if len(after) > 0 {
		n, writeErr := stream.Write(after)
		written += max(0, n)
		if writeErr == nil && n != len(after) {
			writeErr = io.ErrShortWrite
		}
		if writeErr != nil {
			return nil, writeErr
		}
	}
	return response, nil
}
