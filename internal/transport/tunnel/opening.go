package tunnel

import (
	"context"
	"errors"

	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// OpeningError retains the exact retry boundary even when no stream is returned.
// VisitorBytes excludes framing and, on ingress openings, PROXY metadata.
type OpeningError struct {
	Step         string
	Committed    bool
	VisitorBytes int64
	Err          error
}

func (e *OpeningError) Error() string { return "open visitor stream: " + e.Err.Error() }
func (e *OpeningError) Unwrap() error { return e.Err }

// service openings retain their metadata-only acceptance boundary.
func (s *Session) OpenServiceForwardingStream(ctx context.Context, h tunnelv1.ServiceForwardingHeader) (muxsession.Stream, error) {
	h.TraceContext = observability.WireTrace(ctx)
	return s.openStream(ctx, func(w muxsession.Stream) (int, error) { return tunnelv1.WriteServiceOpening(w, h) })
}

func (s *Session) openStream(ctx context.Context, write func(muxsession.Stream) (int, error)) (result muxsession.Stream, err error) {
	stream, err := s.transport.OpenStream(ctx)
	if err != nil {
		return nil, &OpeningError{Step: "open_stream", Err: err}
	}
	step := "set_deadline"
	written := 0
	defer func() {
		if err != nil {
			result = nil
			err = &OpeningError{Step: step, Committed: written > 0, VisitorBytes: int64(written), Err: errors.Join(controlContextError(ctx, err), stream.Close())}
		}
	}()
	finish, err := setupDeadline(ctx, stream)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, finish(err == nil)) }()
	step = "write_opening"
	written, err = write(stream)
	if err != nil {
		return nil, err
	}
	step = "wait_for_ack"
	response := &returnStream{Stream: stream}
	if err := response.accept(); err != nil {
		return nil, err
	}
	step = "clear_deadline"
	return response, nil
}
