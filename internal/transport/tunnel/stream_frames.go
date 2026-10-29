package tunnel

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type ReturnEvents struct {
	Promoted func(tunnelv1.AdmissionHeader) error
	Rejected func(tunnelv1.ErrorCode) error
}

// returnStream strips outer framing before visitor TLS sees any response byte.
type returnStream struct {
	muxsession.Stream
	readMu    sync.Mutex
	accepted  bool
	promoted  bool
	remaining []byte
	terminal  error
	events    ReturnEvents
}

func (s *returnStream) accept() error {
	frame, err := tunnelv1.ReadReturnFrame(s.Stream)
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return err
	}
	if frame.Kind == tunnelv1.ReturnRejected {
		return &ProtocolError{Code: frame.Code}
	}
	if frame.Kind != tunnelv1.ReturnAccepted {
		return tunnelv1.ErrReturnFrame
	}
	s.accepted = true
	return nil
}

func (s *returnStream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	s.readMu.Lock()
	defer s.readMu.Unlock()
	for len(s.remaining) == 0 && s.terminal == nil {
		frame, err := tunnelv1.ReadReturnFrame(s.Stream)
		if err != nil {
			// only an explicit end frame is a clean half-close.
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			s.terminal = err
			break
		}
		switch frame.Kind {
		case tunnelv1.ReturnAccepted:
			if s.accepted {
				s.terminal = tunnelv1.ErrReturnFrame
			} else {
				s.accepted = true
			}
		case tunnelv1.ReturnRejected:
			s.terminal = &ProtocolError{Code: frame.Code}
			if s.events.Rejected != nil {
				s.terminal = errors.Join(s.terminal, s.events.Rejected(frame.Code))
			}
		case tunnelv1.ReturnPromoted:
			if !s.accepted || s.promoted || s.events.Promoted == nil {
				s.terminal = tunnelv1.ErrReturnFrame
			} else if err := s.events.Promoted(frame.Promotion); err != nil {
				s.terminal = err
				var rejected *ProtocolError
				if s.events.Rejected != nil && errors.As(err, &rejected) {
					s.terminal = errors.Join(err, s.events.Rejected(rejected.Code))
				}
			} else {
				s.promoted = true
			}
		case tunnelv1.ReturnData:
			if !s.accepted {
				s.terminal = tunnelv1.ErrReturnFrame
			} else {
				s.remaining = frame.Data
			}
		case tunnelv1.ReturnEnded:
			if !s.accepted {
				s.terminal = tunnelv1.ErrReturnFrame
			} else {
				s.terminal = io.EOF
			}
		}
	}
	if len(s.remaining) > 0 {
		n := copy(p, s.remaining)
		s.remaining = s.remaining[n:]
		return n, nil
	}
	if s.terminal != io.EOF {
		_ = s.Stream.Close()
	}
	return 0, s.terminal
}

// replyStream serializes decisions with return data, while request reads and
// half-closes remain independent. each responder is owned by one visitor stream.
type replyStream struct {
	muxsession.Stream
	writeInit  sync.Once
	writeGate  chan struct{}
	responded  bool
	respondErr error
	accepted   bool
	promoted   bool
	ended      bool
	writeErr   error
	promotion  tunnelv1.AdmissionHeader
}

// writers serializes return frames, including the one accept/reject decision.
// initialization never waits for I/O; decision waiters select on their context.
func (s *replyStream) writers() chan struct{} {
	s.writeInit.Do(func() { s.writeGate = make(chan struct{}, 1) })
	return s.writeGate
}

// decide bounds both admission to the writer and the write itself. cancellation
// resets only this stream and is joined before returning. resetting, rather than
// temporarily changing deadlines, cannot be undone by another decision writer.
func (s *replyStream) decide(ctx context.Context, write func() error) (err error) {
	ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	if err := context.Cause(ctx); err != nil {
		return err
	}
	interrupted := make(chan struct{})
	var resetErr error
	locked := false
	stop := context.AfterFunc(ctx, func() {
		resetErr = s.Stream.Reset(0)
		close(interrupted)
	})
	defer func() {
		if !stop() {
			<-interrupted
		} else if context.Cause(ctx) != nil {
			resetErr = s.Stream.Reset(0)
		}
		err = errors.Join(err, context.Cause(ctx), resetErr)
		if locked {
			<-s.writeGate
		}
	}()
	select {
	case s.writers() <- struct{}{}:
		locked = true
	case <-ctx.Done():
		return context.Cause(ctx)
	}
	if err := context.Cause(ctx); err != nil {
		return err
	}
	return write()
}

func (s *replyStream) respond(ctx context.Context, response tunnelv1.StreamResponse) error {
	if err := response.Validate(); err != nil {
		return err
	}
	return s.decide(ctx, func() error {
		if !s.responded {
			s.responded = true
			s.respondErr = s.respondLocked(response)
		}
		return s.respondErr
	})
}

func (s *replyStream) respondLocked(response tunnelv1.StreamResponse) error {
	if response.Type == tunnelv1.StreamRejected {
		s.ended = true
		return errors.Join(tunnelv1.WriteReturnFrame(s.Stream, tunnelv1.ReturnFrame{Kind: tunnelv1.ReturnRejected, Code: response.Code}), s.Stream.Close())
	}
	s.writeErr = tunnelv1.WriteReturnFrame(s.Stream, tunnelv1.ReturnFrame{Kind: tunnelv1.ReturnAccepted})
	if s.writeErr == nil {
		s.writeErr = s.Stream.SetDeadline(time.Time{})
	}
	if s.writeErr != nil {
		return errors.Join(s.writeErr, s.Stream.Close())
	}
	s.accepted = true
	return nil
}

func (s *replyStream) forwardRejection(ctx context.Context, code tunnelv1.ErrorCode) error {
	return s.decide(ctx, func() error {
		if s.ended {
			return io.ErrClosedPipe
		}
		s.ended = true
		return errors.Join(tunnelv1.WriteReturnFrame(s.Stream, tunnelv1.ReturnFrame{Kind: tunnelv1.ReturnRejected, Code: code}), s.Stream.Close())
	})
}

func (s *replyStream) writable() error {
	if s.writeErr != nil {
		return s.writeErr
	}
	if !s.accepted || s.ended {
		return io.ErrClosedPipe
	}
	return nil
}

func (s *replyStream) Write(p []byte) (int, error) {
	s.writers() <- struct{}{}
	defer func() { <-s.writeGate }()
	if err := s.writable(); err != nil {
		return 0, err
	}
	written := 0
	for len(p) > 0 {
		length := min(len(p), tunnelv1.MaxStreamDataBytes)
		s.writeErr = tunnelv1.WriteReturnFrame(s.Stream, tunnelv1.ReturnFrame{Kind: tunnelv1.ReturnData, Data: p[:length]})
		if s.writeErr != nil {
			return written, s.writeErr
		}
		written += length
		p = p[length:]
	}
	return written, nil
}

func (s *replyStream) promote(ctx context.Context, h tunnelv1.AdmissionHeader) error {
	if err := h.Validate(); err != nil {
		return err
	}
	return s.decide(ctx, func() error {
		if s.promoted {
			return tunnelv1.ErrReturnFrame
		}
		if err := s.writable(); err != nil {
			return err
		}
		s.writeErr = tunnelv1.WriteReturnFrame(s.Stream, tunnelv1.ReturnFrame{Kind: tunnelv1.ReturnPromoted, Promotion: h})
		s.promoted = s.writeErr == nil
		return s.writeErr
	})
}

func (s *replyStream) CloseWrite() error {
	s.writers() <- struct{}{}
	defer func() { <-s.writeGate }()
	return s.closeWriteLocked()
}

func (s *replyStream) end(ctx context.Context) error {
	return s.decide(ctx, func() error {
		if s.ended {
			return s.writeErr
		}
		if err := s.writable(); err != nil {
			return err
		}
		// tls.Conn expires its payload write deadline after close-notify.
		// the final outer frame belongs to this bounded decision instead;
		// cancellation resets the stream and cannot be undone by this deadline.
		if err := s.Stream.SetWriteDeadline(time.Time{}); err != nil {
			s.writeErr = err
			return err
		}
		return s.closeWriteLocked()
	})
}

func (s *replyStream) closeWriteLocked() error {
	if s.ended {
		return s.writeErr
	}
	if err := s.writable(); err != nil {
		return err
	}
	s.writeErr = errors.Join(tunnelv1.WriteReturnFrame(s.Stream, tunnelv1.ReturnFrame{Kind: tunnelv1.ReturnEnded}), s.Stream.CloseWrite())
	s.ended = true
	return s.writeErr
}
