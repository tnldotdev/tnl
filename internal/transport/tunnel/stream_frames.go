package tunnel

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// returnStream removes all outer framing before TLS or a native protocol sees
// response bytes. request writes remain independent of return-side acceptance.
type returnStream struct {
	muxsession.Stream
	readMu    sync.Mutex
	accepted  bool
	promoted  bool
	remaining []byte
	terminal  error
	notify    func(tunnelv1.AdmissionHeader) error
	reject    func(tunnelv1.ErrorCode) error
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
			if errors.Is(err, io.EOF) && !s.accepted {
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
			if s.reject != nil {
				s.terminal = errors.Join(s.terminal, s.reject(frame.Code))
			}
		case tunnelv1.ReturnPromoted:
			if !s.accepted || s.promoted || s.notify == nil {
				s.terminal = tunnelv1.ErrReturnFrame
			} else if err := s.notify(frame.Promotion); err != nil {
				s.terminal = err
				var rejected *ProtocolError
				if s.reject != nil && errors.As(err, &rejected) {
					s.terminal = errors.Join(err, s.reject(rejected.Code))
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
	if !errors.Is(s.terminal, io.EOF) {
		_ = s.Stream.Close()
	}
	return 0, s.terminal
}

// replyStream reads raw request bytes and writes framed replies. accept is a
// local decision: it must not block request processing on a peer reading an ack.
// the first return write carries acceptance before its notification or data.
type replyStream struct {
	muxsession.Stream
	readMu    sync.Mutex
	initial   *bytes.Reader
	writeMu   sync.Mutex
	state     atomic.Uint32
	sent      bool
	promoted  bool
	ended     bool
	writeErr  error
	promotion tunnelv1.AdmissionHeader
}

const (
	replyPending uint32 = iota
	replyAccepted
	replyRejected
)

func newReplyStream(stream muxsession.Stream, initial []byte) *replyStream {
	return &replyStream{Stream: stream, initial: bytes.NewReader(initial)}
}

func (s *replyStream) takeInitial() []byte {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	initial, _ := io.ReadAll(s.initial)
	return initial
}

func (s *replyStream) forwardRejection(code tunnelv1.ErrorCode) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.state.Load() == replyRejected || s.ended {
		return io.ErrClosedPipe
	}
	s.state.Store(replyRejected)
	err := tunnelv1.WriteReturnFrame(s.Stream, tunnelv1.ReturnFrame{Kind: tunnelv1.ReturnRejected, Code: code})
	return errors.Join(err, s.Stream.Close())
}

// PromoteVisitorStream sends on the same outer return stream as the visitor's
// response. a plain connection cannot supply this publisher-only capability.
func PromoteVisitorStream(connection net.Conn) error {
	stream, ok := connection.(*replyStream)
	if !ok {
		return tunnelv1.ErrReturnFrame
	}
	return stream.Promote(stream.promotion)
}

func PromoteServiceVisitorStream(connection net.Conn, visitor tunnelv1.ServiceVisitorReference) error {
	stream, ok := connection.(*replyStream)
	if !ok || !visitor.Valid() || stream.promotion.ServiceID == "" {
		return tunnelv1.ErrReturnFrame
	}
	header := stream.promotion
	header.Visitor = visitor
	return stream.Promote(header)
}

func (s *replyStream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if s.state.Load() != replyAccepted {
		return 0, tunnelv1.ErrReturnFrame
	}
	s.readMu.Lock()
	defer s.readMu.Unlock()
	if s.initial.Len() > 0 {
		return s.initial.Read(p)
	}
	return s.Stream.Read(p)
}

func (s *replyStream) respond(response tunnelv1.StreamResponse) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := response.Validate(); err != nil {
		return err
	}
	if s.state.Load() != replyPending {
		return tunnelv1.ErrReturnFrame
	}
	if response.Type == tunnelv1.StreamRejected {
		s.state.Store(replyRejected)
		err := tunnelv1.WriteReturnFrame(s.Stream, tunnelv1.ReturnFrame{Kind: tunnelv1.ReturnRejected, Code: response.Code})
		return errors.Join(err, s.Stream.Close())
	}
	if err := s.Stream.SetDeadline(time.Time{}); err != nil {
		return errors.Join(err, s.Stream.Close())
	}
	s.state.Store(replyAccepted)
	return nil
}

func (s *replyStream) startReplyLocked() error {
	if s.state.Load() != replyAccepted || s.ended {
		return io.ErrClosedPipe
	}
	if s.writeErr != nil {
		return s.writeErr
	}
	if !s.sent {
		s.writeErr = tunnelv1.WriteReturnFrame(s.Stream, tunnelv1.ReturnFrame{Kind: tunnelv1.ReturnAccepted})
		s.sent = s.writeErr == nil
	}
	return s.writeErr
}

func (s *replyStream) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if err := s.startReplyLocked(); err != nil {
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

func (s *replyStream) Promote(h tunnelv1.AdmissionHeader) error {
	if err := h.Validate(); err != nil {
		return err
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.promoted {
		return tunnelv1.ErrReturnFrame
	}
	if err := s.startReplyLocked(); err != nil {
		return err
	}
	s.writeErr = tunnelv1.WriteReturnFrame(s.Stream, tunnelv1.ReturnFrame{Kind: tunnelv1.ReturnPromoted, Promotion: h})
	s.promoted = s.writeErr == nil
	return s.writeErr
}

func (s *replyStream) CloseWrite() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.ended {
		return s.writeErr
	}
	if err := s.startReplyLocked(); err != nil {
		return err
	}
	s.writeErr = tunnelv1.WriteReturnFrame(s.Stream, tunnelv1.ReturnFrame{Kind: tunnelv1.ReturnEnded})
	s.ended = true
	return errors.Join(s.writeErr, s.Stream.CloseWrite())
}
