package tunnel

import (
	"os"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
)

// a control exchange records interruption before advancing its owned deadline.
// a later stop cannot supply provenance to an already-observed operation error.
type controlDeadlineStop struct {
	mu       sync.Mutex
	entry    error
	cause    error
	deadline time.Time
}

func (s *controlDeadlineStop) beforeIO(cause error) {
	if s != nil {
		s.entry = cause
	}
}

func (s *controlDeadlineStop) interrupt(cause error, deadline time.Time) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.cause, s.deadline = cause, deadline
	s.mu.Unlock()
}

func (s *controlDeadlineStop) operationCause(err error) error {
	if !controlSocketDeadlineOnly(err) {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// before the original deadline, this exchange's cancellation callback is
	// the only owner that can have advanced the socket deadline. once that
	// original budget is spent, a timeout remains an operation failure.
	if !s.deadline.After(time.Now()) {
		return nil
	}
	return s.cause
}

func controlSocketDeadlineOnly(err error) bool {
	if err == os.ErrDeadlineExceeded {
		return true
	}
	switch wrapped := err.(type) {
	case *ProtocolError, *SessionCleanupError, *muxsession.QUICTransportCloseError,
		*failure.Error, interface{ FailureReason() failure.Reason }:
		return false
	case interface{ Unwrap() []error }:
		children := wrapped.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !controlSocketDeadlineOnly(child) {
				return false
			}
		}
		return true
	case interface{ Unwrap() error }:
		return controlSocketDeadlineOnly(wrapped.Unwrap())
	default:
		return false
	}
}
