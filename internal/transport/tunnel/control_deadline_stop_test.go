package tunnel

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"testing/synctest"
	"time"

	yamux "github.com/libp2p/go-yamux/v5"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
)

type deadlineMatchingError struct{}

func (deadlineMatchingError) Error() string {
	return "independent failure with a timeout matching hook"
}
func (deadlineMatchingError) Is(target error) bool { return target == os.ErrDeadlineExceeded }

func TestControlDeadlineStopRequiresObservedInterruptionAndUnspentBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var stopped controlDeadlineStop
		earlier := stopped.operationCause(os.ErrDeadlineExceeded)
		cause := errors.New("control caller stopped")
		budget, finish := context.WithTimeout(t.Context(), 2*time.Second)
		defer finish()
		until, _ := budget.Deadline()
		stopped.interrupt(cause, until)
		if earlier != nil || stopped.operationCause(os.ErrDeadlineExceeded) != cause {
			t.Fatal("interruption was not tied to its observation before deadline expiry")
		}
		independent := errors.New("independent operation")
		for _, err := range []error{
			errors.Join(os.ErrDeadlineExceeded, independent), errors.Join(yamux.ErrTimeout, independent), deadlineMatchingError{},
			&ProtocolError{Code: "unavailable"}, &SessionCleanupError{Err: os.ErrDeadlineExceeded},
			&SessionCleanupError{Err: yamux.ErrTimeout},
			&muxsession.QUICTransportCloseError{Err: os.ErrDeadlineExceeded},
			failure.Wrap("control", failure.ConnectionUnavailable, os.ErrDeadlineExceeded),
		} {
			if stopped.operationCause(err) != nil {
				t.Fatal("local interruption hid an independent operation or cleanup", err)
			}
		}
		if stopped.operationCause(fmt.Errorf("read: %w", os.ErrDeadlineExceeded)) != cause {
			t.Fatal("a wrapped raw socket deadline lost its interruption origin")
		}
		if stopped.operationCause(yamux.ErrTimeout) != cause {
			t.Fatal("the native yamux stream deadline lost its observed interruption origin")
		}
		<-budget.Done()
		if stopped.operationCause(os.ErrDeadlineExceeded) != nil {
			t.Fatal("a spent original budget acquired local-stop provenance")
		}
	})
}
