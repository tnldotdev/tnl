package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

const rejectionDrainTimeout = time.Second

// a queued write or fin is not delivery. the server sends rejection + fin and
// waits for the publisher's fin; the publisher sends its fin only after reading
// that exact frame and the server's fin, then joins the server's session end.
// neither side closes the outer session while its final bytes are only queued.
func rejectPublisherHello(ctx context.Context, control muxsession.Stream, code tunnelv1.ErrorCode, closeTransport func() error) error {
	return publisherRejectionExchange(ctx, control, closeTransport, func(context.Context) error {
		if err := writeProtocolError(control, code); err != nil {
			return fmt.Errorf("tunnel: write publisher rejection: %w", err)
		}
		if err := control.CloseWrite(); err != nil {
			return fmt.Errorf("tunnel: finish publisher rejection: %w", err)
		}
		return publisherRejectionEnd(control, "acknowledgement")
	})
}

func acknowledgePublisherRejection(ctx context.Context, transport muxsession.Session, control muxsession.Stream, closeTransport func() error) error {
	return publisherRejectionExchange(ctx, control, closeTransport, func(exchange context.Context) error {
		if err := publisherRejectionEnd(control, "response"); err != nil {
			return err
		}
		if err := control.CloseWrite(); err != nil {
			return fmt.Errorf("tunnel: acknowledge publisher rejection: %w", err)
		}
		select {
		case <-transport.Done():
		case <-exchange.Done():
			return errors.Join(context.Cause(exchange), transport.Err())
		}
		end := transport.Err()
		if cause := context.Cause(exchange); cause != nil {
			return errors.Join(cause, end)
		}
		// only this completed exchange owns the expected outer close. a reset,
		// truncated frame, canceled exchange, or independent joined error cannot
		// acquire this provenance, even when it also unwraps to EOF or closed.
		if end != nil && (failure.Only(end, io.EOF) || muxsession.NormalSessionCloseOnly(end)) {
			return nil
		}
		if end == nil {
			return errors.New("tunnel: publisher rejection session ended without a result")
		}
		return fmt.Errorf("tunnel: join publisher rejection session: %w", end)
	})
}

func publisherRejectionEnd(control muxsession.Stream, boundary string) error {
	var extra [1]byte
	n, err := control.Read(extra[:])
	if n == 0 && err == io.EOF {
		return nil
	}
	if n != 0 || err == nil {
		return errors.Join(fmt.Errorf("tunnel: unexpected publisher rejection %s data", boundary), err)
	}
	return fmt.Errorf("tunnel: read publisher rejection %s end: %w", boundary, err)
}

func publisherRejectionExchange(ctx context.Context, control muxsession.Stream, closeTransport func() error, exchange func(context.Context) error) (result error) {
	// deriving from the original setup context preserves time already spent on
	// authentication and i/o. the existing short rejection cap can only shorten it.
	until := time.Now().Add(rejectionDrainTimeout)
	if original, ok := ctx.Deadline(); ok && original.Before(until) {
		until = original
	}
	bounded, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	if cause := context.Cause(bounded); cause != nil {
		return cause
	}
	if err := control.SetDeadline(until); err != nil {
		return fmt.Errorf("tunnel: set publisher rejection deadline: %w", err)
	}
	interrupted := make(chan struct{})
	var interruptErr error
	stop := context.AfterFunc(bounded, func() {
		// yamux fin queueing ignores stream deadlines. force the owned session
		// closed at this same deadline too, then join both the i/o and watcher.
		interruptErr = errors.Join(control.SetDeadline(time.Now()), closeTransport())
		close(interrupted)
	})
	defer func() {
		if !stop() {
			<-interrupted
		}
		cause := context.Cause(bounded)
		if cause == nil && !time.Now().Before(until) {
			cause = context.DeadlineExceeded
		}
		result = errors.Join(result, cause, interruptErr)
	}()
	return exchange(bounded)
}
