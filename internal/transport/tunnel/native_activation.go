package tunnel

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// ActivateNativeLeg selects only this authenticated hello's carrier. racing
// candidates remain passive until their owner joins the losers and chooses one.
// activation does not sign another proof, contact control, or extend a deadline.
func (s *Session) ActivateNativeLeg(ctx context.Context, requestID string) (err error) {
	if s == nil || s.role != tunnelv1.NativeConnector || s.nativeLeg == nil {
		return &ProtocolError{Code: tunnelv1.Unauthenticated}
	}
	s.nativeControl.Lock()
	defer s.nativeControl.Unlock()
	if s.nativeActivated {
		return &ProtocolError{Code: tunnelv1.InvalidMessage}
	}
	finish, err := setupDeadline(ctx, s.control)
	if err != nil {
		return errors.Join(err, &ProtocolError{Code: tunnelv1.Unavailable})
	}
	defer func() {
		err = errors.Join(err, finish(err == nil))
		// a socket deadline can fire before the context's timer goroutine runs.
		// its absolute deadline still fences the result and remains the cause.
		if deadline, ok := ctx.Deadline(); ok && !deadline.After(time.Now()) {
			err = errors.Join(err, context.DeadlineExceeded)
		}
		if err != nil {
			var classified *ProtocolError
			if !errors.As(err, &classified) || classified == nil {
				err = errors.Join(&ProtocolError{Code: tunnelv1.Unavailable}, err)
			}
		}
	}()
	// an ambiguous response cannot be retried on this control stream. the role
	// owner closes this candidate rather than risking a second installation.
	s.nativeActivated = true
	binding := tunnelv1.NativeLegBinding{Nonce: bytes.Clone(s.nativeLeg.Nonce)}
	if err := tunnelv1.WriteControl(s.control, tunnelv1.Message{Type: tunnelv1.NativeLegActivate, ProtocolVersion: tunnelv1.Version,
		RequestID: requestID, Role: tunnelv1.NativeConnector, NativeLegBinding: &binding}); err != nil {
		return err
	}
	response, err := tunnelv1.ReadControl(s.control)
	if err != nil {
		return err
	}
	if response.RequestID != requestID {
		return &ProtocolError{Code: tunnelv1.InvalidMessage}
	}
	if response.Type == tunnelv1.Error {
		return &ProtocolError{Code: response.Code}
	}
	if response.Type != tunnelv1.NativeLegActivated || response.NativeLegBinding == nil || !response.NativeLegBinding.Matches(*s.nativeLeg) {
		return &ProtocolError{Code: tunnelv1.InvalidMessage}
	}
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	if deadline, ok := ctx.Deadline(); ok && !deadline.After(time.Now()) {
		return context.DeadlineExceeded
	}
	return nil
}
