package tunnel

import (
	"context"
	"errors"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// ActivateConnectorLeg selects only this authenticated hello's carrier. racing
// candidates remain passive until their owner joins the losers and chooses one.
// activation does not sign another proof, contact control, or extend a deadline.
func (s *Session) ActivateConnectorLeg(ctx context.Context, requestID string) (err error) {
	return s.activateConnectorLeg(ctx, requestID, tunnelv1.ConnectorHandoff{}, false)
}

// ReplaceConnectorLeg selects a successor on its authenticated control stream.
// the relay must check the predecessor, source and unchanged authority itself.
func (s *Session) ReplaceConnectorLeg(ctx context.Context, requestID string, handoff tunnelv1.ConnectorHandoff) error {
	if !handoff.Valid() {
		return &ProtocolError{Code: tunnelv1.InvalidMessage}
	}
	return s.activateConnectorLeg(ctx, requestID, handoff, true)
}

func (s *Session) activateConnectorLeg(ctx context.Context, requestID string, handoff tunnelv1.ConnectorHandoff, replacement bool) (err error) {
	if s == nil || s.role != tunnelv1.Connector || s.connectorLeg == nil {
		return &ProtocolError{Code: tunnelv1.Unauthenticated}
	}
	s.connectorControl.Lock()
	defer s.connectorControl.Unlock()
	if s.connectorActivated {
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
	s.connectorActivated = true
	hello, err := tunnelv1.ParseConnectorHelloNonce(s.connectorLeg.Nonce)
	if err != nil {
		return &ProtocolError{Code: tunnelv1.InvalidMessage}
	}
	activation := tunnelv1.InitialConnectorActivation(hello)
	if replacement {
		activation = activation.Replacing(handoff)
	}
	binding := activation.Binding()
	if err := tunnelv1.WriteControl(s.control, tunnelv1.Message{Type: tunnelv1.ConnectorLegActivate, ProtocolVersion: tunnelv1.Version,
		RequestID: requestID, Role: tunnelv1.Connector, ConnectorLegBinding: &binding}); err != nil {
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
	if response.Type != tunnelv1.ConnectorLegActivated || response.ConnectorLegBinding == nil {
		return &ProtocolError{Code: tunnelv1.InvalidMessage}
	}
	confirmed, err := response.ConnectorLegBinding.Activation()
	if err != nil || confirmed != activation {
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
