package tunnel

import (
	"context"
	"errors"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// RenewConnectorLeg exchanges a fresh proof on the existing native control stream.
// it cannot move a claim to a different assignment or accepted source. callers
// still fence their old local deadline before installing the returned duration.
func (s *Session) RenewConnectorLeg(ctx context.Context, requestID string, proof tunnelv1.ConnectorPairLegProof, previous tunnelv1.ConnectorPairLegAccepted) (receipt tunnelv1.ConnectorPairLegAccepted, err error) {
	if s == nil || s.role != tunnelv1.Connector || s.connectorLeg == nil || !s.connectorLeg.SameLeg(proof) || previous.Validate() != nil {
		return receipt, &ProtocolError{Code: tunnelv1.Unauthenticated}
	}
	s.connectorControl.Lock()
	defer s.connectorControl.Unlock()
	started := time.Now()
	finish, err := setupDeadline(ctx, s.control)
	if err != nil {
		return receipt, err
	}
	defer func() {
		err = errors.Join(err, finish(err == nil))
		if err != nil {
			receipt = tunnelv1.ConnectorPairLegAccepted{}
		}
	}()
	if err := tunnelv1.WriteControl(s.control, tunnelv1.Message{Type: tunnelv1.ConnectorLegRenew, ProtocolVersion: tunnelv1.Version,
		RequestID: requestID, Role: tunnelv1.Connector, ConnectorPairLegProof: &proof}); err != nil {
		return receipt, err
	}
	response, err := tunnelv1.ReadControl(s.control)
	if err != nil {
		return receipt, err
	}
	if response.RequestID != requestID {
		return receipt, errors.New("tunnel: connector renewal response does not match request")
	}
	if response.Type == tunnelv1.Error {
		return receipt, &ProtocolError{Code: response.Code}
	}
	if response.Type != tunnelv1.ConnectorLegRenewed || response.ConnectorPairLegAccepted == nil ||
		response.ConnectorPairLegAccepted.Match(proof, previous.DeliveryID, started, time.Now()) != nil || response.ConnectorPairLegAccepted.SourceIP != previous.SourceIP {
		return receipt, errors.New("tunnel: connector renewal receipt does not match existing claim")
	}
	return *response.ConnectorPairLegAccepted, nil
}

// HandleConnectorLegControl owns the accepted native control stream until it
// stops. the callback must check current authority without reviving an expired
// owner. packet stream/datagram readers stay with their existing role owner.
func (s *Session) HandleConnectorLegControl(ctx context.Context, activate func(context.Context, tunnelv1.ConnectorLegBinding) error, authorize func(context.Context, tunnelv1.ConnectorPairLegProof) (tunnelv1.ConnectorPairLegAccepted, error)) (err error) {
	if s == nil || s.role != tunnelv1.Connector || s.connectorLeg == nil || authorize == nil {
		return &ProtocolError{Code: tunnelv1.Unauthenticated}
	}
	s.connectorControl.Lock()
	defer s.connectorControl.Unlock()
	finish, err := setContextDeadline(ctx, s.control)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, finish()) }()
	for {
		request, err := tunnelv1.ReadControl(s.control)
		if err != nil {
			return err
		}
		if request.Type == tunnelv1.ConnectorLegActivate {
			var authErr error
			if activate == nil || s.connectorActivated || request.ConnectorLegBinding == nil || !request.ConnectorLegBinding.Matches(*s.connectorLeg) {
				authErr = &ProtocolError{Code: tunnelv1.Unauthenticated}
			} else {
				authErr = activate(ctx, *request.ConnectorLegBinding)
				if authErr == nil {
					authErr = context.Cause(ctx)
				}
			}
			if authErr != nil {
				code := tunnelv1.Unauthenticated
				var rejected *ProtocolError
				if errors.As(authErr, &rejected) && rejected != nil && validAuthenticationError(rejected.Code) {
					code = rejected.Code
				}
				writeErr := tunnelv1.WriteControl(s.control, tunnelv1.Message{Type: tunnelv1.Error, ProtocolVersion: tunnelv1.Version, RequestID: request.RequestID, Code: code})
				return errors.Join(authErr, writeErr)
			}
			s.connectorActivated = true
			if err := tunnelv1.WriteControl(s.control, tunnelv1.Message{Type: tunnelv1.ConnectorLegActivated, ProtocolVersion: tunnelv1.Version, RequestID: request.RequestID, ConnectorLegBinding: request.ConnectorLegBinding}); err != nil {
				return err
			}
			continue
		}
		if request.Type != tunnelv1.ConnectorLegRenew || request.ConnectorPairLegProof == nil || !s.connectorLeg.SameLeg(*request.ConnectorPairLegProof) {
			return &ProtocolError{Code: tunnelv1.Unauthenticated}
		}
		receipt, authErr := authorize(ctx, *request.ConnectorPairLegProof)
		if authErr != nil {
			code := tunnelv1.Unauthenticated
			var protocol *ProtocolError
			if errors.As(authErr, &protocol) && protocol != nil && validAuthenticationError(protocol.Code) {
				code = protocol.Code
			}
			if err := tunnelv1.WriteControl(s.control, tunnelv1.Message{Type: tunnelv1.Error, ProtocolVersion: tunnelv1.Version, RequestID: request.RequestID, Code: code}); err != nil {
				return err
			}
			if code == tunnelv1.Unavailable {
				continue
			}
			return authErr
		}
		if receipt.Validate() != nil || receipt.PairID != request.ConnectorPairLegProof.PairID ||
			receipt.DeliveryGeneration != request.ConnectorPairLegProof.DeliveryGeneration || receipt.ConnectionSlot != request.ConnectorPairLegProof.ConnectionSlot || !receipt.ExpiresAt.After(time.Now()) {
			return &ProtocolError{Code: tunnelv1.Unauthenticated}
		}
		if err := tunnelv1.WriteControl(s.control, tunnelv1.Message{Type: tunnelv1.ConnectorLegRenewed, ProtocolVersion: tunnelv1.Version, RequestID: request.RequestID, ConnectorPairLegAccepted: &receipt}); err != nil {
			return err
		}
	}
}
