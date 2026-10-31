package tunnel

import (
	"context"
	"errors"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// RenewNativeLeg exchanges a fresh proof on the existing native control stream.
// it cannot move a claim to a different assignment or accepted source. callers
// still fence their old local deadline before installing the returned duration.
func (s *Session) RenewNativeLeg(ctx context.Context, requestID string, proof tunnelv1.NativePairLegProof, previous tunnelv1.NativePairLegAccepted) (receipt tunnelv1.NativePairLegAccepted, err error) {
	if s == nil || s.role != tunnelv1.NativeConnector || s.nativeLeg == nil || !s.nativeLeg.SameLeg(proof) || previous.Validate() != nil {
		return receipt, &ProtocolError{Code: tunnelv1.Unauthenticated}
	}
	s.nativeControl.Lock()
	defer s.nativeControl.Unlock()
	started := time.Now()
	finish, err := setupDeadline(ctx, s.control)
	if err != nil {
		return receipt, err
	}
	defer func() {
		err = errors.Join(err, finish(err == nil))
		if err != nil {
			receipt = tunnelv1.NativePairLegAccepted{}
		}
	}()
	if err := tunnelv1.WriteControl(s.control, tunnelv1.Message{Type: tunnelv1.NativeLegRenew, ProtocolVersion: tunnelv1.Version,
		RequestID: requestID, Role: tunnelv1.NativeConnector, NativePairLegProof: &proof}); err != nil {
		return receipt, err
	}
	response, err := tunnelv1.ReadControl(s.control)
	if err != nil {
		return receipt, err
	}
	if response.RequestID != requestID {
		return receipt, errors.New("tunnel: native renewal response does not match request")
	}
	if response.Type == tunnelv1.Error {
		return receipt, &ProtocolError{Code: response.Code}
	}
	if response.Type != tunnelv1.NativeLegRenewed || response.NativePairLegAccepted == nil ||
		response.NativePairLegAccepted.Match(proof, previous.DeliveryID, started, time.Now()) != nil || response.NativePairLegAccepted.SourceIP != previous.SourceIP {
		return receipt, errors.New("tunnel: native renewal receipt does not match existing claim")
	}
	return *response.NativePairLegAccepted, nil
}

// HandleNativeLegControl owns the accepted native control stream until it
// stops. the callback must check current authority without reviving an expired
// owner. packet stream/datagram readers stay with their existing role owner.
func (s *Session) HandleNativeLegControl(ctx context.Context, activate func(context.Context, tunnelv1.NativeLegBinding) error, authorize func(context.Context, tunnelv1.NativePairLegProof) (tunnelv1.NativePairLegAccepted, error)) (err error) {
	if s == nil || s.role != tunnelv1.NativeConnector || s.nativeLeg == nil || authorize == nil {
		return &ProtocolError{Code: tunnelv1.Unauthenticated}
	}
	s.nativeControl.Lock()
	defer s.nativeControl.Unlock()
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
		if request.Type == tunnelv1.NativeLegActivate {
			var authErr error
			if activate == nil || s.nativeActivated || request.NativeLegBinding == nil || !request.NativeLegBinding.Matches(*s.nativeLeg) {
				authErr = &ProtocolError{Code: tunnelv1.Unauthenticated}
			} else {
				authErr = activate(ctx, *request.NativeLegBinding)
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
			s.nativeActivated = true
			if err := tunnelv1.WriteControl(s.control, tunnelv1.Message{Type: tunnelv1.NativeLegActivated, ProtocolVersion: tunnelv1.Version, RequestID: request.RequestID, NativeLegBinding: request.NativeLegBinding}); err != nil {
				return err
			}
			continue
		}
		if request.Type != tunnelv1.NativeLegRenew || request.NativePairLegProof == nil || !s.nativeLeg.SameLeg(*request.NativePairLegProof) {
			return &ProtocolError{Code: tunnelv1.Unauthenticated}
		}
		receipt, authErr := authorize(ctx, *request.NativePairLegProof)
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
		if receipt.Validate() != nil || receipt.PairID != request.NativePairLegProof.PairID ||
			receipt.DeliveryGeneration != request.NativePairLegProof.DeliveryGeneration || receipt.ConnectionSlot != request.NativePairLegProof.ConnectionSlot || !receipt.ExpiresAt.After(time.Now()) {
			return &ProtocolError{Code: tunnelv1.Unauthenticated}
		}
		if err := tunnelv1.WriteControl(s.control, tunnelv1.Message{Type: tunnelv1.NativeLegRenewed, ProtocolVersion: tunnelv1.Version, RequestID: request.RequestID, NativePairLegAccepted: &receipt}); err != nil {
			return err
		}
	}
}
