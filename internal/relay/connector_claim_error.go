package relay

import (
	"errors"
	"net/http"

	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// connectorClaimError preserves the same private problem through HTTP and
// standalone. traverse joined errors so a retryable cause cannot hide denial,
// and a stale network source cannot turn an explicit denial into a rebind.
func connectorClaimError(err error) error {
	if err == nil {
		return nil
	}
	denied, staleNetwork, staleAssignment, retryable := false, false, false, false
	protocol := func(code tunnelv1.ErrorCode) {
		switch code {
		case tunnelv1.StaleNetworkBinding:
			staleNetwork = true
		case tunnelv1.StaleConnectionAssignment:
			staleAssignment = true
		case tunnelv1.Unavailable, tunnelv1.CapacityExceeded:
			retryable = true
		default:
			denied = true
		}
	}
	problem := func(status int, code relayv1.ProblemCode) {
		switch code {
		case relayv1.StaleNetworkBinding:
			protocol(tunnelv1.StaleNetworkBinding)
		case relayv1.StaleConnectionAssignment, relayv1.RelayLeaseStale:
			protocol(tunnelv1.StaleConnectionAssignment)
		case relayv1.Unauthenticated, relayv1.InvalidPublisherConnectionCredential:
			denied = true
		default:
			if status == http.StatusConflict || status == http.StatusTooManyRequests || status >= 500 {
				retryable = true
			} else {
				denied = true
			}
		}
	}
	var visit func(error)
	visit = func(cause error) {
		switch classified := cause.(type) {
		case *tunnel.ProtocolError:
			protocol(classified.Code)
		case *ControlProblemError:
			var code relayv1.ProblemCode
			if classified.Problem != nil {
				code = classified.Problem.Code
			}
			problem(classified.Status, code)
		case *serviceapi.ProblemError:
			problem(classified.Status, relayv1.ProblemCode(classified.Code))
		case *temporaryControlError:
			retryable = true
		}
		switch wrapped := cause.(type) {
		case interface{ Unwrap() []error }:
			for _, child := range wrapped.Unwrap() {
				visit(child)
			}
		case interface{ Unwrap() error }:
			visit(wrapped.Unwrap())
		}
	}
	visit(err)
	code := tunnelv1.Unauthenticated
	if !denied {
		switch {
		case staleNetwork:
			code = tunnelv1.StaleNetworkBinding
		case staleAssignment:
			code = tunnelv1.StaleConnectionAssignment
		case retryable:
			code = tunnelv1.Unavailable
		}
	}
	return errors.Join(&tunnel.ProtocolError{Code: code}, err)
}
