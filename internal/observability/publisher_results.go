package observability

import (
	"errors"

	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// tunnel failures expose only their closed protocol code, avoiding an import
// cycle with transport implementations and never classifying by message text.
func tunnelErrorResult(err error) (Outcome, string, bool) {
	var rejection interface{ TunnelCode() tunnelv1.ErrorCode }
	if !errors.As(err, &rejection) {
		return "", "", false
	}
	code := rejection.TunnelCode()
	outcome := Error
	switch code {
	case tunnelv1.Unauthenticated:
		outcome = Denied
	case tunnelv1.InvalidMessage, tunnelv1.StalePublishRunNumber, tunnelv1.StaleConnectionAssignment, tunnelv1.DuplicatePublisherConnection, tunnelv1.DrainingPublisherConnection, tunnelv1.CapacityExceeded:
		outcome = Rejected
	case tunnelv1.Unavailable, tunnelv1.Internal:
	default:
		return "", "", false
	}
	return outcome, "tunnel." + string(code), true
}

func diagnosticErrorOutcome(code diagnostic.Code) Outcome {
	switch code {
	case diagnostic.VisitorAccessDenied, diagnostic.IPPolicyDenied, diagnostic.AuthenticationRequired:
		return Denied
	case diagnostic.AuthenticationTimeout:
		return Timeout
	case diagnostic.MemberHostnameDepthExceeded, diagnostic.TargetInvalid, diagnostic.PublicURLInvalid, diagnostic.RequestRejected, diagnostic.RequestMisdirected, diagnostic.RequestLimitReached, diagnostic.RequestRateLimited, diagnostic.RequestBudgetExhausted, diagnostic.RateLimited, diagnostic.ServiceAmbiguous, diagnostic.PublicURLConflict:
		return Rejected
	default:
		return Error
	}
}
