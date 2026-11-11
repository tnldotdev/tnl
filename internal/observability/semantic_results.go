package observability

// DomainReason is bounded detail, independent of the operation's outcome.
// no parser narrows arbitrary strings at the semantic observer boundary.
type DomainReason uint8

const (
	ReasonForwarded DomainReason = iota + 1
	ReasonCommitted
	ReasonPlaced
	ReasonServed
	ReasonNotModified
	ReasonClaimed
	ReasonEmpty
	ReasonProgress
	ReasonPending
	ReasonBusy
	ReasonPolicyDenied
	ReasonNotAdmitted
	ReasonCapacityDenied
	ReasonCapacity
	ReasonBandwidth
	ReasonDraining
	ReasonInvalid
	ReasonInvalidProjection
	ReasonInsufficientServices
	ReasonClientError
	ReasonStale
	ReasonLookupMissing
	ReasonLookupUnavailable
	ReasonOpenFailed
	ReasonSetupFailed
	ReasonCommittedFailed
	ReasonUnavailable
	ReasonRetry
	ReasonTerminal
	ReasonSaveFailed
	ReasonHTTPError
	ReasonServerError
	ReasonTransportError
	ReasonInvalidResponse
	ReasonOther
	ReasonExpired
)

var domainReasonNames = []string{"", "forwarded", "committed", "placed", "served", "not_modified", "claimed", "empty", "progress", "pending", "busy", "policy_denied", "not_admitted", "capacity_denied", "capacity", "bandwidth", "draining", "invalid", "invalid_projection", "insufficient_services", "client_error", "stale", "lookup_missing", "lookup_unavailable", "open_failed", "setup_failed", "committed_failed", "unavailable", "retry", "terminal", "save_failed", "http_error", "server_error", "transport_error", "invalid_response", "other", "expired"}

func (v DomainReason) String() string { return enumString(domainReasonNames, int(v)) }

type semanticResult struct {
	outcome Outcome
	reason  DomainReason
}

func (v VisitorOutcome) result() semanticResult {
	switch v {
	case VisitorForwarded:
		return semanticResult{Success, ReasonForwarded}
	case VisitorPolicyDenied:
		return semanticResult{Denied, ReasonPolicyDenied}
	case VisitorCapacityDenied:
		return semanticResult{Rejected, ReasonCapacityDenied}
	case VisitorDraining:
		return semanticResult{Rejected, ReasonDraining}
	case VisitorInvalidProjection:
		return semanticResult{Rejected, ReasonInvalidProjection}
	case VisitorLookupMissing:
		return semanticResult{Error, ReasonLookupMissing}
	case VisitorLookupUnavailable:
		return semanticResult{Error, ReasonLookupUnavailable}
	case VisitorOpenFailed:
		return semanticResult{Error, ReasonOpenFailed}
	case VisitorCommittedFailed:
		return semanticResult{Error, ReasonCommittedFailed}
	default:
		return semanticResult{Error, ReasonOther}
	}
}

func (v RelayAttemptOutcome) result() semanticResult {
	switch v {
	case RelayAttemptCommitted:
		return semanticResult{Success, ReasonCommitted}
	case RelayAttemptOpenFailed:
		return semanticResult{Error, ReasonOpenFailed}
	case RelayAttemptSetupFailed:
		return semanticResult{Error, ReasonSetupFailed}
	case RelayAttemptCommittedFailed:
		return semanticResult{Error, ReasonCommittedFailed}
	default:
		return semanticResult{Error, ReasonOther}
	}
}

func (v RecoveryAttemptOutcome) result() semanticResult {
	switch v {
	case RecoveryAttemptSuccess:
		return semanticResult{outcome: Success}
	case RecoveryAttemptCanceled:
		return semanticResult{outcome: Canceled}
	case RecoveryAttemptStale:
		return semanticResult{Rejected, ReasonStale}
	default:
		return semanticResult{Error, ReasonRetry}
	}
}

func (v PlacementOutcome) result() semanticResult {
	switch v {
	case PlacementPlaced:
		return semanticResult{Success, ReasonPlaced}
	case PlacementInsufficientServices:
		return semanticResult{Rejected, ReasonInsufficientServices}
	case PlacementCapacity:
		return semanticResult{Rejected, ReasonCapacity}
	case PlacementUnavailable:
		return semanticResult{Error, ReasonUnavailable}
	case PlacementStale:
		return semanticResult{Rejected, ReasonStale}
	default:
		return semanticResult{outcome: Error}
	}
}

func (v DNSWorkOutcome) result() semanticResult {
	switch v {
	case DNSWorkSuccess:
		return semanticResult{outcome: Success}
	case DNSWorkPending:
		return semanticResult{Success, ReasonPending}
	default:
		return semanticResult{outcome: Error}
	}
}

func (v CertificateClaimOutcome) result() semanticResult {
	switch v {
	case CertificateClaimed:
		return semanticResult{Success, ReasonClaimed}
	case CertificateEmpty:
		return semanticResult{Success, ReasonEmpty}
	default:
		return semanticResult{outcome: Error}
	}
}

func (v CertificateWorkOutcome) result() semanticResult {
	switch v {
	case CertificateProgress:
		return semanticResult{Success, ReasonProgress}
	case CertificateTerminal:
		return semanticResult{Error, ReasonTerminal}
	case CertificateSaveFailed:
		return semanticResult{Error, ReasonSaveFailed}
	default:
		return semanticResult{Error, ReasonRetry}
	}
}

func (v APIRequestOutcome) result() semanticResult {
	switch v {
	case APIRequestSuccess:
		return semanticResult{outcome: Success}
	case APIRequestDeadlineExceeded:
		return semanticResult{outcome: Timeout}
	case APIRequestCanceled:
		return semanticResult{outcome: Canceled}
	case APIRequestDenied:
		return semanticResult{outcome: Denied}
	case APIRequestServerError:
		return semanticResult{Error, ReasonServerError}
	case APIRequestClientError:
		return semanticResult{Rejected, ReasonClientError}
	case APIRequestNotAdmitted:
		return semanticResult{Rejected, ReasonNotAdmitted}
	case APIRequestDraining:
		return semanticResult{Rejected, ReasonDraining}
	default:
		return semanticResult{Error, ReasonOther}
	}
}
