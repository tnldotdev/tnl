package observability

// each metric family has its own bounded outcome vocabulary.
type VisitorOutcome string

const (
	VisitorLookupMissing     VisitorOutcome = "lookup_missing"
	VisitorLookupUnavailable VisitorOutcome = "lookup_unavailable"
	VisitorInvalidProjection VisitorOutcome = "invalid_projection"
	VisitorPolicyDenied      VisitorOutcome = "policy_denied"
	VisitorCapacityDenied    VisitorOutcome = "capacity_denied"
	VisitorOpenFailed        VisitorOutcome = "open_failed"
	VisitorCommittedFailed   VisitorOutcome = "committed_failed"
	VisitorForwarded         VisitorOutcome = "forwarded"
	VisitorDraining          VisitorOutcome = "draining"
	VisitorOther             VisitorOutcome = "other"
)

type RelayAttemptOutcome string

const (
	RelayAttemptOpenFailed      RelayAttemptOutcome = "open_failed"
	RelayAttemptSetupFailed     RelayAttemptOutcome = "setup_failed"
	RelayAttemptCommittedFailed RelayAttemptOutcome = "committed_failed"
	RelayAttemptCommitted       RelayAttemptOutcome = "committed"
	RelayAttemptOther           RelayAttemptOutcome = "other"
)

type RecoveryAttemptOutcome string

const (
	RecoveryAttemptSuccess  RecoveryAttemptOutcome = "success"
	RecoveryAttemptStale    RecoveryAttemptOutcome = "stale"
	RecoveryAttemptRetry    RecoveryAttemptOutcome = "retry"
	RecoveryAttemptCanceled RecoveryAttemptOutcome = "canceled"
)

type PlacementOutcome string

const (
	PlacementPlaced               PlacementOutcome = "placed"
	PlacementInsufficientServices PlacementOutcome = "insufficient_services"
	PlacementCapacity             PlacementOutcome = "capacity"
	PlacementUnavailable          PlacementOutcome = "unavailable"
	PlacementStale                PlacementOutcome = "stale"
	PlacementError                PlacementOutcome = "error"
)

type DNSWorkOutcome string

const (
	DNSWorkSuccess DNSWorkOutcome = "success"
	DNSWorkPending DNSWorkOutcome = "pending"
	DNSWorkError   DNSWorkOutcome = "error"
)

type CertificateClaimOutcome string

const (
	CertificateClaimed CertificateClaimOutcome = "claimed"
	CertificateEmpty   CertificateClaimOutcome = "empty"
	CertificateError   CertificateClaimOutcome = "error"
)

type CertificateWorkOutcome string

const (
	CertificateProgress   CertificateWorkOutcome = "progress"
	CertificateRetry      CertificateWorkOutcome = "retry"
	CertificateTerminal   CertificateWorkOutcome = "terminal"
	CertificateSaveFailed CertificateWorkOutcome = "save_failed"
)

type UsageWorkOutcome string

const (
	UsageWorkSuccess UsageWorkOutcome = "success"
	UsageWorkEmpty   UsageWorkOutcome = "empty"
	UsageWorkError   UsageWorkOutcome = "error"
)

type UsageReceiverOutcome string

const (
	UsageReceiverSuccess         UsageReceiverOutcome = "success"
	UsageReceiverHTTPError       UsageReceiverOutcome = "http_error"
	UsageReceiverTransportError  UsageReceiverOutcome = "transport_error"
	UsageReceiverInvalidResponse UsageReceiverOutcome = "invalid_response"
)

type APIRequestOutcome string

const (
	APIRequestSuccess          APIRequestOutcome = "success"
	APIRequestDeadlineExceeded APIRequestOutcome = "deadline_exceeded"
	APIRequestCanceled         APIRequestOutcome = "canceled"
	APIRequestServerError      APIRequestOutcome = "server_error"
	APIRequestClientError      APIRequestOutcome = "client_error"
)
