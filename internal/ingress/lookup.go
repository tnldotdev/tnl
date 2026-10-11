package ingress

// LookupReason describes why ingress cannot use a public URL projection.
type LookupReason string

const (
	LookupCurrent            LookupReason = ""
	LookupInvalidHostname    LookupReason = "invalid_hostname"
	LookupUninitialized      LookupReason = "uninitialized"
	LookupMissing            LookupReason = "missing"
	LookupNotFound           LookupReason = "not_found"
	LookupTombstone          LookupReason = "tombstone"
	LookupPublicURLExpired   LookupReason = "public_url_expired"
	LookupIngressUnavailable LookupReason = "ingress_unavailable"
	LookupInvalidProjection  LookupReason = "invalid_projection"
	LookupNoBackends         LookupReason = "unavailable"
)

type ForwardingFailureReason string

const (
	ForwardingNoBackend      ForwardingFailureReason = "no_backend"
	ForwardingCommittedWrite ForwardingFailureReason = "committed_write"
)
