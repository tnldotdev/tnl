package observability

import "slices"

type ServiceKind uint8

const (
	Service ServiceKind = iota + 1
	PublicURL
)

func (v ServiceKind) String() string {
	return enumString([]string{"", "service", "public_url"}, int(v))
}

// NormalizeServiceKind translates the service wire value at the boundary.
func NormalizeServiceKind(value string) ServiceKind {
	switch value {
	case "service":
		return Service
	case "public_url":
		return PublicURL
	default:
		return 0
	}
}

// these ordinal types cannot be narrowed from a string by a cast. parsers omit
// unknown external values; zero is always unspecified, never an invented value.
type Protocol uint8

const (
	ProtocolHTTP Protocol = iota + 1
	ProtocolPostgres
	ProtocolMySQL
	ProtocolTCP
	ProtocolKubernetes
)

var protocols = []string{"", "http", "postgres", "mysql", "tcp", "kubernetes"}

func (v Protocol) String() string { return enumString(protocols, int(v)) }
func ParseProtocol(value string) (Protocol, bool) {
	i := slices.Index(protocols, value)
	if i <= 0 {
		return 0, false
	}
	return Protocol(i), true
}

type TransportValue uint8

const (
	TransportQUIC TransportValue = iota + 1
	TransportTLSTCP
)

var transports = []string{"", "quic", "tls-tcp"}

func (v TransportValue) String() string { return enumString(transports, int(v)) }
func ParseTransport(value string) (TransportValue, bool) {
	i := slices.Index(transports, value)
	if i <= 0 {
		return 0, false
	}
	return TransportValue(i), true
}

type Role uint8

const (
	RoleControl Role = iota + 1
	RoleIngress
	RoleRelay
	RoleStandalone
	RolePublisher
	RoleClient
	RoleAccounts
	RoleCollector
)

var roles = []string{"", "control", "ingress", "relay", "standalone", "publisher", "client", "accounts", "collector"}

func (v Role) String() string { return enumString(roles, int(v)) }
func ParseRole(value string) (Role, bool) {
	i := slices.Index(roles, value)
	if i <= 0 {
		return 0, false
	}
	return Role(i), true
}

type Outcome uint8

const (
	Success Outcome = iota + 1
	Denied
	Rejected
	Timeout
	Canceled
	Error
)

var outcomes = []string{"", "success", "denied", "rejected", "timeout", "canceled", "error"}

func (v Outcome) String() string { return enumString(outcomes, int(v)) }

type LifecycleState uint8

const (
	StateReady LifecycleState = iota + 1
	StateNotReady
	StateActive
	StateDraining
	StateFresh
	StateLastSuccess
	StateStale
	StateFailed
	StateDenied
	StateAdmitted
	StatePending
	StateAvailable
	StateInstalled
	StateCleanupComplete
	StatePublished
	StateRemoved
	StateReleased
	StateConfigured
	StateClaimed
	StateQuarantined
	StateOpen
	StateConnecting
	StateCertificateMissing
	StateConnectionsMissing
	StateCertificateAndConnectionsMissing
	StateDNSPending
	StateDNSFailed
	StateError
)

var states = []string{"", "ready", "not_ready", "active", "draining", "fresh", "last_success", "stale", "failed", "denied", "admitted", "pending", "available", "installed", "cleanup_complete", "published", "removed", "released", "configured", "claimed", "quarantined", "open", "connecting", "certificate_missing", "connections_missing", "certificate_and_connections_missing", "dns_pending", "dns_failed", "error"}

func (v LifecycleState) String() string { return enumString(states, int(v)) }
func ParseState(value string) (LifecycleState, bool) {
	i := slices.Index(states, value)
	if i <= 0 {
		return 0, false
	}
	return LifecycleState(i), true
}

type LifecycleEvent uint8

const (
	EventQueued LifecycleEvent = iota + 1
	EventDelivered
	EventRetry
	EventDropped
	EventAccepted
	EventDuplicate
	EventConnected
	EventExpectedClose
	EventUnexpectedClose
	EventOperationalFailure
	EventIncomplete
	EventFinalized
	EventRetried
	EventRejected
	EventIssued
	EventAllocated
	EventReady
	EventExpired
	EventReadyLimit
	EventCleanup
	EventOpened
	EventClosed
	EventFailed
	EventBound
	EventRegistered
	EventPublicationReady
	EventBusy
	EventCompleted
	EventPartialFailed
)

var events = []string{"", "queued", "delivered", "retry", "dropped", "accepted", "duplicate", "connected", "expected_close", "unexpected_close", "operational_failure", "incomplete", "finalized", "retried", "rejected", "issued", "allocated", "ready", "expired", "ready_limit", "cleanup", "opened", "closed", "failed", "bound", "registered", "publication_ready", "busy", "completed", "partial_failed"}

func (v LifecycleEvent) String() string { return enumString(events, int(v)) }
func ParseEvent(value string) (LifecycleEvent, bool) {
	i := slices.Index(events, value)
	if i <= 0 {
		return 0, false
	}
	return LifecycleEvent(i), true
}

func enumString(values []string, index int) string {
	if index <= 0 || index >= len(values) {
		return ""
	}
	return values[index]
}

// operationName accepts authored literals at public span boundaries, but callers
// cannot cast a dynamic string to this unexported type. dynamic domain adapters
// must validate their own closed vocabulary before constructing it here.
type operationName string

func (v operationName) String() string { return string(v) }
