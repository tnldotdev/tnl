package failure

import "sort"

const (
	InvalidControlURL   Reason = "client.invalid_control_url"
	InvalidTarget       Reason = "client.invalid_target"
	ClientStateLocked   Reason = "client.state_locked"
	Authentication      Reason = "client.authentication_required"
	RelayLeaseStale     Reason = "relay.lease_stale"
	InvalidRole         Reason = "server.invalid_role"
	DatabaseUnavailable Reason = "server.database_unavailable"
	Unexpected          Reason = "internal.unexpected"
)

var definitions = map[Reason]Definition{
	InvalidControlURL: {
		Class: Invalid, Message: "server must be an HTTPS origin",
		Action: "use an HTTPS control URL with --server or TNL_SERVER", Retry: RetryAfterChange,
	},
	InvalidTarget: {
		Class: Invalid, Message: "the local service target is invalid",
		Action: "use an HTTP loopback address or a local port", Retry: RetryAfterChange,
	},
	ClientStateLocked: {
		Class: Conflict, Message: "another tnl process is using the client state",
		Action: "wait for it to finish or stop it, then retry", Retry: RetryLater,
	},
	Authentication: {
		Class: Unauthenticated, Message: "tnl could not authenticate this request",
		Action: "log in again or check the supplied access token", Retry: RetryAfterChange,
	},
	RelayLeaseStale: {
		Class: Stale, Message: "the relay lease is no longer current",
		Action: "register a new relay process run", Retry: RetryAfterChange,
	},
	InvalidRole: {
		Class: Invalid, Message: "server role is invalid",
		Action: "set the role to standalone, control, ingress, or relay", Retry: RetryAfterChange,
	},
	DatabaseUnavailable: {
		Class: Unavailable, Message: "control cannot reach PostgreSQL",
		Action: "check the database address and connection, then retry", Retry: RetryLater,
	},
	Unexpected: {
		Class: Internal, Message: "the operation failed unexpectedly",
		Action: "retry; if the failure continues, report it to the server operator", Retry: RetryLater,
	},
}

// DefinitionFor reports the text and retry policy for one known reason.
func DefinitionFor(reason Reason) (Definition, bool) {
	definition, found := definitions[reason]
	return definition, found
}

// Reasons returns every defined reason for adapter-coverage checks.
func Reasons() []Reason {
	reasons := make([]Reason, 0, len(definitions))
	for reason := range definitions {
		reasons = append(reasons, reason)
	}
	sort.Slice(reasons, func(i, j int) bool { return reasons[i] < reasons[j] })
	return reasons
}
