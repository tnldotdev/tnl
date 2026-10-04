package failure

import "sort"

const (
	InvalidControlURL           Reason = "client.invalid_control_url"
	InvalidControlPort          Reason = "client.invalid_control_port"
	InvalidAuthorityURL         Reason = "client.invalid_authority_url"
	InvalidTarget               Reason = "client.invalid_target"
	MissingTarget               Reason = "client.missing_target"
	InvalidCommand              Reason = "client.invalid_command"
	OutputUnavailable           Reason = "client.output_unavailable"
	InitFailed                  Reason = "client.init_failed"
	TunnelUnavailable           Reason = "client.tunnel_unavailable"
	TeamUnavailable             Reason = "client.team_unavailable"
	DomainUnavailable           Reason = "client.domain_unavailable"
	AdminUnavailable            Reason = "client.admin_unavailable"
	ServiceNotConfigured        Reason = "client.service_not_configured"
	InvalidTunnelFlags          Reason = "client.invalid_tunnel_flags"
	InvalidStartupTimeout       Reason = "client.invalid_startup_timeout"
	ProjectConfigMissing        Reason = "client.project_config_missing"
	ClientStateLocked           Reason = "client.state_locked"
	ClientStateUnavailable      Reason = "client.state_unavailable"
	CurrentDirectoryUnavailable Reason = "client.current_directory_unavailable"
	TeamNotFound                Reason = "client.team_not_found"
	TeamSelectionAmbiguous      Reason = "client.team_selection_ambiguous"
	DomainNotAvailable          Reason = "client.domain_not_available"
	DomainNotReady              Reason = "client.domain_not_ready"
	InvalidDomainName           Reason = "client.invalid_domain_name"
	LoginTokenInvalid           Reason = "client.login_token_invalid"
	LoginTerminalRequired       Reason = "client.login_terminal_required"
	ProjectConfigInvalid        Reason = "client.project_config_invalid"
	InitPackageManager          Reason = "client.init_package_manager"
	InitFramework               Reason = "client.init_framework"
	InvalidSetupInput           Reason = "client.invalid_setup_input"
	BrowserOpenFailed           Reason = "client.browser_open_failed"
	TransportUnavailable        Reason = "client.transport_unavailable"
	TransportFallback           Reason = "client.transport_fallback"
	Authentication              Reason = "client.authentication_required"
	ServerResourceNotFound      Reason = "client.server_resource_not_found"
	ServerConflict              Reason = "client.server_conflict"
	ServerDenied                Reason = "client.server_denied"
	ServerUnavailable           Reason = "client.server_unavailable"
	ServerRateLimited           Reason = "client.server_rate_limited"
	ServerResponseInvalid       Reason = "client.server_response_invalid"
	ServerRequestInvalid        Reason = "client.server_request_invalid"
	DNSPending                  Reason = "client.dns_pending"
	CertificateUnavailable      Reason = "client.certificate_unavailable"
	RelayLeaseStale             Reason = "relay.lease_stale"
	InvalidRole                 Reason = "server.invalid_role"
	DatabaseUnavailable         Reason = "server.database_unavailable"
	Unexpected                  Reason = "internal.unexpected"
)

var definitions = map[Reason]Definition{
	InvalidControlURL: {
		Class: Invalid, Message: "server must be an HTTPS origin",
		Action: "use an HTTPS control URL with --server or TNL_SERVER", Retry: RetryAfterChange,
	},
	InvalidControlPort: {
		Class: Invalid, Message: "server port must be between 1 and 65535",
		Action: "check the control URL port and retry", Retry: RetryAfterChange,
	},
	InvalidAuthorityURL: {
		Class: Invalid, Message: "authority endpoint must be a canonical HTTPS origin",
		Action: "check the authority URL configured on the selected server", Retry: RetryAfterChange,
	},
	InvalidTarget: {
		Class: Invalid, Message: "the local service target is invalid",
		Action: "use an HTTP loopback address or a local port", Retry: RetryAfterChange,
	},
	MissingTarget: {
		Class: Invalid, Message: "a local target is required",
		Action: "pass a local port or set publish.target in the project configuration", Retry: RetryAfterChange,
	},
	InvalidCommand: {
		Class: Invalid, Message: "tnl could not use this command or its options",
		Action: "run tnl --help or the command's --help and correct the arguments", Retry: RetryAfterChange,
	},
	OutputUnavailable: {
		Class: Unavailable, Message: "tnl could not write the command result",
		Action: "check the output destination and retry", Retry: RetryAfterChange,
	},
	InitFailed: {
		Class: Unavailable, Message: "tnl could not finish setting up this project",
		Action: "check project files and permissions, then run tnl init again", Retry: RetryAfterChange,
	},
	TunnelUnavailable: {
		Class: Unavailable, Message: "tnl could not start or maintain this tunnel",
		Action: "check the local service, selected server, and network connection, then retry", Retry: RetryLater,
	},
	TeamUnavailable: {
		Class: Unavailable, Message: "tnl could not complete the team operation",
		Action: "check the selected team and membership, then retry", Retry: RetryAfterChange,
	},
	DomainUnavailable: {
		Class: Unavailable, Message: "tnl could not complete the domain operation",
		Action: "check the team domain and required DNS records, then retry", Retry: RetryAfterChange,
	},
	AdminUnavailable: {
		Class: Unavailable, Message: "tnl could not complete the administrator operation",
		Action: "check administrator access and control health, then retry", Retry: RetryAfterChange,
	},
	ServiceNotConfigured: {
		Class: NotFound, Message: "the selected service is not configured",
		Action: "run tnl config check or select a configured project service", Retry: RetryAfterChange,
	},
	InvalidTunnelFlags: {
		Class: Invalid, Message: "tunnel options conflict or contain an invalid value",
		Action: "check --public-url, --name, --allow-ip, --allow-provider, and --request-limit", Retry: RetryAfterChange,
	},
	InvalidStartupTimeout: {
		Class: Invalid, Message: "startup timeout must be greater than zero and at most 10 minutes",
		Action: "choose a startup timeout within that range", Retry: RetryAfterChange,
	},
	ProjectConfigMissing: {
		Class: NotFound, Message: "no project configuration file was found",
		Action: "run tnl init or select a config file with --config", Retry: RetryAfterChange,
	},
	ClientStateLocked: {
		Class: Conflict, Message: "another tnl process is using the client state",
		Action: "wait for it to finish or stop it, then retry", Retry: RetryLater,
	},
	ClientStateUnavailable: {
		Class: Unavailable, Message: "tnl could not use the client state",
		Action: "check the state directory and its permissions, then retry", Retry: RetryAfterChange,
	},
	CurrentDirectoryUnavailable: {
		Class: Unavailable, Message: "tnl could not read the working directory",
		Action: "move to an accessible project directory and retry", Retry: RetryAfterChange,
	},
	TeamNotFound: {
		Class: NotFound, Message: "team not found",
		Action: "run tnl team list and choose a team you belong to", Retry: RetryAfterChange,
	},
	TeamSelectionAmbiguous: {
		Class: Conflict, Message: "more than one team has the selected name",
		Action: "run tnl team list and select a team by ID with --team", Retry: RetryAfterChange,
	},
	DomainNotAvailable: {
		Class: NotFound, Message: "the selected domain is not available to this team",
		Action: "run tnl domain list and select a domain owned by the current team", Retry: RetryAfterChange,
	},
	DomainNotReady: {
		Class: Unavailable, Message: "the selected domain is not ready for public URLs",
		Action: "check tnl domain status and complete its required DNS records", Retry: RetryAfterChange,
	},
	InvalidDomainName: {
		Class: Invalid, Message: "the domain name is not a canonical DNS name",
		Action: "use lowercase ASCII DNS labels without a trailing dot", Retry: RetryAfterChange,
	},
	LoginTokenInvalid: {
		Class: Unauthenticated, Message: "the login token is invalid",
		Action: "get a new login token for this server and retry", Retry: RetryAfterChange,
	},
	LoginTerminalRequired: {
		Class: Invalid, Message: "login-token authentication requires an interactive terminal",
		Action: "run tnl login in a terminal or supply TNL_LOGIN_TOKEN", Retry: RetryAfterChange,
	},
	ProjectConfigInvalid: {
		Class: Invalid, Message: "tnl could not use the project configuration",
		Action: "run tnl config check and correct the reported setting", Retry: RetryAfterChange,
	},
	InitPackageManager: {
		Class: Invalid, Message: "tnl could not select a package manager",
		Action: "set packageManager to pnpm, npm, yarn, or bun, then run tnl init again", Retry: RetryAfterChange,
	},
	InitFramework: {
		Class: Invalid, Message: "tnl could not determine the project's framework",
		Action: "choose the framework integration for the project, then run tnl init again", Retry: RetryAfterChange,
	},
	InvalidSetupInput: {
		Class: Invalid, Message: "the entered value is not valid for this prompt",
		Action: "enter one of the shown values or press enter to skip", Retry: RetryAfterChange,
	},
	BrowserOpenFailed: {
		Class: Unavailable, Message: "tnl could not open the public URL in a browser",
		Action: "open the printed public URL manually", Retry: NoRetry,
	},
	TransportUnavailable: {
		Class: Unavailable, Message: "a publisher connection could not be established",
		Action: "check connectivity to the assigned relay and retry", Retry: RetryLater,
	},
	TransportFallback: {
		Class: Degraded, Message: "QUIC did not establish before TLS/TCP; continuing over TLS/TCP",
		Action: "the tunnel remains available over TLS/TCP", Retry: NoRetry,
	},
	Authentication: {
		Class: Unauthenticated, Message: "tnl could not authenticate this request",
		Action: "log in again or check the supplied access token", Retry: RetryAfterChange,
	},
	ServerResourceNotFound: {
		Class: NotFound, Message: "the requested resource was not found on the selected server",
		Action: "check the selected server, team, and resource ID", Retry: RetryAfterChange,
	},
	ServerConflict: {
		Class: Conflict, Message: "the requested operation conflicts with the server's current state",
		Action: "inspect the public URL or team state and retry when it changes", Retry: RetryAfterChange,
	},
	ServerDenied: {
		Class: Forbidden, Message: "the selected identity is not allowed to perform this operation",
		Action: "check the team membership and selected credentials", Retry: RetryAfterChange,
	},
	ServerUnavailable: {
		Class: Unavailable, Message: "tnl could not reach the selected server",
		Action: "check the server address and connectivity, then retry", Retry: RetryLater,
	},
	ServerRateLimited: {
		Class: RateLimited, Message: "the server is limiting requests",
		Action: "wait for the retry interval before sending another request", Retry: RetryLater,
	},
	ServerResponseInvalid: {
		Class: Internal, Message: "the server sent a response tnl could not use",
		Action: "check the selected server and its version, then retry", Retry: RetryAfterChange,
	},
	ServerRequestInvalid: {
		Class: Invalid, Message: "the server rejected this request",
		Action: "check the command options and selected resource, then retry", Retry: RetryAfterChange,
	},
	DNSPending: {
		Class: Unavailable, Message: "the domain's DNS setup is not ready",
		Action: "check its DNS records and retry after they propagate", Retry: RetryLater,
	},
	CertificateUnavailable: {
		Class: Unavailable, Message: "the public URL certificate is not ready",
		Action: "leave the tunnel running while certificate issuance retries", Retry: RetryLater,
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
