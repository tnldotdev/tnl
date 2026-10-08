package failure

import (
	"slices"
	"sort"
)

const (
	InvalidControlURL                 Reason = "TNL_CLIENT_INVALID_CONTROL_URL"
	InvalidControlPort                Reason = "TNL_CLIENT_INVALID_CONTROL_PORT"
	InvalidAuthorityURL               Reason = "TNL_CLIENT_INVALID_AUTHORITY_URL"
	InvalidTarget                     Reason = "TNL_CLIENT_INVALID_TARGET"
	MissingTarget                     Reason = "TNL_CLIENT_MISSING_TARGET"
	InvalidCommand                    Reason = "TNL_CLIENT_INVALID_COMMAND"
	OutputUnavailable                 Reason = "TNL_CLIENT_OUTPUT_UNAVAILABLE"
	InitFailed                        Reason = "TNL_CLIENT_INIT_FAILED"
	TunnelUnavailable                 Reason = "TNL_CLIENT_TUNNEL_UNAVAILABLE"
	TeamUnavailable                   Reason = "TNL_CLIENT_TEAM_UNAVAILABLE"
	DomainUnavailable                 Reason = "TNL_CLIENT_DOMAIN_UNAVAILABLE"
	AdminUnavailable                  Reason = "TNL_CLIENT_ADMIN_UNAVAILABLE"
	ServiceNotConfigured              Reason = "TNL_CLIENT_SERVICE_NOT_CONFIGURED"
	InvalidTunnelFlags                Reason = "TNL_CLIENT_INVALID_TUNNEL_FLAGS"
	DemoTargetNotAllowed              Reason = "TNL_CLIENT_DEMO_TARGET_NOT_ALLOWED"
	DemoConfigNotUsed                 Reason = "TNL_CLIENT_DEMO_CONFIG_NOT_USED"
	DemoURLManaged                    Reason = "TNL_CLIENT_DEMO_URL_MANAGED"
	DemoMustBeEphemeral               Reason = "TNL_CLIENT_DEMO_MUST_BE_EPHEMERAL"
	DemoLocalServiceUnavailable       Reason = "TNL_CLIENT_DEMO_LOCAL_SERVICE_UNAVAILABLE"
	InvalidStartupTimeout             Reason = "TNL_CLIENT_INVALID_STARTUP_TIMEOUT"
	ProjectConfigMissing              Reason = "TNL_CLIENT_PROJECT_CONFIG_MISSING"
	ClientStateLocked                 Reason = "TNL_CLIENT_STATE_LOCKED"
	ClientStateUnavailable            Reason = "TNL_CLIENT_STATE_UNAVAILABLE"
	GuestSessionInvalid               Reason = "TNL_CLIENT_GUEST_SESSION_INVALID"
	CurrentDirectoryUnavailable       Reason = "TNL_CLIENT_CURRENT_DIRECTORY_UNAVAILABLE"
	TeamNotFound                      Reason = "TNL_CLIENT_TEAM_NOT_FOUND"
	TeamSelectionAmbiguous            Reason = "TNL_CLIENT_TEAM_SELECTION_AMBIGUOUS"
	DomainNotAvailable                Reason = "TNL_CLIENT_DOMAIN_NOT_AVAILABLE"
	DomainNotReady                    Reason = "TNL_CLIENT_DOMAIN_NOT_READY"
	CustomDomainsDisabled             Reason = "TNL_CLIENT_CUSTOM_DOMAINS_DISABLED"
	MemberHostnameDepthExceeded       Reason = "TNL_CLIENT_MEMBER_HOSTNAME_DEPTH_EXCEEDED"
	InvalidDomainName                 Reason = "TNL_CLIENT_INVALID_DOMAIN_NAME"
	LoginTokenInvalid                 Reason = "TNL_CLIENT_LOGIN_TOKEN_INVALID"
	LoginTerminalRequired             Reason = "TNL_CLIENT_LOGIN_TERMINAL_REQUIRED"
	ProjectConfigInvalid              Reason = "TNL_CLIENT_PROJECT_CONFIG_INVALID"
	InitPackageManager                Reason = "TNL_CLIENT_INIT_PACKAGE_MANAGER"
	InitFramework                     Reason = "TNL_CLIENT_INIT_FRAMEWORK"
	InvalidSetupInput                 Reason = "TNL_CLIENT_INVALID_SETUP_INPUT"
	FeedbackInputInvalid              Reason = "TNL_CLIENT_FEEDBACK_INPUT_INVALID"
	ShareInputInvalid                 Reason = "TNL_CLIENT_SHARE_INPUT_INVALID"
	PreviewNotSaved                   Reason = "TNL_CLIENT_PREVIEW_NOT_SAVED"
	PreviewStateConflict              Reason = "TNL_CLIENT_PREVIEW_STATE_CONFLICT"
	DevProcessFailed                  Reason = "TNL_CLIENT_DEV_PROCESS_FAILED"
	DevSocketUnavailable              Reason = "TNL_CLIENT_DEV_SOCKET_UNAVAILABLE"
	BrowserOpenFailed                 Reason = "TNL_CLIENT_BROWSER_OPEN_FAILED"
	TransportUnavailable              Reason = "TNL_CLIENT_TRANSPORT_UNAVAILABLE"
	TransportFallback                 Reason = "TNL_CLIENT_TRANSPORT_FALLBACK"
	Authentication                    Reason = "TNL_CLIENT_AUTHENTICATION_REQUIRED"
	ServerResourceNotFound            Reason = "TNL_CLIENT_SERVER_RESOURCE_NOT_FOUND"
	ServerConflict                    Reason = "TNL_CLIENT_SERVER_CONFLICT"
	ServerDenied                      Reason = "TNL_CLIENT_SERVER_DENIED"
	ServerUnavailable                 Reason = "TNL_CLIENT_SERVER_UNAVAILABLE"
	ServerRateLimited                 Reason = "TNL_CLIENT_SERVER_RATE_LIMITED"
	GuestTrialExhausted               Reason = "TNL_CLIENT_GUEST_TRIAL_EXHAUSTED"
	GuestDemoOnly                     Reason = "TNL_CLIENT_GUEST_DEMO_ONLY"
	GuestIssuanceLimited              Reason = "TNL_CLIENT_GUEST_ISSUANCE_LIMITED"
	GuestSignInRequired               Reason = "TNL_CLIENT_GUEST_SIGN_IN_REQUIRED"
	GuestIPChanged                    Reason = "TNL_CLIENT_GUEST_IP_CHANGED"
	ServerResponseInvalid             Reason = "TNL_CLIENT_SERVER_RESPONSE_INVALID"
	ServerRequestInvalid              Reason = "TNL_CLIENT_SERVER_REQUEST_INVALID"
	DNSPending                        Reason = "TNL_CLIENT_DNS_PENDING"
	CertificateUnavailable            Reason = "TNL_CLIENT_CERTIFICATE_UNAVAILABLE"
	RelayLeaseStale                   Reason = "relay.lease_stale"
	InvalidRole                       Reason = "server.invalid_role"
	DatabaseUnavailable               Reason = "server.database_unavailable"
	ServerConfigInvalid               Reason = "server.config_invalid"
	ServerListenAddressInvalid        Reason = "server.listen_address_invalid"
	ServerDatabaseURLInvalid          Reason = "server.database_url_invalid"
	ServerStorageKeyInvalid           Reason = "server.storage_key_invalid"
	ServerACMEInvalid                 Reason = "server.acme_invalid"
	ServerOIDCInvalid                 Reason = "server.oidc_invalid"
	ServerDNSConfigInvalid            Reason = "server.dns_config_invalid"
	ServerUsageConfigInvalid          Reason = "server.usage_config_invalid"
	ServerEmailConfigInvalid          Reason = "server.email_config_invalid"
	ServerWebsiteConfigInvalid        Reason = "server.website_config_invalid"
	ServerClusterSecretInvalid        Reason = "server.cluster_secret_invalid"
	ServerLoginTokenInvalid           Reason = "server.login_token_invalid"
	ServerConfigFileInvalid           Reason = "server.config_file_invalid"
	ServerCommandInvalid              Reason = "server.command_invalid"
	DirectDatabaseURLMissing          Reason = "server.direct_database_url_missing"
	ServerMigrationFailed             Reason = "server.migration_failed"
	ServerStartupFailed               Reason = "server.startup_failed"
	ServerOutputUnavailable           Reason = "server.output_unavailable"
	ServerWorkerFailed                Reason = "server.worker_failed"
	ServerIngressFailed               Reason = "server.ingress_failed"
	ServerRelayFailed                 Reason = "server.relay_failed"
	ServerConnectionFailed            Reason = "server.connection_failed"
	ServerCertificateFailed           Reason = "server.certificate_failed"
	ServerCertificateRejected         Reason = "server.certificate_rejected"
	ServerDNSFailed                   Reason = "server.dns_failed"
	ServerDNSConflict                 Reason = "server.dns_conflict"
	ServerUsageDeliveryFailed         Reason = "server.usage_delivery_failed"
	ServerEmailDeliveryFailed         Reason = "server.email_delivery_failed"
	ServerEmailLeaseStale             Reason = "server.email_lease_stale"
	ServerStoredStateInvalid          Reason = "server.stored_state_invalid"
	ServerAPIInternal                 Reason = "server.api_internal"
	ServerIdentityProviderUnavailable Reason = "server.identity_provider_unavailable"
	ServerAuthorityUnavailable        Reason = "server.authority_unavailable"
	BenchmarkInputInvalid             Reason = "benchmark.input_invalid"
	BenchmarkMeasurementFailed        Reason = "benchmark.measurement_failed"
	Unexpected                        Reason = "internal.unexpected"
)

const ServerControlConnectionFailed Reason = "server.control_connection_failed"

const (
	ServerDatabaseDiagnosticsUnavailable Reason = "server.database_diagnostics_unavailable"
	ServerDiagnosticsBusy                Reason = "server.diagnostics_busy"
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
	DemoTargetNotAllowed: {
		Class: Invalid, Message: "the built-in demo starts its own local service",
		Action: "remove the service or target argument from tnl publish --demo", Retry: RetryAfterChange,
	},
	DemoConfigNotUsed: {
		Class: Invalid, Message: "the built-in demo does not use project configuration",
		Action: "remove --config from tnl publish --demo", Retry: RetryAfterChange,
	},
	DemoURLManaged: {
		Class: Invalid, Message: "the built-in demo chooses its own public URL",
		Action: "remove --name or --public-url from tnl publish --demo", Retry: RetryAfterChange,
	},
	DemoMustBeEphemeral: {
		Class: Invalid, Message: "the built-in demo needs an ephemeral public URL",
		Action: "remove --ephemeral=false from tnl publish --demo", Retry: RetryAfterChange,
	},
	DemoLocalServiceUnavailable: {
		Class: Unavailable, Message: "tnl could not start the local demo",
		Action: "check that loopback networking is available, then retry", Retry: RetryLater,
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
		Cases: []Case{{ID: "permission-denied", Description: "tnl cannot access the local client state directory.",
			Action: "check permissions on the state directory, then retry", DiagramDetail: "state directory access denied"}},
	},
	GuestSessionInvalid: {
		Class: Invalid, Message: "the saved guest demo state is invalid",
		Action: "run tnl login or retry tnl publish --demo with a fresh --state-dir", Retry: RetryAfterChange,
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
	CustomDomainsDisabled: {
		Class: Forbidden, Message: "this server does not allow adding custom domains",
		Action: "publish on a domain already available to your team", Retry: RetryAfterChange,
	},
	MemberHostnameDepthExceeded: {
		Class: Forbidden, Message: "this hostname exceeds the server's member URL depth limit on its managed domain",
		Action: "use fewer labels beneath your namespace", Retry: RetryAfterChange,
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
	FeedbackInputInvalid: {
		Class: Invalid, Message: "feedback ID, cursor, or message is invalid",
		Action: "use an ID from tnl feedback list, a nonnegative cursor, and a message of at most 4000 bytes", Retry: RetryAfterChange,
	},
	ShareInputInvalid: {
		Class: Invalid, Message: "share URL or lifetime is invalid",
		Action: "select a public URL ID, hostname, or HTTPS origin and a lifetime greater than zero and at most 30d", Retry: RetryAfterChange,
	},
	PreviewNotSaved: {
		Class: NotFound, Message: "the project does not have a saved preview",
		Action: "select the configured project and run tnl dev before sharing or reading its feedback", Retry: RetryAfterChange,
	},
	PreviewStateConflict: {
		Class: Conflict, Message: "the saved preview does not match the current project",
		Action: "check the selected server, team, and project, then run tnl dev again", Retry: RetryAfterChange,
	},
	DevProcessFailed: {
		Class: Unavailable, Message: "the development server command could not start or stopped",
		Action: "check the command and its child output, then restart tnl dev", Retry: RetryAfterChange,
	},
	DevSocketUnavailable: {
		Class: Unavailable, Message: "tnl could not use its development session socket",
		Action: "check the local runtime directory and permissions, then restart tnl dev", Retry: RetryAfterChange,
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
		Cases: []Case{
			{ID: "timeout", Description: "the selected server did not respond before the request timed out.",
				Action: "check network connectivity and server health, then retry", DiagramDetail: "server response timed out"},
			{ID: "connection-refused", Description: "a connection to the selected server was refused.",
				Action: "check the selected control URL and server listener, then retry", DiagramDetail: "server refused connection"},
		},
	},
	ServerRateLimited: {
		Class: RateLimited, Message: "the server is limiting requests",
		Action: "wait for the retry interval before sending another request", Retry: RetryLater,
	},
	GuestTrialExhausted: {
		Class: Forbidden, Message: "this guest demo trial has ended",
		Action: "run tnl login to publish your own app", Retry: RetryAfterChange,
	},
	GuestDemoOnly: {
		Class: Forbidden, Message: "guest access only publishes the built-in demo",
		Action: "run tnl login to publish your own app or change settings", Retry: RetryAfterChange,
	},
	GuestIssuanceLimited: {
		Class: RateLimited, Message: "guest demo creation is limited on this network",
		Action: "wait an hour or run tnl login to continue", Retry: RetryLater,
	},
	GuestSignInRequired: {
		Class: Unauthenticated, Message: "this command needs sign-in",
		Action: "run tnl login to manage this server, or tnl publish --demo to try the built-in demo", Retry: RetryAfterChange,
	},
	GuestIPChanged: {
		Class: Forbidden, Message: "your IP changed since this guest demo started",
		Action: "run tnl login to publish your own app", Retry: RetryAfterChange,
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
	ServerConfigInvalid: {
		Class: Invalid, Message: "server configuration is invalid",
		Action: "run tnld config check and correct the reported setting", Retry: RetryAfterChange,
	},
	ServerListenAddressInvalid: {
		Class: Invalid, Message: "listen address must be a canonical host and port",
		Action: "set a host:port address with a port between 1 and 65535", Retry: RetryAfterChange,
	},
	ServerDatabaseURLInvalid: {
		Class: Invalid, Message: "database URL must be a pooled PostgreSQL URL",
		Action: "set the pooled runtime URL and reserve TNLD_DATABASE_DIRECT_URL for tnld migrate", Retry: RetryAfterChange,
	},
	ServerStorageKeyInvalid: {
		Class: Invalid, Message: "storage key is missing or invalid",
		Action: "set an unpadded base64url 32-byte key for control, then retry", Retry: RetryAfterChange,
	},
	ServerACMEInvalid: {
		Class: Invalid, Message: "ACME certificate settings are incomplete or invalid",
		Action: "check TNLD_ACME_DIRECTORY_URL, TNLD_ACME_EMAIL, and TNLD_ACME_ACCEPT_TERMS", Retry: RetryAfterChange,
	},
	ServerOIDCInvalid: {
		Class: Invalid, Message: "OIDC authentication settings are incomplete or invalid",
		Action: "check TNLD_OIDC_ISSUER, TNLD_OIDC_CLIENT_ID, login flow, and scopes", Retry: RetryAfterChange,
	},
	ServerDNSConfigInvalid: {
		Class: Invalid, Message: "DNS automation settings are incomplete or invalid",
		Action: "check Route 53 zone IDs, region, and ingress IP addresses", Retry: RetryAfterChange,
	},
	ServerUsageConfigInvalid: {
		Class: Invalid, Message: "public URL usage receiver settings are invalid",
		Action: "configure both a valid usage URL and token or omit both", Retry: RetryAfterChange,
	},
	ServerEmailConfigInvalid: {
		Class: Invalid, Message: "invitation email settings are incomplete or invalid",
		Action: "configure an HTTPS TNLD_EMAIL_URL and matching TNLD_WEBHOOK_SECRET or omit both", Retry: RetryAfterChange,
	},
	ServerWebsiteConfigInvalid: {
		Class: Invalid, Message: "website identity settings are incomplete or invalid",
		Action: "configure TNLD_OIDC_ISSUER and a valid TNLD_WEB_SERVICE_SECRET", Retry: RetryAfterChange,
	},
	ServerClusterSecretInvalid: {
		Class: Invalid, Message: "cluster secret configuration is invalid for this role",
		Action: "check TNLD_CLUSTER_SECRET and the selected role", Retry: RetryAfterChange,
	},
	ServerLoginTokenInvalid: {
		Class: Invalid, Message: "built-in authority login token is missing or invalid",
		Action: "configure TNLD_LOGIN_TOKEN", Retry: RetryAfterChange,
	},
	ServerConfigFileInvalid: {
		Class: Invalid, Message: "tnld could not read the configuration file",
		Action: "use a readable YAML or JSON file with a tnld section", Retry: RetryAfterChange,
	},
	ServerCommandInvalid: {
		Class: Invalid, Message: "tnld could not use this command or its flags",
		Action: "run tnld --help and correct the command", Retry: RetryAfterChange,
	},
	DirectDatabaseURLMissing: {
		Class: Invalid, Message: "direct database URL is required for migration",
		Action: "set a direct PostgreSQL URL with migration permissions, then rerun tnld migrate", Retry: RetryAfterChange,
	},
	ServerMigrationFailed: {
		Class: Unavailable, Message: "tnld could not migrate the database",
		Action: "check PostgreSQL connectivity, migration permissions, and the database schema version", Retry: RetryAfterChange,
	},
	ServerStartupFailed: {
		Class: Unavailable, Message: "tnld could not start the configured role",
		Action: "check role listeners, control reachability, and required credentials", Retry: RetryAfterChange,
	},
	ServerOutputUnavailable: {
		Class: Unavailable, Message: "tnld could not write the command output",
		Action: "check the output destination and retry", Retry: RetryAfterChange,
	},
	ServerWorkerFailed: {
		Class: Unavailable, Message: "background work failed and will be retried",
		Action: "check process health and the affected service", Retry: RetryLater,
	},
	ServerIngressFailed: {
		Class: Unavailable, Message: "ingress could not serve a visitor connection",
		Action: "check ingress health, routing, and connected relays", Retry: RetryLater,
	},
	ServerRelayFailed: {
		Class: Unavailable, Message: "relay forwarding failed",
		Action: "check relay health and publisher connections", Retry: RetryLater,
	},
	ServerConnectionFailed: {
		Class: Unavailable, Message: "a publisher or relay connection failed",
		Action: "check the network path and current connection assignment", Retry: RetryLater,
	},
	ServerControlConnectionFailed: {
		Class: Unavailable, Message: "ingress or relay could not reach control",
		Action: "check the private control listener and cluster authentication if retries continue", Retry: RetryLater,
	},
	ServerCertificateFailed: {
		Class: Unavailable, Message: "certificate work failed",
		Action: "check ACME access and DNS validation, then retry", Retry: RetryLater,
	},
	ServerCertificateRejected: {
		Class: Conflict, Message: "certificate issuance or validation failed permanently",
		Action: "check the ACME order, certificate plan, and DNS challenge before retrying", Retry: RetryAfterChange,
	},
	ServerDNSFailed: {
		Class: Unavailable, Message: "DNS work failed",
		Action: "check Route 53 access and DNS authority, then retry", Retry: RetryLater,
	},
	ServerDNSConflict: {
		Class: Conflict, Message: "DNS records or zone ownership conflict with this public URL",
		Action: "inspect zone delegation, ownership records, and existing address records", Retry: RetryAfterChange,
	},
	ServerUsageDeliveryFailed: {
		Class: Unavailable, Message: "usage delivery failed",
		Action: "check the configured usage receiver and retry", Retry: RetryLater,
	},
	ServerEmailDeliveryFailed: {
		Class: Unavailable, Message: "invitation email work failed and will be retried",
		Action: "check PostgreSQL and the configured mailer, then retry", Retry: RetryLater,
	},
	ServerEmailLeaseStale: {
		Class: Stale, Message: "the invitation email lease is no longer current",
		Action: "discard this claim and let the current worker complete delivery", Retry: NoRetry,
	},
	ServerStoredStateInvalid: {
		Class: Internal, Message: "control could not use its stored state",
		Action: "check the storage key and database state before retrying", Retry: RetryAfterChange,
	},
	ServerAPIInternal: {
		Class: Internal, Message: "server API request failed unexpectedly",
		Action: "check process health and correlate the request ID with service diagnostics", Retry: RetryLater,
	},
	ServerIdentityProviderUnavailable: {
		Class: Unavailable, Message: "the identity provider is unavailable",
		Action: "check OIDC discovery, signing keys, and provider connectivity", Retry: RetryLater,
	},
	ServerAuthorityUnavailable: {
		Class: Unavailable, Message: "the authority API is unavailable",
		Action: "check authority health, authentication, and connectivity", Retry: RetryLater,
	},
	BenchmarkInputInvalid: {
		Class: Invalid, Message: "benchmark inputs are incomplete or invalid",
		Action: "check tnlbench --help, the workload plan, and explicit approval inputs", Retry: RetryAfterChange,
	},
	ServerDatabaseDiagnosticsUnavailable: {
		Class: Unavailable, Message: "the database diagnostic snapshot could not be collected",
		Action: "check PostgreSQL, the pooler, and diagnostic connection access", Retry: RetryLater,
	},
	ServerDiagnosticsBusy: {
		Class: Conflict, Message: "a database diagnostic snapshot is already in progress",
		Action: "wait for the current snapshot before collecting another", Retry: RetryLater,
	},
	BenchmarkMeasurementFailed: {
		Class: Unavailable, Message: "the benchmark could not complete its measurement",
		Action: "check the local generator, publisher connections, and server health", Retry: RetryAfterChange,
	},
	Unexpected: {
		Class: Internal, Message: "the operation failed unexpectedly",
		Action: "retry; if the failure continues, report it to the server operator", Retry: RetryLater,
	},
}

// DefinitionFor reports the text and retry policy for one known reason.
func DefinitionFor(reason Reason) (Definition, bool) {
	definition, found := definitions[reason]
	definition.Cases = slices.Clone(definition.Cases)
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
