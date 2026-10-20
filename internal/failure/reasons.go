package failure

import (
	"slices"
	"sort"
)

const (
	ConnectionTLSRejected               Reason = "TNL_CLIENT_CONNECTION_TLS_REJECTED"
	ConnectionCleanupFailed             Reason = "TNL_CLIENT_CONNECTION_CLEANUP_FAILED"
	ConnectionPortInUse                 Reason = "TNL_CLIENT_CONNECTION_PORT_IN_USE"
	ConnectionTeamBinding               Reason = "TNL_CLIENT_CONNECTION_TEAM_BINDING"
	ConnectionTransportMissing          Reason = "TNL_CLIENT_CONNECTION_TRANSPORT_MISSING"
	ConnectionHandleInvalid             Reason = "TNL_CLIENT_CONNECTION_HANDLE_INVALID"
	ConnectionExpired                   Reason = "TNL_CLIENT_CONNECTION_EXPIRED"
	ConnectionRequestInvalid            Reason = "TNL_CLIENT_CONNECTION_REQUEST_INVALID"
	ConnectionUnavailable               Reason = "TNL_CLIENT_CONNECTION_UNAVAILABLE"
	TargetDiscoveryInvalid              Reason = "TNL_CLIENT_TARGET_DISCOVERY_INVALID"
	TargetDiscoveryDenied               Reason = "TNL_CLIENT_TARGET_DISCOVERY_DENIED"
	TargetDiscoveryAuthentication       Reason = "TNL_CLIENT_TARGET_DISCOVERY_AUTHENTICATION"
	TargetDiscoveryNotFound             Reason = "TNL_CLIENT_TARGET_DISCOVERY_NOT_FOUND"
	TargetDiscoveryNotReady             Reason = "TNL_CLIENT_TARGET_DISCOVERY_NOT_READY"
	TargetDiscoveryUnavailable          Reason = "TNL_CLIENT_TARGET_DISCOVERY_UNAVAILABLE"
	TargetDiscoveryMetadata             Reason = "TNL_CLIENT_TARGET_DISCOVERY_METADATA"
	TargetDiscoveryChanged              Reason = "TNL_CLIENT_TARGET_DISCOVERY_CHANGED"
	TargetDiscoveryStale                Reason = "TNL_CLIENT_TARGET_DISCOVERY_STALE"
	AWSBootstrapInvalid                 Reason = "TNL_CLIENT_AWS_BOOTSTRAP_INVALID"
	AWSBootstrapScope                   Reason = "TNL_CLIENT_AWS_BOOTSTRAP_SCOPE"
	AWSBootstrapStateLost               Reason = "TNL_CLIENT_AWS_BOOTSTRAP_STATE_LOST"
	AWSBootstrapSecretConflict          Reason = "TNL_CLIENT_AWS_BOOTSTRAP_SECRET_CONFLICT"
	AWSBootstrapVersionConflict         Reason = "TNL_CLIENT_AWS_BOOTSTRAP_VERSION_CONFLICT"
	AWSBootstrapDenied                  Reason = "TNL_CLIENT_AWS_BOOTSTRAP_DENIED"
	AWSBootstrapAuthentication          Reason = "TNL_CLIENT_AWS_BOOTSTRAP_AUTHENTICATION"
	AWSBootstrapThrottled               Reason = "TNL_CLIENT_AWS_BOOTSTRAP_THROTTLED"
	AWSBootstrapUnavailable             Reason = "TNL_CLIENT_AWS_BOOTSTRAP_UNAVAILABLE"
	InvalidControlURL                   Reason = "TNL_CLIENT_INVALID_CONTROL_URL"
	InvalidControlPort                  Reason = "TNL_CLIENT_INVALID_CONTROL_PORT"
	InvalidAuthorityURL                 Reason = "TNL_CLIENT_INVALID_AUTHORITY_URL"
	InvalidTarget                       Reason = "TNL_CLIENT_INVALID_TARGET"
	TargetTLSRejected                   Reason = "TNL_CLIENT_TARGET_TLS_REJECTED"
	TargetUnavailable                   Reason = "TNL_CLIENT_TARGET_UNAVAILABLE"
	MissingTarget                       Reason = "TNL_CLIENT_MISSING_TARGET"
	InvalidCommand                      Reason = "TNL_CLIENT_INVALID_COMMAND"
	AppReadinessTimeout                 Reason = "TNL_CLIENT_APP_READINESS_TIMEOUT"
	AppCursorExpired                    Reason = "TNL_CLIENT_APP_CURSOR_EXPIRED"
	OutputUnavailable                   Reason = "TNL_CLIENT_OUTPUT_UNAVAILABLE"
	InitFailed                          Reason = "TNL_CLIENT_INIT_FAILED"
	TunnelUnavailable                   Reason = "TNL_CLIENT_TUNNEL_UNAVAILABLE"
	TeamUnavailable                     Reason = "TNL_CLIENT_TEAM_UNAVAILABLE"
	DomainUnavailable                   Reason = "TNL_CLIENT_DOMAIN_UNAVAILABLE"
	AdminUnavailable                    Reason = "TNL_CLIENT_ADMIN_UNAVAILABLE"
	ServiceNotConfigured                Reason = "TNL_CLIENT_SERVICE_NOT_CONFIGURED"
	InvalidTunnelFlags                  Reason = "TNL_CLIENT_INVALID_TUNNEL_FLAGS"
	ConnectModeInvalid                  Reason = "TNL_CLIENT_CONNECT_MODE_INVALID"
	ConnectNativeModeRequired           Reason = "TNL_CLIENT_CONNECT_NATIVE_MODE_REQUIRED"
	ConnectStdioProtocolInvalid         Reason = "TNL_CLIENT_CONNECT_STDIO_PROTOCOL_INVALID"
	ConnectOutputModeInvalid            Reason = "TNL_CLIENT_CONNECT_OUTPUT_MODE_INVALID"
	ConnectProtocolMismatch             Reason = "TNL_CLIENT_CONNECT_PROTOCOL_MISMATCH"
	ConnectServerRootsUnavailable       Reason = "TNL_CLIENT_CONNECT_SERVER_ROOTS_UNAVAILABLE"
	ConnectAccessRequired               Reason = "TNL_CLIENT_CONNECT_ACCESS_REQUIRED"
	DemoTargetNotAllowed                Reason = "TNL_CLIENT_DEMO_TARGET_NOT_ALLOWED"
	DemoConfigNotUsed                   Reason = "TNL_CLIENT_DEMO_CONFIG_NOT_USED"
	DemoURLManaged                      Reason = "TNL_CLIENT_DEMO_URL_MANAGED"
	DemoMustBeEphemeral                 Reason = "TNL_CLIENT_DEMO_MUST_BE_EPHEMERAL"
	DemoLocalServiceUnavailable         Reason = "TNL_CLIENT_DEMO_LOCAL_SERVICE_UNAVAILABLE"
	ProjectConfigMissing                Reason = "TNL_CLIENT_PROJECT_CONFIG_MISSING"
	ClientStateLocked                   Reason = "TNL_CLIENT_STATE_LOCKED"
	ClientStateUnavailable              Reason = "TNL_CLIENT_STATE_UNAVAILABLE"
	PublisherIdentityStateUnavailable   Reason = "TNL_CLIENT_PUBLISHER_IDENTITY_STATE_UNAVAILABLE"
	PublisherIdentityStateInvalid       Reason = "TNL_CLIENT_PUBLISHER_IDENTITY_STATE_INVALID"
	PublisherCertificateStateMissing    Reason = "TNL_CLIENT_PUBLISHER_CERTIFICATE_STATE_MISSING"
	ServiceNotInstalled                 Reason = "TNL_CLIENT_SERVICE_NOT_INSTALLED"
	InstalledPublisherSelectionMissing  Reason = "TNL_CLIENT_INSTALLED_PUBLISHER_SELECTION_MISSING"
	InstalledServiceIdentityUnavailable Reason = "TNL_CLIENT_INSTALLED_SERVICE_IDENTITY_UNAVAILABLE"
	PrivatePublisherUnavailable         Reason = "TNL_CLIENT_PRIVATE_PUBLISHER_UNAVAILABLE"
	LocalPrivateServiceUnavailable      Reason = "TNL_CLIENT_LOCAL_PRIVATE_SERVICE_UNAVAILABLE"
	InstalledTargetMissing              Reason = "TNL_CLIENT_INSTALLED_TARGET_MISSING"
	InstalledJobAmbiguous               Reason = "TNL_CLIENT_INSTALLED_JOB_AMBIGUOUS"
	DetachedNotFound                    Reason = "TNL_CLIENT_DETACHED_NOT_FOUND"
	DetachedStartFailed                 Reason = "TNL_CLIENT_DETACHED_START_FAILED"
	GuestSessionInvalid                 Reason = "TNL_CLIENT_GUEST_SESSION_INVALID"
	CurrentDirectoryUnavailable         Reason = "TNL_CLIENT_CURRENT_DIRECTORY_UNAVAILABLE"
	TeamNotFound                        Reason = "TNL_CLIENT_TEAM_NOT_FOUND"
	TeamSelectionAmbiguous              Reason = "TNL_CLIENT_TEAM_SELECTION_AMBIGUOUS"
	DomainNotAvailable                  Reason = "TNL_CLIENT_DOMAIN_NOT_AVAILABLE"
	DomainNotReady                      Reason = "TNL_CLIENT_DOMAIN_NOT_READY"
	CustomDomainsDisabled               Reason = "TNL_CLIENT_CUSTOM_DOMAINS_DISABLED"
	MemberHostnameDepthExceeded         Reason = "TNL_CLIENT_MEMBER_HOSTNAME_DEPTH_EXCEEDED"
	InvalidDomainName                   Reason = "TNL_CLIENT_INVALID_DOMAIN_NAME"
	ProjectConfigInvalid                Reason = "TNL_CLIENT_PROJECT_CONFIG_INVALID"
	CIRepositoryMetadataUnavailable     Reason = "TNL_CLIENT_CI_REPOSITORY_METADATA_UNAVAILABLE"
	ObservabilityConfigInvalid          Reason = "TNL_CLIENT_OBSERVABILITY_CONFIG_INVALID"
	PublisherDeploymentInvalid          Reason = "TNL_CLIENT_PUBLISHER_DEPLOYMENT_INVALID"
	PublisherDeploymentMetadataInvalid  Reason = "TNL_CLIENT_PUBLISHER_DEPLOYMENT_METADATA_INVALID"
	PublisherDeploymentWriteFailed      Reason = "TNL_CLIENT_PUBLISHER_DEPLOYMENT_WRITE_FAILED"
	AliasOwned                          Reason = "TNL_CLIENT_ALIAS_OWNED"
	AliasReceiverUnready                Reason = "TNL_CLIENT_ALIAS_RECEIVER_UNREADY"
	AliasNotSelected                    Reason = "TNL_CLIENT_ALIAS_NOT_SELECTED"
	AliasPolicyConflict                 Reason = "TNL_CLIENT_ALIAS_POLICY_CONFLICT"
	WebhookOwned                        Reason = "TNL_CLIENT_WEBHOOK_OWNED"
	WebhookReceiverUnready              Reason = "TNL_CLIENT_WEBHOOK_RECEIVER_UNREADY"
	WebhookNotSelected                  Reason = "TNL_CLIENT_WEBHOOK_NOT_SELECTED"
	IntegrationURLNotReady              Reason = "TNL_CLIENT_INTEGRATION_URL_NOT_READY"
	IntegrationURLLeaseExpired          Reason = "TNL_CLIENT_INTEGRATION_URL_LEASE_EXPIRED"
	WebhookNoReadyReceivers             Reason = "TNL_CLIENT_WEBHOOK_NO_READY_RECEIVERS"
	WebhookOwnerMissing                 Reason = "TNL_CLIENT_WEBHOOK_OWNER_MISSING"
	WebhookOwnerUnready                 Reason = "TNL_CLIENT_WEBHOOK_OWNER_UNREADY"
	WebhookPolicyConflict               Reason = "TNL_CLIENT_WEBHOOK_POLICY_CONFLICT"
	InitPackageManager                  Reason = "TNL_CLIENT_INIT_PACKAGE_MANAGER"
	InitFramework                       Reason = "TNL_CLIENT_INIT_FRAMEWORK"
	InvalidSetupInput                   Reason = "TNL_CLIENT_INVALID_SETUP_INPUT"
	FeedbackInputInvalid                Reason = "TNL_CLIENT_FEEDBACK_INPUT_INVALID"
	ShareInputInvalid                   Reason = "TNL_CLIENT_SHARE_INPUT_INVALID"
	PreviewNotSaved                     Reason = "TNL_CLIENT_PREVIEW_NOT_SAVED"
	PreviewStateConflict                Reason = "TNL_CLIENT_PREVIEW_STATE_CONFLICT"
	BrowserOpenFailed                   Reason = "TNL_CLIENT_BROWSER_OPEN_FAILED"
	TransportUnavailable                Reason = "TNL_CLIENT_TRANSPORT_UNAVAILABLE"
	TransportFallback                   Reason = "TNL_CLIENT_TRANSPORT_FALLBACK"
	Authentication                      Reason = "TNL_CLIENT_AUTHENTICATION_REQUIRED"
	AuthRecoveryRequired                Reason = "TNL_CLIENT_AUTH_RECOVERY_REQUIRED"
	AuthWaitTimeout                     Reason = "TNL_CLIENT_AUTH_WAIT_TIMEOUT"
	AuthOperationNotFound               Reason = "TNL_CLIENT_AUTH_OPERATION_NOT_FOUND"
	AuthCancelled                       Reason = "TNL_CLIENT_AUTH_CANCELLED"
	AuthDenied                          Reason = "TNL_CLIENT_AUTH_DENIED"
	AuthExpired                         Reason = "TNL_CLIENT_AUTH_EXPIRED"
	AuthMethodUnavailable               Reason = "TNL_CLIENT_AUTH_METHOD_UNAVAILABLE"
	AuthProviderUnavailable             Reason = "TNL_CLIENT_AUTH_PROVIDER_UNAVAILABLE"
	ServerResourceNotFound              Reason = "TNL_CLIENT_SERVER_RESOURCE_NOT_FOUND"
	ServerConflict                      Reason = "TNL_CLIENT_SERVER_CONFLICT"
	ServerDenied                        Reason = "TNL_CLIENT_SERVER_DENIED"
	ServerUnavailable                   Reason = "TNL_CLIENT_SERVER_UNAVAILABLE"
	ServerRateLimited                   Reason = "TNL_CLIENT_SERVER_RATE_LIMITED"
	GuestTrialExhausted                 Reason = "TNL_CLIENT_GUEST_TRIAL_EXHAUSTED"
	GuestDemoOnly                       Reason = "TNL_CLIENT_GUEST_DEMO_ONLY"
	GuestIssuanceLimited                Reason = "TNL_CLIENT_GUEST_ISSUANCE_LIMITED"
	GuestSignInRequired                 Reason = "TNL_CLIENT_GUEST_SIGN_IN_REQUIRED"
	GuestIPChanged                      Reason = "TNL_CLIENT_GUEST_IP_CHANGED"
	ServerResponseInvalid               Reason = "TNL_CLIENT_SERVER_RESPONSE_INVALID"
	ServerRequestInvalid                Reason = "TNL_CLIENT_SERVER_REQUEST_INVALID"
	DNSPending                          Reason = "TNL_CLIENT_DNS_PENDING"
	CertificateUnavailable              Reason = "TNL_CLIENT_CERTIFICATE_UNAVAILABLE"
	RelayLeaseStale                     Reason = "relay.lease_stale"
	InvalidRole                         Reason = "server.invalid_role"
	DatabaseUnavailable                 Reason = "server.database_unavailable"
	ServerConfigInvalid                 Reason = "server.config_invalid"
	ServerListenAddressInvalid          Reason = "server.listen_address_invalid"
	ServerDatabaseURLInvalid            Reason = "server.database_url_invalid"
	ServerStorageKeyInvalid             Reason = "server.storage_key_invalid"
	ServerACMEInvalid                   Reason = "server.acme_invalid"
	ServerOIDCInvalid                   Reason = "server.oidc_invalid"
	ServerDNSConfigInvalid              Reason = "server.dns_config_invalid"
	ServerUsageConfigInvalid            Reason = "server.usage_config_invalid"
	ServerEmailConfigInvalid            Reason = "server.email_config_invalid"
	ServerWebsiteConfigInvalid          Reason = "server.website_config_invalid"
	ServerClusterSecretInvalid          Reason = "server.cluster_secret_invalid"
	ServerConfigFileInvalid             Reason = "server.config_file_invalid"
	ServerCommandInvalid                Reason = "server.command_invalid"
	DirectDatabaseURLMissing            Reason = "server.direct_database_url_missing"
	ServerMigrationFailed               Reason = "server.migration_failed"
	ServerStartupFailed                 Reason = "server.startup_failed"
	ServerOutputUnavailable             Reason = "server.output_unavailable"
	ServerWorkerFailed                  Reason = "server.worker_failed"
	ServerIngressFailed                 Reason = "server.ingress_failed"
	ServerRelayFailed                   Reason = "server.relay_failed"
	ServerConnectionFailed              Reason = "server.connection_failed"
	ServerCertificateFailed             Reason = "server.certificate_failed"
	ServerCertificateRejected           Reason = "server.certificate_rejected"
	ServerDNSFailed                     Reason = "server.dns_failed"
	ServerDNSConflict                   Reason = "server.dns_conflict"
	ServerUsageDeliveryFailed           Reason = "server.usage_delivery_failed"
	ServerEmailDeliveryFailed           Reason = "server.email_delivery_failed"
	ServerEmailLeaseStale               Reason = "server.email_lease_stale"
	ServerStoredStateInvalid            Reason = "server.stored_state_invalid"
	ServerAPIInternal                   Reason = "server.api_internal"
	ServerIdentityProviderUnavailable   Reason = "server.identity_provider_unavailable"
	ServerAuthorityUnavailable          Reason = "server.authority_unavailable"
	BenchmarkInputInvalid               Reason = "benchmark.input_invalid"
	BenchmarkMeasurementFailed          Reason = "benchmark.measurement_failed"
	Unexpected                          Reason = "internal.unexpected"
)

const ServerControlConnectionFailed Reason = "server.control_connection_failed"

const (
	ServerDatabaseDiagnosticsUnavailable Reason = "server.database_diagnostics_unavailable"
	ServerDiagnosticsBusy                Reason = "server.diagnostics_busy"
)

var definitions = map[Reason]Definition{
	ConnectionTLSRejected:              {Class: Invalid, Message: "the native service TLS certificate could not be verified", Action: "check the managed service hostname and the client's server trust roots, then prepare connections again", Retry: RetryAfterChange},
	ConnectionCleanupFailed:            {Class: Unavailable, Message: "the native connection owner stopped with a cleanup failure", Action: "check the selected server's availability and revoke the workload session if it remains active", Retry: RetryAfterChange},
	ConnectionPortInUse:                {Class: Conflict, Message: "the service's allocated loopback port is already in use", Action: "stop the process using that port and prepare connections again", Retry: RetryAfterChange},
	ConnectionTeamBinding:              {Class: Invalid, Message: "the project has no matching applied team binding", Action: "run tnl apply as a team administrator and commit .tnl/generated/connections.json", Retry: RetryAfterChange},
	ConnectionTransportMissing:         {Class: Unavailable, Message: "this binary does not include the required native connection transport", Action: "use a tnl binary with the required connection capabilities", Retry: RetryAfterChange},
	ConnectionHandleInvalid:            {Class: Invalid, Message: "the private connection handle is not valid for this project or user", Action: "prepare connections again from the selected project", Retry: RetryAfterChange},
	ConnectionExpired:                  {Class: Unavailable, Message: "the native connection session has expired", Action: "prepare connections again within the authorized execution window", Retry: RetryAfterChange},
	ConnectionRequestInvalid:           {Class: Invalid, Message: "the native connection request is invalid", Action: "check the connection schema, project configuration, and selected services", Retry: RetryAfterChange},
	ConnectionUnavailable:              {Class: Unavailable, Message: "the native connection owner could not prepare or maintain every selected service", Action: "check service availability and prepare connections again", Retry: RetryLater},
	PublisherDeploymentMetadataInvalid: {Class: Invalid, Message: "publisher deployment metadata is incomplete or invalid", Action: "supply all TNL_DEPLOYMENT_* metadata fields from the generated deployment and use the provisioned instance", Retry: RetryAfterChange},
	AWSBootstrapInvalid:                {Class: Invalid, Message: "publisher deployment input is invalid or stale", Action: "check the customer deployment file and run tnl generate for the current project", Retry: RetryAfterChange},
	AWSBootstrapScope:                  {Class: Conflict, Message: "publisher deployment scope does not match the current project, team, or AWS account", Action: "check the applied project, selected company, AWS profile, account and region", Retry: RetryAfterChange},
	AWSBootstrapStateLost:              {Class: Conflict, Message: "publisher bootstrap state or its protected key is missing", Action: "restore the original client state before retrying this deployment; do not enroll replacement keys", Retry: RetryAfterChange},
	AWSBootstrapSecretConflict:         {Class: Conflict, Message: "the identity secret name or container belongs to another operation", Action: "check the exact secret ARN and deployment binding; select a new deployment only for a new replica identity", Retry: RetryAfterChange},
	AWSBootstrapVersionConflict:        {Class: Conflict, Message: "the pinned secret version does not match this publisher identity", Action: "restore the original secret version and protected client state; do not overwrite another identity", Retry: RetryAfterChange},
	AWSBootstrapDenied:                 {Class: Forbidden, Message: "AWS denied the publisher bootstrap operation", Action: "check Secrets Manager and KMS permissions for the selected credentials", Retry: RetryAfterChange},
	AWSBootstrapAuthentication:         {Class: Unauthenticated, Message: "AWS credentials are missing, expired, or rejected", Action: "renew the selected AWS credentials and retry bootstrap", Retry: RetryAfterChange},
	AWSBootstrapThrottled:              {Class: Unavailable, Message: "AWS throttled publisher bootstrap", Action: "wait before retrying the same deployment", Retry: RetryLater},
	AWSBootstrapUnavailable:            {Class: Unavailable, Message: "AWS publisher bootstrap could not complete its request", Action: "check network access and AWS service availability, then retry the same deployment", Retry: RetryLater},
	TargetDiscoveryInvalid:             {Class: Invalid, Message: "cloud target selector or protocol is invalid", Action: "check the assigned target declaration", Retry: RetryAfterChange},
	TargetDiscoveryDenied:              {Class: Forbidden, Message: "cloud target discovery was denied", Action: "allow the selected resource's Describe action on the publisher role", Retry: RetryAfterChange},
	TargetDiscoveryAuthentication:      {Class: Unauthenticated, Message: "cloud target credentials are unavailable or rejected", Action: "check the publisher's AWS credential chain", Retry: RetryAfterChange},
	TargetDiscoveryNotFound:            {Class: NotFound, Message: "cloud target was not found", Action: "check the declared region and resource identifier", Retry: RetryAfterChange},
	TargetDiscoveryNotReady:            {Class: Unavailable, Message: "cloud target is not ready", Action: "wait for the selected resource to become available", Retry: RetryLater},
	TargetDiscoveryUnavailable:         {Class: Unavailable, Message: "cloud target discovery is unavailable", Action: "retry when AWS is reachable", Retry: RetryLater},
	TargetDiscoveryMetadata:            {Class: Invalid, Message: "cloud target metadata or TLS trust is invalid", Action: "check the selected resource before preparing another publication", Retry: RetryAfterChange},
	TargetDiscoveryChanged:             {Class: Conflict, Message: "cloud target resource or CA changed", Action: "prepare a new publication", Retry: RetryAfterChange},
	TargetDiscoveryStale:               {Class: Stale, Message: "cloud target discovery is stale", Action: "restore publisher access to AWS before opening new connections", Retry: RetryLater},
	TargetTLSRejected: {
		Class: Invalid, Message: "target TLS could not be verified or negotiated",
		Action: "check the target protocol, target.tls.server_name, and target.tls.ca_file, then retry", Retry: RetryAfterChange,
	},
	TargetUnavailable: {
		Class: Unavailable, Message: "the publisher could not reach the target",
		Action: "check the target listener and publisher network connection, then retry", Retry: RetryLater,
	},
	AppReadinessTimeout: {Class: Unavailable, Message: "public readiness checks timed out", Action: "check tnl status and the app response, then run tnl wait again", Retry: RetryLater},
	AppCursorExpired:    {Class: Invalid, Message: "the local event cursor has expired", Action: "run tnl watch without --after to follow current events", Retry: RetryAfterChange},
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
		Class: Invalid, Message: "the service target is invalid",
		Action: "use an HTTP or HTTPS origin reachable by tnl, or a local port", Retry: RetryAfterChange,
	},
	MissingTarget: {
		Class: Invalid, Message: "a target is required",
		Action: "pass an HTTP or HTTPS origin or local port, or set publish.target in the project configuration", Retry: RetryAfterChange,
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
		Action: "run tnl check or select a configured project service", Retry: RetryAfterChange,
	},
	InvalidTunnelFlags: {
		Class: Invalid, Message: "tunnel options conflict or contain an invalid value",
		Action: "check --public-url, --name, --allow-ip, and --concurrency", Retry: RetryAfterChange,
	},
	ConnectModeInvalid: {
		Class: Invalid, Message: "connect options select incompatible modes",
		Action: "select one of --foreground, --detach, or --install; --stdio takes none of these, --listen, or --output=json", Retry: RetryAfterChange,
	},
	ConnectNativeModeRequired: {
		Class: Invalid, Message: "public HTTP and database connections print native instructions and exit",
		Action: "run tnl connect NAME without --install, --detach, --foreground, or --listen", Retry: RetryAfterChange,
	},
	ConnectStdioProtocolInvalid: {
		Class: Invalid, Message: "--stdio requires a service with the approved tcp protocol",
		Action: "omit --stdio for native HTTP and database clients; no flag changes the service's authentication", Retry: RetryAfterChange,
	},
	ConnectOutputModeInvalid: {
		Class: Invalid, Message: "--output=json is only available for finite public HTTP and database instructions",
		Action: "omit --output=json when running a listener or an opaque stream", Retry: RetryAfterChange,
	},
	ConnectProtocolMismatch: {
		Class: Invalid, Message: "--protocol differs from the approved service protocol",
		Action: "omit --protocol to use trusted service metadata; no flag changes the service's authentication", Retry: RetryAfterChange,
	},
	ConnectServerRootsUnavailable: {
		Class: NotFound, Message: "mysql needs a server CA bundle for VERIFY_IDENTITY",
		Action: "install system CA certificates or set SSL_CERT_FILE to a trusted PEM bundle, then run tnl connect again", Retry: RetryAfterChange,
	},
	ConnectAccessRequired: {
		Class: Forbidden, Message: "the current sign-in or device cannot access this service",
		Action: "run tnl auth login --team <team> to refresh company sign-in, and check device and service access before reconnecting", Retry: RetryAfterChange,
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
	PublisherIdentityStateUnavailable: {
		Class: Unavailable, Message: "tnl could not use the durable publisher identity files",
		Action: "check the identity directory's mount and available space, then retry", Retry: RetryLater,
	},
	PublisherIdentityStateInvalid: {
		Class: Invalid, Message: "the durable publisher identity files are unsafe, invalid or belong to another scope",
		Action: "check the identity directory, permissions and replica ownership, or restore its valid files", Retry: RetryAfterChange,
	},
	PublisherCertificateStateMissing: {
		Class: NotFound, Message: "this replica's durable publisher certificate state is missing",
		Action: "restore this replica's identity directory and select it with --identity-dir", Retry: RetryAfterChange,
	},
	ServiceNotInstalled: {
		Class: NotFound, Message: "the selected tnl service is not installed or running",
		Action: "log into your user session and run tnl service install, or run sudo tnl service install --system for headless publications", Retry: RetryAfterChange,
	},
	InstalledPublisherSelectionMissing: {
		Class: NotFound, Message: "this service has no saved scoped publisher grant",
		Action: "publish the service once to save its public URL, then enroll a publisher for that URL and retry --install with --enroll-key", Retry: RetryAfterChange,
	},
	InstalledServiceIdentityUnavailable: {
		Class: Unavailable, Message: "tnl could not determine the configured service's exact public hostname and team",
		Action: "sign in to resolve the selected team and domain, or configure an exact tunnel.public_url and select its publisher explicitly", Retry: RetryAfterChange,
	},
	PrivatePublisherUnavailable: {
		Class: Unavailable, Message: "the private TCP publisher is not connected to the relay service yet",
		Action: "wait for private publisher relay support before installing this service", Retry: RetryAfterChange,
	},
	LocalPrivateServiceUnavailable: {
		Class: NotFound, Message: "the local private service is not available in this worktree",
		Action: "start the app or run tnl publish with the configured service key, check visitor access, then retry tnl connect", Retry: RetryAfterChange,
	},
	InstalledTargetMissing: {
		Class: Invalid, Message: "the configured service has no fixed target to install",
		Action: "set this service's target to an address that remains valid after restart, then retry --install", Retry: RetryAfterChange,
	},
	InstalledJobAmbiguous: {
		Class: Conflict, Message: "more than one installed publication has this name",
		Action: "run tnl service list and use the job ID for start, stop, or remove", Retry: RetryAfterChange,
	},
	DetachedNotFound: {
		Class: NotFound, Message: "the detached publication is not running",
		Action: "run tnl detached list to see current publications", Retry: RetryAfterChange,
	},
	DetachedStartFailed: {
		Class: Unavailable, Message: "the detached publication did not start",
		Action: "run tnl publish without --detach to see the failure, then retry", Retry: RetryAfterChange,
	},
	GuestSessionInvalid: {
		Class: Invalid, Message: "the saved guest demo state is invalid",
		Action: "run tnl auth login or retry tnl publish --demo with a fresh --state-dir", Retry: RetryAfterChange,
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
	ProjectConfigInvalid: {
		Class: Invalid, Message: "tnl could not use the project configuration",
		Action: "run tnl check and correct the reported setting", Retry: RetryAfterChange,
	},
	CIRepositoryMetadataUnavailable: {
		Class: Invalid, Message: "ci repository metadata is unavailable for first setup",
		Action: "configure existing gh authentication with read access to this repository, then run tnl apply again", Retry: RetryAfterChange,
	},
	ObservabilityConfigInvalid: {
		Class: Invalid, Message: "operational observability configuration is invalid",
		Action: "correct the named OTEL setting or remove optional export configuration", Retry: RetryAfterChange,
	},
	PublisherDeploymentInvalid: {
		Class: Invalid, Message: "publisher deployment artifacts are missing, stale, or unsafe",
		Action: "run tnl generate with the same --output-dir; use regular files and directories without symlinks", Retry: RetryAfterChange,
	},
	PublisherDeploymentWriteFailed: {
		Class: Invalid, Message: "tnl could not write publisher deployment artifacts",
		Action: "check output directory permissions and symlinks; move custom files that conflict with generated paths, then run tnl generate", Retry: RetryAfterChange,
	},
	AliasOwned: {
		Class: Conflict, Message: "another live worktree owns this alias",
		Action: "use tnl alias use NAME --force for a deliberate handoff", Retry: RetryAfterChange,
	},
	AliasReceiverUnready: {
		Class: Unavailable, Message: "the selected alias entry service is not ready",
		Action: "start the entry service in the selected worktree and check tnl status", Retry: RetryAfterChange,
	},
	AliasNotSelected: {
		Class: Conflict, Message: "this worktree is not selected for the alias",
		Action: "release the alias from its selected worktree or select this one explicitly", Retry: RetryAfterChange,
	},
	AliasPolicyConflict: {
		Class: Conflict, Message: "another running worktree declares a different alias or uses its hostname",
		Action: "use matching alias definitions across worktrees and choose a distinct public hostname", Retry: RetryAfterChange,
	},
	WebhookOwned: {
		Class: Conflict, Message: "another running tunnel is selected for this webhook",
		Action: "run tnl webhook use NAME --force to switch, or release it from the current worktree", Retry: RetryAfterChange,
	},
	WebhookReceiverUnready: {
		Class: Unavailable, Message: "the selected webhook receiver is not ready",
		Action: "start the configured service in this worktree and wait for its public URL to be ready", Retry: RetryLater,
	},
	WebhookNotSelected: {
		Class: Conflict, Message: "this worktree is not the selected webhook receiver",
		Action: "check tnl status before releasing or switching this webhook", Retry: RetryAfterChange,
	},
	IntegrationURLNotReady: {
		Class: Unavailable, Message: "the integration URL publisher is not ready",
		Action: "keep a participating app or tnl publish tunnel running and wait for its publisher", Retry: RetryLater,
	},
	IntegrationURLLeaseExpired: {
		Class: Stale, Message: "the integration URL publisher stopped renewing its readiness",
		Action: "check the running app tunnels and restart one if the publisher does not recover", Retry: RetryLater,
	},
	WebhookNoReadyReceivers: {
		Class: Unavailable, Message: "this webhook has no ready receivers",
		Action: "start the configured service in a worktree and wait for its public URL", Retry: RetryLater,
	},
	WebhookOwnerMissing: {
		Class: Unavailable, Message: "this webhook has no selected receiver",
		Action: "run tnl webhook use NAME from a worktree with a ready service", Retry: RetryAfterChange,
	},
	WebhookOwnerUnready: {
		Class: Unavailable, Message: "the selected webhook receiver is not ready",
		Action: "wait for its tunnel to recover or run tnl webhook use NAME --force from a ready worktree", Retry: RetryLater,
	},
	WebhookPolicyConflict: {
		Class: Conflict, Message: "worktrees disagree about this webhook endpoint",
		Action: "make the endpoint declarations agree, then restart the conflicting tunnel", Retry: RetryAfterChange,
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
		Action: "start a configured app service before sharing or reading its feedback", Retry: RetryAfterChange,
	},
	PreviewStateConflict: {
		Class: Conflict, Message: "the saved preview does not match the current project",
		Action: "check the selected server, team, and project, then restart the app", Retry: RetryAfterChange,
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
	AuthRecoveryRequired: {
		Class: Conflict, Message: "login credential redemption has an uncertain outcome",
		Action: "start a new login with tnl auth login; this operation cannot be replayed", Retry: RetryAfterChange,
	},
	AuthWaitTimeout: {
		Class: Unavailable, Message: "login is still waiting for approval",
		Action: "resume with tnl auth login wait <operation-id>", Retry: RetryLater,
	},
	AuthOperationNotFound: {
		Class: NotFound, Message: "the login operation was not found for the selected server",
		Action: "check the operation ID, server, and state directory", Retry: RetryAfterChange,
	},
	AuthCancelled: {
		Class: Conflict, Message: "the login operation was cancelled",
		Action: "start a new login with tnl auth login", Retry: RetryAfterChange,
	},
	AuthDenied: {
		Class: Forbidden, Message: "login approval was denied",
		Action: "start a new login with tnl auth login", Retry: RetryAfterChange,
	},
	AuthExpired: {
		Class: Unauthenticated, Message: "the login approval code expired",
		Action: "start a new login with tnl auth login", Retry: RetryAfterChange,
	},
	AuthMethodUnavailable: {
		Class: Invalid, Message: "the selected server does not support this login method",
		Action: "use tnl auth login with a method supported by this server", Retry: RetryAfterChange,
	},
	AuthProviderUnavailable: {
		Class: Unavailable, Message: "the sign-in provider could not be reached or its signing keys are unavailable",
		Action: "check provider connectivity and resume with tnl auth login wait <operation-id>", Retry: RetryLater,
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
		Action: "run tnl auth login to publish your own app", Retry: RetryAfterChange,
	},
	GuestDemoOnly: {
		Class: Forbidden, Message: "guest access only publishes the built-in demo",
		Action: "run tnl auth login to publish your own app or change settings", Retry: RetryAfterChange,
	},
	GuestIssuanceLimited: {
		Class: RateLimited, Message: "guest demo creation is limited on this network",
		Action: "wait an hour or run tnl auth login to continue", Retry: RetryLater,
	},
	GuestSignInRequired: {
		Class: Unauthenticated, Message: "this command needs sign-in",
		Action: "run tnl auth login to manage this server, or tnl publish --demo to try the built-in demo", Retry: RetryAfterChange,
	},
	GuestIPChanged: {
		Class: Forbidden, Message: "your IP changed since this guest demo started",
		Action: "run tnl auth login to publish your own app", Retry: RetryAfterChange,
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
