package config

import (
	"errors"
	"fmt"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	ingresspool "github.com/tnldotdev/tnl/internal/ingress/pool"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
)

const defaultACMEDirectoryURL = "https://acme-v02.api.letsencrypt.org/directory"

// Role selects the role hosted by one tnld process.
type Role string

const (
	RoleStandalone Role = "standalone"
	RoleControl    Role = "control"
	RoleIngress    Role = "ingress"
	RoleRelay      Role = "relay"

	minimumAccessTokenLifetime  = 5 * time.Minute
	maximumAccessTokenLifetime  = 30 * 24 * time.Hour
	maximumRefreshTokenLifetime = 365 * 24 * time.Hour
)

func (r Role) RunsControl() bool { return r == RoleStandalone || r == RoleControl }
func (r Role) RunsIngress() bool { return r == RoleStandalone || r == RoleIngress }
func (r Role) RunsRelay() bool   { return r == RoleStandalone || r == RoleRelay }

// Config configures one tnld process. migration configuration is intentionally
// absent: tnld migrate reads only TNLD_DATABASE_DIRECT_URL.
type Config struct {
	Role Role `name:"role" env:"TNLD_ROLE" default:"standalone" enum:"standalone,control,ingress,relay" help:"Process role: ${enum}."`

	DatabaseURL   string `name:"database-url" env:"TNLD_DATABASE_URL" help:"Pooled PostgreSQL URL used by control and standalone."`
	MetricsListen string `name:"metrics-listen" env:"TNLD_METRICS_LISTEN" default:"127.0.0.1:9090" help:"Private Prometheus listen address; empty disables metrics."`

	ControlListen         string   `name:"control-listen" env:"TNLD_CONTROL_LISTEN" help:"Private HTTP backend for the deployment's control HTTPS proxy."`
	ControlTrustedProxies []string `name:"control-trusted-proxies" env:"TNLD_CONTROL_TRUSTED_PROXIES" default:"127.0.0.1/32,::1/128" help:"Exact trusted control HTTPS proxy peer CIDRs."`
	ControlClientIPHeader string   `name:"control-client-ip-header" env:"TNLD_CONTROL_CLIENT_IP_HEADER" default:"X-Forwarded-For" enum:"X-Forwarded-For,Fly-Client-IP" help:"Source header overwritten by the trusted control HTTPS proxy."`
	PrivateControlListen  string   `name:"private-control-listen" env:"TNLD_PRIVATE_CONTROL_LISTEN" help:"Private control API listen address for ingress and relays."`
	IngressListen         string   `name:"ingress-listen" env:"TNLD_INGRESS_LISTEN" help:"Public visitor TCP listen address."`
	RelayTCPListen        string   `name:"relay-tcp-listen" env:"TNLD_RELAY_TCP_LISTEN" help:"Public TLS/TCP publisher-connection listen address."`
	RelayUDPListen        string   `name:"relay-udp-listen" env:"TNLD_RELAY_UDP_LISTEN" help:"Public QUIC publisher-connection listen address."`
	InternalRelayListen   string   `name:"internal-relay-listen" env:"TNLD_INTERNAL_RELAY_LISTEN" help:"Internal forwarding listen address."`
	DNSServer             string   `name:"dns-server" env:"TNLD_DNS_SERVER" help:"DNS resolver used to verify custom domains. Defaults to the system resolver."`

	ServerDomain                      string                `name:"server-domain" env:"TNLD_SERVER_DOMAIN" help:"Infrastructure DNS suffix used to derive control, ingress, and relay hostnames."`
	ControlURL                        string                `name:"control-url" env:"TNLD_CONTROL_URL" help:"External HTTPS origin of the control deployment proxy; defaults to https://control.<server-domain>."`
	ControlHostname                   string                `name:"control-hostname" env:"TNLD_CONTROL_HOSTNAME" help:"Control API hostname used by ingress and relay processes."`
	PrivateControlAddress             string                `name:"private-control-address" env:"TNLD_PRIVATE_CONTROL_ADDRESS" help:"Optional private control host and port dialed by ingress and relay processes."`
	ManagedDomain                     string                `name:"managed-domain" env:"TNLD_MANAGED_DOMAIN" help:"Server-controlled domain used for namespaces."`
	ManagedURLMode                    naming.ManagedURLMode `name:"managed-url-mode" env:"TNLD_MANAGED_URL_MODE" default:"simple" enum:"simple,generated" help:"Managed-domain public URL names: ${enum}."`
	ManagedDomainMaxMemberChildLabels int                   `name:"managed-domain-max-member-child-labels" env:"TNLD_MANAGED_DOMAIN_MAX_MEMBER_CHILD_LABELS" default:"0" help:"Maximum labels beneath a member namespace on the managed domain; 0 uses DNS length limits only."`
	CustomDomainsEnabled              bool                  `name:"custom-domains-enabled" env:"TNLD_CUSTOM_DOMAINS_ENABLED" help:"Allow teams to add custom domains; requires managed DNS automation."`

	ControlTLSCertificateFile   string `name:"private-control-tls-certificate-file" env:"TNLD_PRIVATE_CONTROL_TLS_CERTIFICATE_FILE" type:"path" help:"Certificate chain for authenticated internal control HTTPS."`
	ControlTLSPrivateKeyFile    string `name:"private-control-tls-private-key-file" env:"TNLD_PRIVATE_CONTROL_TLS_PRIVATE_KEY_FILE" type:"path" help:"Private key for authenticated internal control HTTPS."`
	RelayTLSCertificateFile     string `name:"relay-tls-certificate-file" env:"TNLD_RELAY_TLS_CERTIFICATE_FILE" type:"path" help:"Optional static relay transport certificate chain."`
	RelayTLSPrivateKeyFile      string `name:"relay-tls-private-key-file" env:"TNLD_RELAY_TLS_PRIVATE_KEY_FILE" type:"path" help:"Optional static relay transport private key."`
	ACMEDirectoryURL            string `name:"acme-directory-url" env:"TNLD_ACME_DIRECTORY_URL" help:"ACME directory URL for automatic public certificates."`
	ACMEEmail                   string `name:"acme-email" env:"TNLD_ACME_EMAIL" help:"ACME account contact email."`
	ACMEAcceptTerms             bool   `name:"acme-accept-terms" env:"TNLD_ACME_ACCEPT_TERMS" help:"Explicitly accept the ACME directory terms."`
	ACMEProfile                 string `name:"acme-profile" env:"TNLD_ACME_PROFILE" default:"tlsserver" help:"ACME certificate profile."`
	PublicURLCertificateWorkers int    `name:"public-url-certificate-workers" env:"TNLD_PUBLIC_URL_CERTIFICATE_WORKERS" default:"8" help:"Concurrent public URL certificate workers per control process (1-8)."`

	OIDCIssuer            string            `name:"oidc-issuer" env:"TNLD_OIDC_ISSUER" help:"OIDC issuer used by the authority."`
	OIDCClientID          string            `name:"oidc-client-id" env:"TNLD_OIDC_CLIENT_ID" help:"OIDC client ID used by the authority."`
	OIDCClientSecret      string            `name:"oidc-client-secret" env:"TNLD_OIDC_CLIENT_SECRET" help:"Optional secret for control's OIDC server client."`
	OIDCAdmissionFile     string            `name:"oidc-admission-file" env:"TNLD_OIDC_ADMISSION_FILE" type:"path" help:"JSON admission rules for the configured direct OIDC issuer."`
	InitialAdministrators []string          `name:"initial-administrator" env:"TNLD_INITIAL_ADMINISTRATORS" help:"Exact subject at the configured OIDC issuer; grants administrator once."`
	InitialTeamOwners     map[string]string `name:"initial-team-owner" env:"TNLD_INITIAL_TEAM_OWNERS" help:"Organization team=subject at the configured OIDC issuer; seeds ownership once."`
	DefaultTeam           string            `name:"default-team" env:"TNLD_DEFAULT_TEAM" help:"Initial team selected for explicitly eligible identities."`
	DefaultTeamMembers    []string          `name:"default-team-member" env:"TNLD_DEFAULT_TEAM_MEMBERS" help:"Exact OIDC subject eligible for initial default-team membership; applied once."`
	WebServiceSecret      string            `name:"web-service-secret" env:"TNLD_WEB_SERVICE_SECRET" help:"Scoped credential for identity-context and website invitation operations."`
	OIDCScopes            []string          `name:"oidc-scope" env:"TNLD_OIDC_SCOPES" help:"OIDC scope requested by clients; repeat for each scope."`
	AccessTokenLifetime   time.Duration     `name:"access-token-lifetime" env:"TNLD_ACCESS_TOKEN_LIFETIME" default:"1h" help:"Lifetime of newly issued access tokens."`
	RefreshTokenLifetime  time.Duration     `name:"refresh-token-lifetime" env:"TNLD_REFRESH_TOKEN_LIFETIME" default:"720h" help:"Absolute lifetime of newly issued control sessions."`
	GuestDemoEnabled      bool              `name:"guest-demo-enabled" env:"TNLD_GUEST_DEMO_ENABLED" help:"Allow limited anonymous tnl publish --demo runs."`

	PublicURLUsageURL   string `name:"public-url-usage-url" env:"TNLD_PUBLIC_URL_USAGE_URL" help:"Public URL usage receiver base URL."`
	PublicURLUsageToken string `name:"public-url-usage-token" env:"TNLD_PUBLIC_URL_USAGE_TOKEN" help:"Service token for the public URL usage receiver."`
	EmailURL            string `name:"email-url" env:"TNLD_EMAIL_URL" help:"HTTPS origin of the invitation email receiver."`
	WebhookSecret       string `name:"webhook-secret" env:"TNLD_WEBHOOK_SECRET" help:"Shared secret for invitation email delivery."`

	Route53Region        string   `name:"route53-region" env:"TNLD_ROUTE53_REGION" default:"us-east-1" help:"AWS region used to sign Route 53 requests."`
	Route53ManagedZoneID string   `name:"route53-managed-zone-id" env:"TNLD_ROUTE53_MANAGED_ZONE_ID" help:"Existing Route 53 hosted zone ID for the managed domain; enables DNS automation."`
	Route53ServerZoneID  string   `name:"route53-server-zone-id" env:"TNLD_ROUTE53_SERVER_ZONE_ID" help:"Existing Route 53 hosted zone ID for the server domain; enables relay certificate DNS-01."`
	IngressIPv4Addresses []string `name:"ingress-ipv4-address" env:"TNLD_INGRESS_IPV4_ADDRESSES" help:"Stable ingress IPv4 address published in owned public URL records; repeat for each address."`
	IngressIPv6Addresses []string `name:"ingress-ipv6-address" env:"TNLD_INGRESS_IPV6_ADDRESSES" help:"Stable ingress IPv6 address published in owned public URL records; repeat for each address."`

	ClusterSecret         string `name:"cluster-secret" env:"TNLD_CLUSTER_SECRET" help:"Current shared secret for private communication among control, ingress, and relays."`
	ClusterSecretPrevious string `name:"cluster-secret-previous" env:"TNLD_CLUSTER_SECRET_PREVIOUS" help:"Previous cluster secret accepted only during rotation."`
	StorageKey            string `name:"storage-key" env:"TNLD_STORAGE_KEY" help:"Unpadded base64url AES-256 key used to encrypt recoverable PostgreSQL secrets."`
	StorageKeyPrevious    string `name:"storage-key-previous" env:"TNLD_STORAGE_KEY_PREVIOUS" help:"Previous storage key retained only during re-encryption."`

	TrafficDefaultConnections        int           `name:"traffic-default-connections" env:"TNLD_TRAFFIC_DEFAULT_CONNECTIONS" default:"32" help:"Default concurrent visitor connections per public URL publish run on each ingress process."`
	TrafficDefaultRate               int           `name:"traffic-default-rate" env:"TNLD_TRAFFIC_DEFAULT_RATE" default:"20" help:"Default new visitor connections per traffic rate period."`
	TrafficDefaultRatePer            time.Duration `name:"traffic-default-rate-per" env:"TNLD_TRAFFIC_DEFAULT_RATE_PER" default:"1s" help:"Default visitor connection rate period."`
	TrafficDefaultBurst              int           `name:"traffic-default-burst" env:"TNLD_TRAFFIC_DEFAULT_BURST" default:"40" help:"Default new visitor connection burst."`
	TrafficDefaultUploadBytes        int64         `name:"traffic-default-upload-bytes" env:"TNLD_TRAFFIC_DEFAULT_UPLOAD_BYTES" default:"8388608" help:"Default encrypted visitor upload bytes per second."`
	TrafficDefaultDownloadBytes      int64         `name:"traffic-default-download-bytes" env:"TNLD_TRAFFIC_DEFAULT_DOWNLOAD_BYTES" default:"16777216" help:"Default encrypted visitor download bytes per second."`
	TrafficDefaultTotalConnections   int64         `name:"traffic-default-total-connections" env:"TNLD_TRAFFIC_DEFAULT_TOTAL_CONNECTIONS" default:"0" help:"Default total visitor connections per publish run and ingress process; 0 is unlimited."`
	TrafficDefaultTotalUploadBytes   int64         `name:"traffic-default-total-upload-bytes" env:"TNLD_TRAFFIC_DEFAULT_TOTAL_UPLOAD_BYTES" default:"0" help:"Default total encrypted upload bytes per publish run and ingress process; 0 is unlimited."`
	TrafficDefaultTotalDownloadBytes int64         `name:"traffic-default-total-download-bytes" env:"TNLD_TRAFFIC_DEFAULT_TOTAL_DOWNLOAD_BYTES" default:"0" help:"Default total encrypted download bytes per publish run and ingress process; 0 is unlimited."`
	TrafficMaxConnections            int           `name:"traffic-max-connections" env:"TNLD_TRAFFIC_MAX_CONNECTIONS" default:"128" help:"Maximum selected concurrent visitor connections per publish run."`
	TrafficMaxRate                   int           `name:"traffic-max-rate" env:"TNLD_TRAFFIC_MAX_RATE" default:"100" help:"Maximum selected new visitor connections per maximum traffic rate period."`
	TrafficMaxRatePer                time.Duration `name:"traffic-max-rate-per" env:"TNLD_TRAFFIC_MAX_RATE_PER" default:"1s" help:"Rate period used by the operator connection rate ceiling."`
	TrafficMaxBurst                  int           `name:"traffic-max-burst" env:"TNLD_TRAFFIC_MAX_BURST" default:"200" help:"Maximum selected visitor connection burst."`
	TrafficMaxUploadBytes            int64         `name:"traffic-max-upload-bytes" env:"TNLD_TRAFFIC_MAX_UPLOAD_BYTES" default:"67108864" help:"Maximum selected encrypted visitor upload bytes per second."`
	TrafficMaxDownloadBytes          int64         `name:"traffic-max-download-bytes" env:"TNLD_TRAFFIC_MAX_DOWNLOAD_BYTES" default:"134217728" help:"Maximum selected encrypted visitor download bytes per second."`
	TrafficMaxTotalConnections       int64         `name:"traffic-max-total-connections" env:"TNLD_TRAFFIC_MAX_TOTAL_CONNECTIONS" default:"0" help:"Maximum selected total connections per publish run and ingress process; 0 is unlimited."`
	TrafficMaxTotalUploadBytes       int64         `name:"traffic-max-total-upload-bytes" env:"TNLD_TRAFFIC_MAX_TOTAL_UPLOAD_BYTES" default:"0" help:"Maximum selected total encrypted upload bytes per publish run and ingress process; 0 is unlimited."`
	TrafficMaxTotalDownloadBytes     int64         `name:"traffic-max-total-download-bytes" env:"TNLD_TRAFFIC_MAX_TOTAL_DOWNLOAD_BYTES" default:"0" help:"Maximum selected total encrypted download bytes per publish run and ingress process; 0 is unlimited."`
	TrafficSourceConnections         int           `name:"traffic-source-connections" env:"TNLD_TRAFFIC_SOURCE_CONNECTIONS" default:"64" help:"Concurrent visitor connections per IPv4 address or IPv6 /64 on each ingress process."`
	TrafficSourceRate                int           `name:"traffic-source-rate" env:"TNLD_TRAFFIC_SOURCE_RATE" default:"30" help:"Visitor connection attempts per source per second."`
	TrafficSourceBurst               int           `name:"traffic-source-burst" env:"TNLD_TRAFFIC_SOURCE_BURST" default:"60" help:"Visitor connection attempt burst per source."`
	TrafficProcessRate               int           `name:"traffic-process-rate" env:"TNLD_TRAFFIC_PROCESS_RATE" default:"200" help:"Visitor connection attempts per ingress process per second."`
	TrafficProcessBurst              int           `name:"traffic-process-burst" env:"TNLD_TRAFFIC_PROCESS_BURST" default:"400" help:"Visitor connection attempt burst per ingress process."`
	TrafficProcessUploadBytes        int64         `name:"traffic-process-upload-bytes" env:"TNLD_TRAFFIC_PROCESS_UPLOAD_BYTES" default:"268435456" help:"Encrypted visitor upload bytes per second per ingress process."`
	TrafficProcessDownloadBytes      int64         `name:"traffic-process-download-bytes" env:"TNLD_TRAFFIC_PROCESS_DOWNLOAD_BYTES" default:"268435456" help:"Encrypted visitor download bytes per second per ingress process."`
	PendingConnectionLimit           int           `name:"pending-connection-limit" env:"TNLD_PENDING_CONNECTION_LIMIT" default:"64" help:"Concurrent visitors awaiting authorization per ingress process."`
	PendingURLConnectionLimit        int           `name:"pending-url-connection-limit" env:"TNLD_PENDING_URL_CONNECTION_LIMIT" default:"8" help:"Concurrent visitors awaiting authorization per public URL."`
	PendingSourceConnectionLimit     int           `name:"pending-source-connection-limit" env:"TNLD_PENDING_SOURCE_CONNECTION_LIMIT" default:"4" help:"Concurrent visitors awaiting authorization per source."`
	PendingTimeout                   time.Duration `name:"pending-timeout" env:"TNLD_PENDING_TIMEOUT" default:"10s" help:"Maximum time a visitor may await authorization."`
	PendingUploadBytes               int64         `name:"pending-upload-bytes" env:"TNLD_PENDING_UPLOAD_BYTES" default:"65536" help:"Encrypted upload byte budget while awaiting authorization."`
	PendingDownloadBytes             int64         `name:"pending-download-bytes" env:"TNLD_PENDING_DOWNLOAD_BYTES" default:"131072" help:"Encrypted download byte budget while awaiting authorization."`
	PendingURLRate                   int           `name:"pending-url-rate" env:"TNLD_PENDING_URL_RATE" default:"5" help:"Pending visitor attempts per public URL per second."`
	PendingURLBurst                  int           `name:"pending-url-burst" env:"TNLD_PENDING_URL_BURST" default:"10" help:"Pending visitor attempt burst per public URL."`
	PendingSourceRate                int           `name:"pending-source-rate" env:"TNLD_PENDING_SOURCE_RATE" default:"3" help:"Pending visitor attempts per source per second."`
	PendingSourceBurst               int           `name:"pending-source-burst" env:"TNLD_PENDING_SOURCE_BURST" default:"6" help:"Pending visitor attempt burst per source."`

	IngressID            string         `name:"ingress-id" env:"TNLD_INGRESS_ID" help:"Stable ingress process identity."`
	IngressPoolID        ingresspool.ID `name:"ingress-pool-id" env:"TNLD_INGRESS_POOL_ID" default:"ingress-a" help:"Ingress pool served by this ingress process."`
	ServicePortRanges    []string       `name:"service-port-ranges" env:"TNLD_SERVICE_PORT_RANGES" default:"20000-20015" help:"Managed TCP ports exposed by this ingress pool: 1-128 non-overlapping declarations, at most 256 ports from 1024 to 65535. Direct ingress binds every port; proxied ingress requires destination metadata."`
	RelayServiceID       string         `name:"relay-service-id" env:"TNLD_RELAY_SERVICE_ID" help:"Stable relay service identity for this relay process."`
	RelayID              string         `name:"relay-id" env:"TNLD_RELAY_ID" help:"Stable relay process identity."`
	RelayAddress         string         `name:"relay-address" env:"TNLD_RELAY_ADDRESS" help:"Relay address advertised by this relay service."`
	InternalRelayAddress string         `name:"internal-relay-address" env:"TNLD_INTERNAL_RELAY_ADDRESS" help:"Internal hostname and port advertised by this relay process."`

	ClientHelloConnectionLimit       int           `name:"client-hello-connection-limit" env:"TNLD_CLIENT_HELLO_CONNECTION_LIMIT" default:"-1" help:"Maximum simultaneous public connection metadata and TLS ClientHello inspections (default: automatic)."`
	StandaloneControlConnectionLimit int           `name:"standalone-control-connection-limit" env:"TNLD_STANDALONE_CONTROL_CONNECTION_LIMIT" default:"-1" help:"Maximum control connections handed off by standalone, held until close (default: automatic)."`
	StandaloneRelayConnectionLimit   int           `name:"standalone-relay-connection-limit" env:"TNLD_STANDALONE_RELAY_CONNECTION_LIMIT" default:"-1" help:"Maximum relay TCP connections handed off by standalone, held until close (default: automatic)."`
	VisitorConnectionLimit           int64         `name:"visitor-connection-limit" env:"TNLD_VISITOR_CONNECTION_LIMIT" default:"-1" help:"Maximum concurrent visitor connections (default: automatic)."`
	PublisherConnectionLimit         int64         `name:"publisher-connection-limit" env:"TNLD_PUBLISHER_CONNECTION_LIMIT" default:"-1" help:"Maximum publisher connections held by one relay process (default: automatic)."`
	RelayStreamCapacity              int64         `name:"relay-stream-capacity" env:"TNLD_RELAY_STREAM_CAPACITY" default:"-1" help:"Maximum concurrent visitor streams held by one relay process (default: automatic)."`
	RequireProxyHeader               bool          `name:"require-proxy-header" env:"TNLD_REQUIRE_PROXY_HEADER" help:"Require one trusted outer PROXY v2 header on ingress TCP traffic."`
	IngressTrustedProxies            []string      `name:"ingress-trusted-proxies" env:"TNLD_INGRESS_TRUSTED_PROXIES" help:"Exact trusted peers supplying ingress PROXY v2 source and destination metadata."`
	QUICMaxIncomingStreams           int64         `name:"quic-max-incoming-streams" env:"TNLD_QUIC_MAX_INCOMING_STREAMS" default:"-1" help:"Maximum incoming QUIC streams per publisher connection (default: relay stream capacity)."`
	QUICIdleTimeout                  time.Duration `name:"quic-idle-timeout" env:"TNLD_QUIC_IDLE_TIMEOUT" default:"45s" help:"Publisher connection QUIC idle timeout."`
	IngressLeaseDuration             time.Duration `name:"ingress-lease-duration" env:"TNLD_INGRESS_LEASE_DURATION" default:"30s" help:"Control-owned ingress lease duration."`
	RelayLeaseDuration               time.Duration `name:"relay-lease-duration" env:"TNLD_RELAY_LEASE_DURATION" default:"30s" help:"Control-owned relay lease duration."`
	LeaseRenewalInterval             time.Duration `name:"lease-renewal-interval" env:"TNLD_LEASE_RENEWAL_INTERVAL" default:"10s" help:"Ingress and relay lease renewal interval."`
	ControlRetryInterval             time.Duration `name:"control-retry-interval" env:"TNLD_CONTROL_RETRY_INTERVAL" default:"1s" help:"Delay before retrying a transient control failure."`
	RoutingTableWait                 time.Duration `name:"routing-table-wait" env:"TNLD_ROUTING_TABLE_WAIT" default:"25s" help:"Maximum wait for ingress routing-table updates."`
	DrainTimeout                     time.Duration `name:"drain-timeout" env:"TNLD_DRAIN_TIMEOUT" default:"30s" help:"Graceful connection drain deadline."`
}

func (c Config) Validate() (retErr error) {
	defer func() {
		if retErr != nil {
			if _, typed := failure.Of(retErr); !typed {
				retErr = failure.Wrap("validate server configuration", failure.ServerConfigInvalid, retErr)
			}
		}
	}()
	if !c.Role.RunsControl() && !c.Role.RunsIngress() && !c.Role.RunsRelay() {
		return failure.Wrap("validate server role", failure.InvalidRole, errors.New("role must be standalone, control, ingress, or relay"))
	}
	if _, err := c.ServicePortInventory(); err != nil {
		return err
	}
	if c.RequireProxyHeader {
		if !c.Role.RunsIngress() {
			return errors.New("PROXY v2 metadata is valid only for ingress listeners")
		}
		if _, err := proxyproto.TrustedPeers(c.IngressTrustedProxies); err != nil {
			return err
		}
	}
	if err := ValidateTraffic(c.TrafficDefaults(), c.TrafficCeiling()); err != nil {
		return err
	}
	if _, _, err := ValidateIngressTraffic(c.IngressTraffic(), c.IngressPending()); err != nil {
		return err
	}
	if c.Role.RunsControl() {
		if err := c.validateControl(); err != nil {
			return err
		}
	} else {
		if c.CustomDomainsEnabled || c.ManagedDomainMaxMemberChildLabels != 0 {
			return errors.New("domain policy settings are valid only for control and standalone")
		}
		if c.DatabaseURL != "" {
			return errors.New("ingress and relay roles cannot receive a database URL")
		}
		if c.OIDCIssuer != "" || c.OIDCClientID != "" || c.OIDCClientSecret != "" || c.OIDCAdmissionFile != "" || len(c.InitialAdministrators) > 0 || len(c.InitialTeamOwners) > 0 || c.DefaultTeam != "" || len(c.DefaultTeamMembers) > 0 || c.ControlTLSCertificateFile != "" || c.ControlTLSPrivateKeyFile != "" {
			return errors.New("ingress and relay roles cannot receive control authentication or TLS configuration")
		}
		if err := validateControlHostname(c.ControlHostname); err != nil {
			return err
		}
		if c.PrivateControlAddress != "" {
			if err := validateDialAddress(c.PrivateControlAddress); err != nil {
				return fmt.Errorf("private control address: %w", err)
			}
		}
		if _, err := serviceapi.NewBearerSecrets(c.ClusterSecret, c.ClusterSecretPrevious); err != nil {
			return failure.Wrap("validate cluster secret", failure.ServerClusterSecretInvalid, err)
		}
		if c.EmailURL != "" || c.WebhookSecret != "" || c.WebServiceSecret != "" || c.StorageKey != "" || c.StorageKeyPrevious != "" ||
			c.Route53ManagedZoneID != "" || c.Route53ServerZoneID != "" ||
			len(c.IngressIPv4Addresses) != 0 || len(c.IngressIPv6Addresses) != 0 {
			return errors.New("ingress and relay roles cannot receive hosted, storage, or DNS provider configuration")
		}
	}
	if c.Role == RoleIngress && !validProcessID(c.IngressID) {
		return errors.New("ingress ID is required and must be canonical")
	}
	if c.Role == RoleRelay {
		if !validProcessID(c.RelayServiceID) || !validProcessID(c.RelayID) {
			return errors.New("relay service ID and relay ID are required and must be canonical")
		}
		if err := validateRelayAddress(c.RelayAddress); err != nil {
			return err
		}
		if err := validateListenAddress(c.InternalRelayAddress); err != nil {
			return fmt.Errorf("internal relay address: %w", err)
		}
	}
	if (c.RelayTLSCertificateFile == "") != (c.RelayTLSPrivateKeyFile == "") {
		return errors.New("relay TLS certificate and private key must be configured together")
	}
	if c.Role != RoleRelay && c.Role != RoleStandalone && (c.RelayTLSCertificateFile != "" || c.RelayTLSPrivateKeyFile != "") {
		return errors.New("relay TLS overrides are valid only for relay and standalone roles")
	}
	for _, listener := range []struct {
		name    string
		setting failure.Setting
		address string
	}{
		{"metrics", failure.SettingMetricsListen, c.MetricsListen},
		{"control", failure.SettingControlListen, c.ControlListen},
		{"private control", failure.SettingPrivateControlListen, c.PrivateControlListen},
		{"ingress", failure.SettingIngressListen, c.IngressListen},
		{"relay TCP", failure.SettingRelayTCPListen, c.RelayTCPListen},
		{"relay UDP", failure.SettingRelayUDPListen, c.RelayUDPListen},
		{"internal relay", failure.SettingInternalRelayListen, c.InternalRelayListen},
		{"DNS server", failure.SettingDNSServer, c.DNSServer},
	} {
		if err := validateListenAddress(listener.address); err != nil {
			return failure.WrapSetting(failure.Operation("validate "+listener.name+" listen address"),
				failure.ServerListenAddressInvalid, listener.setting, err)
		}
	}
	if c.ClientHelloConnectionLimit <= 0 ||
		c.StandaloneControlConnectionLimit <= 0 || c.StandaloneRelayConnectionLimit <= 0 {
		return errors.New("ingress admission capacities must be positive")
	}
	if c.PublicURLCertificateWorkers < 1 || c.PublicURLCertificateWorkers > 8 {
		return errors.New("public URL certificate workers must be between 1 and 8")
	}
	if c.VisitorConnectionLimit <= 0 || c.PublisherConnectionLimit <= 0 ||
		c.RelayStreamCapacity <= 0 || c.QUICMaxIncomingStreams <= 0 {
		return errors.New("connection and stream capacities must be positive")
	}
	if c.IngressLeaseDuration <= 0 || c.RelayLeaseDuration <= 0 || c.LeaseRenewalInterval <= 0 ||
		c.LeaseRenewalInterval >= c.IngressLeaseDuration || c.LeaseRenewalInterval >= c.RelayLeaseDuration ||
		c.ControlRetryInterval <= 0 || c.RoutingTableWait <= 0 || c.RoutingTableWait > 25*time.Second ||
		c.RoutingTableWait%time.Second != 0 || c.DrainTimeout <= 0 ||
		c.QUICIdleTimeout <= 0 {
		return errors.New("lease, routing-table, transport, or drain timing is invalid")
	}
	return nil
}
