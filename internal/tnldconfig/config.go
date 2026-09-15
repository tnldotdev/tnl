package tnldconfig

import (
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/internal/storagekey"
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

type OIDCLoginFlow string

const (
	OIDCLoginFlowDeviceCode            OIDCLoginFlow = "device_code"
	OIDCLoginFlowAuthorizationCodePKCE OIDCLoginFlow = "authorization_code_pkce"
)

func (r Role) RunsControl() bool { return r == RoleStandalone || r == RoleControl }
func (r Role) RunsIngress() bool { return r == RoleStandalone || r == RoleIngress }
func (r Role) RunsRelay() bool   { return r == RoleStandalone || r == RoleRelay }

// Config configures one tnld process. Migration configuration is intentionally
// absent: tnld migrate reads only TNLD_DATABASE_DIRECT_URL.
type Config struct {
	Mode Role `name:"mode" env:"TNLD_MODE" default:"standalone" enum:"standalone,control,ingress,relay" help:"Process role: ${enum}."`

	DatabaseURL   string `name:"database-url" env:"TNLD_DATABASE_URL" help:"Pooled PostgreSQL URL used by control and standalone."`
	MetricsListen string `name:"metrics-listen" env:"TNLD_METRICS_LISTEN" default:"127.0.0.1:9090" help:"Private Prometheus listen address; empty disables metrics."`

	ControlListen        string `name:"control-listen" env:"TNLD_CONTROL_LISTEN" help:"Public control HTTPS listen address."`
	PrivateControlListen string `name:"private-control-listen" env:"TNLD_PRIVATE_CONTROL_LISTEN" help:"Private cluster-authenticated ingress and relay API listen address."`
	IngressListen        string `name:"ingress-listen" env:"TNLD_INGRESS_LISTEN" help:"Public visitor TCP listen address."`
	RelayTCPListen       string `name:"relay-tcp-listen" env:"TNLD_RELAY_TCP_LISTEN" help:"Public TLS/TCP publisher-connection listen address."`
	RelayUDPListen       string `name:"relay-udp-listen" env:"TNLD_RELAY_UDP_LISTEN" help:"Public QUIC publisher-connection listen address."`
	InternalRelayListen  string `name:"internal-relay-listen" env:"TNLD_INTERNAL_RELAY_LISTEN" help:"Internal forwarding listen address."`
	DNSServer            string `name:"dns-server" env:"TNLD_DNS_SERVER" help:"DNS resolver used for authoritative verification; defaults to the system resolver."`

	ServerDomain            string   `name:"server-domain" env:"TNLD_SERVER_DOMAIN" help:"Infrastructure DNS suffix used to derive control, ingress, and relay hostnames."`
	ControlHostname         string   `name:"control-hostname" env:"TNLD_CONTROL_HOSTNAME" help:"Control API hostname used by ingress and relay processes."`
	ManagedDeploymentDomain string   `name:"managed-deployment-domain" env:"TNLD_MANAGED_DEPLOYMENT_DOMAIN" help:"Managed public route DNS domain."`
	ReservedRouteNames      []string `name:"reserved-route-name" env:"TNLD_RESERVED_ROUTE_NAMES" help:"DNS labels unavailable for routes; repeat for each label."`

	ControlTLSCertificateFile string `name:"control-tls-certificate-file" env:"TNLD_CONTROL_TLS_CERTIFICATE_FILE" type:"path" help:"Optional static public control certificate chain override."`
	ControlTLSPrivateKeyFile  string `name:"control-tls-private-key-file" env:"TNLD_CONTROL_TLS_PRIVATE_KEY_FILE" type:"path" help:"Optional static public control private key override."`
	RelayTLSCertificateFile   string `name:"relay-tls-certificate-file" env:"TNLD_RELAY_TLS_CERTIFICATE_FILE" type:"path" help:"Optional static public relay certificate chain override."`
	RelayTLSPrivateKeyFile    string `name:"relay-tls-private-key-file" env:"TNLD_RELAY_TLS_PRIVATE_KEY_FILE" type:"path" help:"Optional static public relay private key override."`
	ACMEDirectoryURL          string `name:"acme-directory-url" env:"TNLD_ACME_DIRECTORY_URL" help:"ACME directory URL for automatic public certificates."`
	ACMEEmail                 string `name:"acme-email" env:"TNLD_ACME_EMAIL" help:"ACME account contact email."`
	ACMEAcceptTerms           bool   `name:"acme-accept-terms" env:"TNLD_ACME_ACCEPT_TERMS" help:"Explicitly accept the ACME directory terms."`
	ACMEProfile               string `name:"acme-profile" env:"TNLD_ACME_PROFILE" default:"tlsserver" help:"ACME certificate profile."`

	OIDCIssuer           string        `name:"oidc-issuer" env:"TNLD_OIDC_ISSUER" help:"OIDC issuer used by the authority."`
	OIDCClientID         string        `name:"oidc-client-id" env:"TNLD_OIDC_CLIENT_ID" help:"OIDC client ID used by the authority."`
	OIDCLoginFlow        OIDCLoginFlow `name:"oidc-login-flow" env:"TNLD_OIDC_LOGIN_FLOW" help:"OIDC login flow: device_code or authorization_code_pkce."`
	OIDCScopes           []string      `name:"oidc-scope" env:"TNLD_OIDC_SCOPES" help:"OIDC scope requested by clients; repeat for each scope."`
	LoginToken           string        `name:"login-token" env:"TNLD_LOGIN_TOKEN" help:"Bootstrap login token for the built-in administrator identity."`
	AuthorityEndpoint    string        `name:"authority-endpoint" env:"TNLD_AUTHORITY_ENDPOINT" help:"Exact external authority HTTPS origin; defaults to the control origin."`
	AccessTokenLifetime  time.Duration `name:"access-token-lifetime" env:"TNLD_ACCESS_TOKEN_LIFETIME" default:"1h" help:"Lifetime of newly issued access tokens."`
	RefreshTokenLifetime time.Duration `name:"refresh-token-lifetime" env:"TNLD_REFRESH_TOKEN_LIFETIME" default:"720h" help:"Absolute lifetime of newly issued control sessions."`

	RouteUsageURL   string `name:"route-usage-url" env:"TNLD_ROUTE_USAGE_URL" help:"Route usage receiver base URL."`
	RouteUsageToken string `name:"route-usage-token" env:"TNLD_ROUTE_USAGE_TOKEN" help:"Service token for the route usage receiver."`

	Route53Region        string   `name:"route53-region" env:"TNLD_ROUTE53_REGION" default:"us-east-1" help:"AWS region used to sign Route 53 requests."`
	Route53ManagedZoneID string   `name:"route53-managed-zone-id" env:"TNLD_ROUTE53_MANAGED_ZONE_ID" help:"Existing Route 53 hosted zone ID for the managed deployment domain; enables DNS automation."`
	Route53ServerZoneID  string   `name:"route53-server-zone-id" env:"TNLD_ROUTE53_SERVER_ZONE_ID" help:"Existing Route 53 hosted zone ID for the server domain; enables relay certificate DNS-01."`
	IngressIPv4Addresses []string `name:"ingress-ipv4-address" env:"TNLD_INGRESS_IPV4_ADDRESSES" help:"Stable ingress IPv4 address published in owned route records; repeat for each address."`
	IngressIPv6Addresses []string `name:"ingress-ipv6-address" env:"TNLD_INGRESS_IPV6_ADDRESSES" help:"Stable ingress IPv6 address published in owned route records; repeat for each address."`

	ClusterSecret         string `name:"cluster-secret" env:"TNLD_CLUSTER_SECRET" help:"Current shared secret for private communication among control, ingress, and relays."`
	ClusterSecretPrevious string `name:"cluster-secret-previous" env:"TNLD_CLUSTER_SECRET_PREVIOUS" help:"Previous cluster secret accepted only during rotation."`
	HostedSecret          string `name:"hosted-secret" env:"TNLD_HOSTED_SECRET" help:"Current secret shared by control and the hosted authority."`
	HostedSecretPrevious  string `name:"hosted-secret-previous" env:"TNLD_HOSTED_SECRET_PREVIOUS" help:"Previous hosted secret accepted only during rotation."`
	StorageKey            string `name:"storage-key" env:"TNLD_STORAGE_KEY" help:"Canonical base64url AES-256 key used to encrypt recoverable PostgreSQL secrets."`
	StorageKeyPrevious    string `name:"storage-key-previous" env:"TNLD_STORAGE_KEY_PREVIOUS" help:"Previous storage key retained only during re-encryption."`

	IngressID            string `name:"ingress-id" env:"TNLD_INGRESS_ID" help:"Stable ingress process identity."`
	RelayServiceID       string `name:"relay-service-id" env:"TNLD_RELAY_SERVICE_ID" help:"Stable relay service identity for this relay process."`
	RelayID              string `name:"relay-id" env:"TNLD_RELAY_ID" help:"Stable relay process identity."`
	RelayAddress         string `name:"relay-address" env:"TNLD_RELAY_ADDRESS" help:"Stable public relay hostname and port advertised by this relay service."`
	InternalRelayAddress string `name:"internal-relay-address" env:"TNLD_INTERNAL_RELAY_ADDRESS" help:"Internal hostname and port advertised by this relay process."`

	PublicConnectionLimit    int64         `name:"public-connection-limit" env:"TNLD_PUBLIC_CONNECTION_LIMIT" default:"20000" help:"Maximum concurrent public visitor connections."`
	RouteConnectionLimit     int64         `name:"route-connection-limit" env:"TNLD_ROUTE_CONNECTION_LIMIT" default:"500" help:"Maximum concurrent visitor connections per route."`
	PublisherConnectionLimit int64         `name:"publisher-connection-limit" env:"TNLD_PUBLISHER_CONNECTION_LIMIT" default:"1000" help:"Maximum publisher connections held by one relay process."`
	RelayStreamCapacity      int64         `name:"relay-stream-capacity" env:"TNLD_RELAY_STREAM_CAPACITY" default:"4096" help:"Maximum concurrent visitor streams held by one relay process."`
	RequireProxyHeader       bool          `name:"require-proxy-header" env:"TNLD_REQUIRE_PROXY_HEADER" help:"Require one trusted outer PROXY v2 header on public ingress."`
	QUICMaxIncomingStreams   int64         `name:"quic-max-incoming-streams" env:"TNLD_QUIC_MAX_INCOMING_STREAMS" default:"4096" help:"Maximum incoming QUIC streams per publisher connection."`
	QUICIdleTimeout          time.Duration `name:"quic-idle-timeout" env:"TNLD_QUIC_IDLE_TIMEOUT" default:"45s" help:"Publisher connection QUIC idle timeout."`
	TunnelFallbackDelay      time.Duration `name:"tunnel-fallback-delay" env:"TNLD_TUNNEL_FALLBACK_DELAY" default:"250ms" help:"Delay before racing TLS/TCP against QUIC."`
	IngressLeaseDuration     time.Duration `name:"ingress-lease-duration" env:"TNLD_INGRESS_LEASE_DURATION" default:"30s" help:"Control-owned ingress lease duration."`
	RelayLeaseDuration       time.Duration `name:"relay-lease-duration" env:"TNLD_RELAY_LEASE_DURATION" default:"30s" help:"Control-owned relay lease duration."`
	LeaseRenewalInterval     time.Duration `name:"lease-renewal-interval" env:"TNLD_LEASE_RENEWAL_INTERVAL" default:"10s" help:"Ingress and relay lease renewal interval."`
	ControlRetryInterval     time.Duration `name:"control-retry-interval" env:"TNLD_CONTROL_RETRY_INTERVAL" default:"1s" help:"Delay before retrying a transient control failure."`
	RoutingTableWait         time.Duration `name:"routing-table-wait" env:"TNLD_ROUTING_TABLE_WAIT" default:"25s" help:"Ingress routing-table long-poll duration."`
	DrainTimeout             time.Duration `name:"drain-timeout" env:"TNLD_DRAIN_TIMEOUT" default:"30s" help:"Graceful connection drain deadline."`
}

func (c Config) Validate() error {
	if !c.Mode.RunsControl() && !c.Mode.RunsIngress() && !c.Mode.RunsRelay() {
		return errors.New("mode must be standalone, control, ingress, or relay")
	}
	if c.Mode.RunsControl() {
		if err := c.validateControl(); err != nil {
			return err
		}
	} else {
		if c.DatabaseURL != "" {
			return errors.New("ingress and relay modes cannot receive a database URL")
		}
		if c.LoginToken != "" || c.ControlTLSCertificateFile != "" || c.ControlTLSPrivateKeyFile != "" {
			return errors.New("ingress and relay modes cannot receive control authentication or TLS configuration")
		}
		if err := validateControlHostname(c.ControlHostname); err != nil {
			return err
		}
		if _, err := serviceapi.NewBearerSecrets(c.ClusterSecret, c.ClusterSecretPrevious); err != nil {
			return errors.New("cluster secret configuration is invalid")
		}
		if c.HostedSecret != "" || c.HostedSecretPrevious != "" || c.StorageKey != "" || c.StorageKeyPrevious != "" ||
			c.Route53ManagedZoneID != "" || c.Route53ServerZoneID != "" ||
			len(c.IngressIPv4Addresses) != 0 || len(c.IngressIPv6Addresses) != 0 {
			return errors.New("ingress and relay modes cannot receive hosted, storage, or DNS provider configuration")
		}
	}
	if c.Mode == RoleIngress && !validProcessID(c.IngressID) {
		return errors.New("ingress ID is required and must be canonical")
	}
	if c.Mode == RoleRelay {
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
	if c.Mode != RoleRelay && c.Mode != RoleStandalone && (c.RelayTLSCertificateFile != "" || c.RelayTLSPrivateKeyFile != "") {
		return errors.New("relay TLS overrides are valid only for relay and standalone modes")
	}
	for name, address := range map[string]string{
		"metrics": c.MetricsListen, "control": c.ControlListen, "private control": c.PrivateControlListen,
		"ingress": c.IngressListen, "relay TCP": c.RelayTCPListen,
		"relay UDP": c.RelayUDPListen, "internal relay": c.InternalRelayListen,
		"DNS server": c.DNSServer,
	} {
		if err := validateListenAddress(address); err != nil {
			return fmt.Errorf("%s listen address: %w", name, err)
		}
	}
	if c.PublicConnectionLimit <= 0 || c.RouteConnectionLimit <= 0 || c.PublisherConnectionLimit <= 0 ||
		c.RelayStreamCapacity <= 0 || c.QUICMaxIncomingStreams <= 0 {
		return errors.New("connection and stream capacities must be positive")
	}
	if c.IngressLeaseDuration <= 0 || c.RelayLeaseDuration <= 0 || c.LeaseRenewalInterval <= 0 ||
		c.LeaseRenewalInterval >= c.IngressLeaseDuration || c.LeaseRenewalInterval >= c.RelayLeaseDuration ||
		c.ControlRetryInterval <= 0 || c.RoutingTableWait <= 0 || c.RoutingTableWait > 25*time.Second ||
		c.RoutingTableWait%time.Second != 0 || c.DrainTimeout <= 0 || c.TunnelFallbackDelay <= 0 ||
		c.QUICIdleTimeout <= 0 {
		return errors.New("lease, routing-table, transport, or drain timing is invalid")
	}
	return nil
}

func (c Config) validateControl() error {
	if err := validatePostgresURL(c.DatabaseURL); err != nil {
		return err
	}
	if c.ControlListen == "" || c.PrivateControlListen == "" {
		return errors.New("control and private control listen addresses are required")
	}
	if err := validateCanonicalHostname(c.ServerDomain, "server domain"); err != nil {
		return err
	}
	if err := validateCanonicalHostname(c.ManagedDeploymentDomain, "managed deployment domain"); err != nil {
		return err
	}
	if c.ControlHostname != "" || c.IngressID != "" || c.RelayServiceID != "" || c.RelayID != "" || c.RelayAddress != "" || c.InternalRelayAddress != "" {
		return errors.New("split-process configuration is invalid for control and standalone")
	}
	if c.Mode == RoleStandalone {
		if c.ClusterSecret != "" || c.ClusterSecretPrevious != "" {
			return errors.New("standalone does not accept a configured cluster secret")
		}
	} else if _, err := serviceapi.NewBearerSecrets(c.ClusterSecret, c.ClusterSecretPrevious); err != nil {
		return errors.New("cluster secret configuration is invalid")
	}
	if c.AuthorityEndpoint == "" {
		if c.LoginToken == "" {
			return errors.New("login token is required for the built-in authority")
		}
		if _, err := credentials.ParseLoginToken(credentials.LoginToken(c.LoginToken)); err != nil {
			return errors.New("login token is invalid")
		}
	} else if c.LoginToken != "" {
		return errors.New("login token cannot be configured with an external authority")
	}
	if err := c.validateReservedRouteNames(); err != nil {
		return err
	}
	if err := c.validateOIDC(); err != nil {
		return err
	}
	if err := c.validateHostedAuthority(); err != nil {
		return err
	}
	if _, err := storagekey.New(c.StorageKey, c.StorageKeyPrevious); err != nil {
		return errors.New("storage key configuration is invalid")
	}
	if err := c.validateACME(); err != nil {
		return err
	}
	if err := c.validateRouteUsage(); err != nil {
		return err
	}
	if err := c.validateDNSAutomation(); err != nil {
		return err
	}
	if c.Mode == RoleStandalone && c.ControlTLSCertificateFile != "" &&
		c.RelayTLSCertificateFile == "" && c.Route53ServerZoneID == "" {
		return errors.New("standalone with a static control certificate requires relay certificate automation or a static relay TLS override")
	}
	if c.AccessTokenLifetime < minimumAccessTokenLifetime || c.AccessTokenLifetime > maximumAccessTokenLifetime {
		return fmt.Errorf("access token lifetime must be between %s and %s", minimumAccessTokenLifetime, maximumAccessTokenLifetime)
	}
	if c.RefreshTokenLifetime < c.AccessTokenLifetime || c.RefreshTokenLifetime > maximumRefreshTokenLifetime {
		return fmt.Errorf("refresh token lifetime must be between the access token lifetime and %s", maximumRefreshTokenLifetime)
	}
	return nil
}

func (c Config) validateReservedRouteNames() error {
	seen := make(map[string]struct{}, len(c.ReservedRouteNames))
	for _, name := range c.ReservedRouteNames {
		canonical, err := naming.CanonicalizeHostname(name)
		if err != nil || canonical != name || strings.Contains(name, ".") {
			return fmt.Errorf("reserved route name %q must be one canonical DNS label", name)
		}
		if _, exists := seen[name]; exists {
			return fmt.Errorf("reserved route name %q is configured more than once", name)
		}
		seen[name] = struct{}{}
	}
	return nil
}

func (c Config) validateACME() error {
	if c.ACMEDirectoryURL == "" || c.ACMEEmail == "" || !c.ACMEAcceptTerms {
		return errors.New("ACME directory, email, and accepted terms are required for control and standalone")
	}
	directory, err := url.Parse(c.ACMEDirectoryURL)
	if err != nil || directory.Scheme != "https" || directory.Host == "" || directory.User != nil || directory.Fragment != "" {
		return errors.New("ACME directory must be an HTTPS URL")
	}
	address, err := mail.ParseAddress(c.ACMEEmail)
	if err != nil || address.Address != c.ACMEEmail || address.Name != "" {
		return errors.New("ACME email must be a plain email address")
	}
	if !validDNSLabel(c.ACMEProfile) {
		return errors.New("ACME profile must contain only lowercase letters, digits, and hyphens")
	}
	staticTLS := c.ControlTLSCertificateFile != "" || c.ControlTLSPrivateKeyFile != ""
	if staticTLS && (c.ControlTLSCertificateFile == "" || c.ControlTLSPrivateKeyFile == "") {
		return errors.New("control TLS certificate and private key must be configured together")
	}
	return nil
}

func (c Config) validateRouteUsage() error {
	if (c.RouteUsageURL == "") != (c.RouteUsageToken == "") {
		return errors.New("route usage URL and token must be configured together")
	}
	if c.RouteUsageURL == "" {
		return nil
	}
	endpoint, err := url.Parse(c.RouteUsageURL)
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" ||
		endpoint.Scheme != "https" && (endpoint.Scheme != "http" || !isLoopbackHost(endpoint.Hostname())) {
		return errors.New("route usage URL must be an HTTPS base URL or a loopback HTTP base URL")
	}
	return nil
}

func (c Config) validateDNSAutomation() error {
	configured := c.Route53ManagedZoneID != "" || c.Route53ServerZoneID != "" ||
		len(c.IngressIPv4Addresses) != 0 || len(c.IngressIPv6Addresses) != 0
	if !configured {
		return nil
	}
	for name, zoneID := range map[string]string{
		"managed": c.Route53ManagedZoneID, "server": c.Route53ServerZoneID,
	} {
		if zoneID != "" && (strings.TrimSpace(zoneID) != zoneID || strings.ContainsAny(zoneID, "/ ")) {
			return fmt.Errorf("route 53 %s zone ID must be a canonical bare hosted zone ID", name)
		}
	}
	if !validDNSLabel(c.Route53Region) {
		return errors.New("route 53 region is invalid")
	}
	if c.Route53ManagedZoneID == "" && (len(c.IngressIPv4Addresses) != 0 || len(c.IngressIPv6Addresses) != 0) {
		return errors.New("ingress IP addresses require a Route 53 managed zone ID")
	}
	if c.Route53ManagedZoneID == "" {
		return nil
	}
	if len(c.IngressIPv4Addresses) == 0 && len(c.IngressIPv6Addresses) == 0 {
		return errors.New("DNS automation requires at least one ingress IP address")
	}
	seen := make(map[netip.Addr]struct{}, len(c.IngressIPv4Addresses)+len(c.IngressIPv6Addresses))
	for _, values := range []struct {
		name string
		want func(netip.Addr) bool
		all  []string
	}{
		{name: "ingress IPv4 address", want: netip.Addr.Is4, all: c.IngressIPv4Addresses},
		{name: "ingress IPv6 address", want: netip.Addr.Is6, all: c.IngressIPv6Addresses},
	} {
		for _, value := range values.all {
			address, err := netip.ParseAddr(value)
			if err != nil || address.String() != value || !values.want(address) {
				return fmt.Errorf("%s %q is not canonical", values.name, value)
			}
			if _, exists := seen[address]; exists {
				return fmt.Errorf("%s %q is configured more than once", values.name, value)
			}
			seen[address] = struct{}{}
		}
	}
	return nil
}

func (c Config) OIDCEnabled() bool { return c.OIDCIssuer != "" }

func (c Config) EffectiveOIDCScopes() []string {
	if len(c.OIDCScopes) == 0 {
		return []string{"openid"}
	}
	return append([]string(nil), c.OIDCScopes...)
}

func (c Config) validateOIDC() error {
	configured := c.OIDCIssuer != "" || c.OIDCClientID != "" || c.OIDCLoginFlow != "" || len(c.OIDCScopes) != 0
	if !configured {
		return nil
	}
	if c.OIDCIssuer == "" || c.OIDCClientID == "" || c.OIDCLoginFlow == "" {
		return errors.New("OIDC configuration is incomplete")
	}
	issuer, err := url.Parse(c.OIDCIssuer)
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.User != nil ||
		issuer.RawQuery != "" || issuer.Fragment != "" {
		return errors.New("OIDC issuer must be an HTTPS URL without credentials, query, or fragment")
	}
	if strings.TrimSpace(c.OIDCClientID) != c.OIDCClientID || c.OIDCClientID == "" || len(c.OIDCClientID) > 128 {
		return errors.New("OIDC client ID is invalid")
	}
	if c.OIDCLoginFlow != OIDCLoginFlowDeviceCode && c.OIDCLoginFlow != OIDCLoginFlowAuthorizationCodePKCE {
		return errors.New("OIDC login flow is invalid")
	}
	seen := make(map[string]struct{})
	hasOpenID := false
	for _, scope := range c.EffectiveOIDCScopes() {
		if scope == "openid" {
			hasOpenID = true
		}
		if scope == "" || len(scope) > 128 || strings.TrimSpace(scope) != scope || strings.ContainsAny(scope, " \t\r\n") {
			return errors.New("OIDC scopes are invalid")
		}
		if _, exists := seen[scope]; exists {
			return errors.New("OIDC scopes contain a duplicate")
		}
		seen[scope] = struct{}{}
	}
	if !hasOpenID {
		return errors.New("OIDC scopes must include openid")
	}
	return nil
}

func (c Config) validateHostedAuthority() error {
	if c.AuthorityEndpoint == "" {
		if c.HostedSecret != "" || c.HostedSecretPrevious != "" {
			return errors.New("hosted secret requires an external authority endpoint")
		}
		return nil
	}
	if err := validateHTTPSOrigin(c.AuthorityEndpoint, "authority endpoint"); err != nil {
		return err
	}
	if !c.OIDCEnabled() {
		return errors.New("external authority requires OIDC configuration")
	}
	if _, err := serviceapi.NewBearerSecrets(c.HostedSecret, c.HostedSecretPrevious); err != nil {
		return errors.New("hosted secret configuration is invalid")
	}
	return nil
}

func (c Config) ACMEEnabled() bool { return c.Mode.RunsControl() }

func (c Config) DNSAutomationEnabled() bool {
	return c.Mode.RunsControl() && c.Route53ManagedZoneID != ""
}

func (c Config) DNSProviderEnabled() bool {
	return c.Mode.RunsControl() && (c.Route53ManagedZoneID != "" || c.Route53ServerZoneID != "")
}

func (c Config) RelayCertificateAutomationEnabled() bool {
	return c.Mode.RunsControl() && c.Route53ServerZoneID != ""
}

func (c Config) ServerHostname() string {
	if !c.Mode.RunsControl() || c.ServerDomain == "" {
		return ""
	}
	return "control." + c.ServerDomain
}

func (c Config) IngressHostname() string {
	if !c.Mode.RunsControl() || c.ServerDomain == "" {
		return ""
	}
	return "ingress." + c.ServerDomain
}

func (c Config) StandaloneRelayHostname() string {
	if c.Mode != RoleStandalone || c.ServerDomain == "" {
		return ""
	}
	return "relay." + c.ServerDomain
}

// RelayServiceHostname derives one split relay service's public hostname.
func (c Config) RelayServiceHostname(relayServiceID string) string {
	if !c.Mode.RunsControl() || !validDNSLabel(relayServiceID) || c.ServerDomain == "" {
		return ""
	}
	return relayServiceID + "." + c.ServerDomain
}

// PrivateControlEndpoint is the fixed private endpoint used by ingress and relay processes.
func (c Config) PrivateControlEndpoint() string {
	hostname := c.ServerHostname()
	if hostname == "" {
		hostname = c.ControlHostname
	}
	if hostname != "" {
		return "https://" + net.JoinHostPort(hostname, "9443")
	}
	return ""
}

func (c Config) ManagedDomain() string { return c.ManagedDeploymentDomain }

func (c Config) AuthorityOrigin() string {
	if c.AuthorityEndpoint != "" {
		return c.AuthorityEndpoint
	}
	if hostname := c.ServerHostname(); hostname != "" {
		return "https://" + hostname
	}
	return ""
}

func (c Config) EffectiveReservedRouteNames() []string {
	result := make([]string, 0, len(c.ReservedRouteNames)+4)
	seen := make(map[string]struct{}, len(c.ReservedRouteNames)+4)
	add := func(name string) {
		if name == "" {
			return
		}
		if _, exists := seen[name]; exists {
			return
		}
		seen[name] = struct{}{}
		result = append(result, name)
	}
	for _, name := range c.ReservedRouteNames {
		add(name)
	}
	add("domains")
	for _, hostname := range []string{c.ServerHostname(), c.IngressHostname(), c.StandaloneRelayHostname()} {
		if label, found := strings.CutSuffix(hostname, "."+c.ManagedDomain()); found && !strings.Contains(label, ".") {
			add(label)
		}
	}
	return result
}

func Parse(args []string) (Config, error) {
	type arguments Config
	var flags arguments
	parser, err := kong.New(&flags, kong.Name("tnld"), kong.Description("tnl server."))
	if err != nil {
		return Config{}, err
	}
	if _, err := parser.Parse(args); err != nil {
		return Config{}, err
	}
	return Resolve(Config(flags))
}

func Resolve(config Config) (Config, error) {
	switch config.Mode {
	case RoleStandalone:
		setControlDefaults(&config)
		if config.IngressListen == "" {
			config.IngressListen = ":443"
		}
		if config.RelayTCPListen == "" {
			config.RelayTCPListen = ":443"
		}
		if config.RelayUDPListen == "" {
			config.RelayUDPListen = ":443"
		}
	case RoleControl:
		setControlDefaults(&config)
	case RoleIngress:
		if config.IngressListen == "" {
			config.IngressListen = ":443"
		}
	case RoleRelay:
		if config.RelayTCPListen == "" {
			config.RelayTCPListen = ":443"
		}
		if config.RelayUDPListen == "" {
			config.RelayUDPListen = ":443"
		}
		if config.InternalRelayListen == "" && config.InternalRelayAddress != "" {
			_, port, err := net.SplitHostPort(config.InternalRelayAddress)
			if err == nil {
				config.InternalRelayListen = net.JoinHostPort("", port)
			}
		}
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func setControlDefaults(config *Config) {
	if config.ControlListen == "" {
		config.ControlListen = ":443"
	}
	if config.PrivateControlListen == "" {
		config.PrivateControlListen = ":9443"
	}
	if config.ACMEDirectoryURL == "" {
		config.ACMEDirectoryURL = defaultACMEDirectoryURL
	}
}

func validatePostgresURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.User == nil || parsed.User.Username() == "" ||
		parsed.Scheme != "postgres" && parsed.Scheme != "postgresql" {
		return errors.New("pooled PostgreSQL database URL is required")
	}
	if strings.TrimSpace(value) != value || parsed.Fragment != "" {
		return errors.New("pooled PostgreSQL database URL is invalid")
	}
	return nil
}

func validateControlHostname(value string) error {
	if err := validateCanonicalHostname(value, "control hostname"); err != nil {
		return err
	}
	if strings.ContainsAny(value, ":/") {
		return errors.New("control hostname must not contain a scheme, path, or port")
	}
	return nil
}

func validateCanonicalHostname(value, name string) error {
	canonical, err := naming.CanonicalizeHostname(value)
	if err != nil || canonical != value {
		return fmt.Errorf("%s must be canonical", name)
	}
	return nil
}

func validateHTTPSOrigin(value, name string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Hostname() != strings.ToLower(parsed.Hostname()) || parsed.Port() == "443" {
		return fmt.Errorf("%s must be a canonical HTTPS origin", name)
	}
	return nil
}

func validateListenAddress(value string) error {
	if value == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil || strings.TrimSpace(host) != host {
		return errors.New("must be a canonical host and port")
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 || strconv.Itoa(number) != port {
		return errors.New("port must be between 1 and 65535")
	}
	return nil
}

func validateRelayAddress(value string) error {
	host, port, err := net.SplitHostPort(value)
	if err != nil || port == "" {
		return errors.New("relay address must be a canonical hostname and port")
	}
	canonical, err := naming.CanonicalizeHostname(host)
	if err != nil || canonical != host {
		return errors.New("relay address must use a canonical hostname")
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 || strconv.Itoa(number) != port {
		return errors.New("relay address port must be between 1 and 65535")
	}
	return nil
}

func validProcessID(value string) bool {
	return value != "" && len(value) <= 256 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, " \t\r\n")
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

func validDNSLabel(value string) bool {
	if len(value) == 0 || len(value) > 63 || (value[0] < 'a' || value[0] > 'z') && (value[0] < '0' || value[0] > '9') {
		return false
	}
	for _, character := range value[1:] {
		if character != '-' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}
