package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/naming"
)

const defaultACMEDirectoryURL = "https://acme-v02.api.letsencrypt.org/directory"

// TNLDMode selects the role hosted by one tnld process.
type TNLDMode string

const (
	TNLDModeStandalone TNLDMode = "standalone"
	TNLDModeControl    TNLDMode = "control"
	TNLDModeIngress    TNLDMode = "ingress"
	TNLDModeRelay      TNLDMode = "relay"

	minimumAccessTokenLifetime  = 5 * time.Minute
	maximumAccessTokenLifetime  = 30 * 24 * time.Hour
	maximumRefreshTokenLifetime = 365 * 24 * time.Hour
)

type OIDCLoginFlow string

const (
	OIDCLoginFlowDeviceCode            OIDCLoginFlow = "device_code"
	OIDCLoginFlowAuthorizationCodePKCE OIDCLoginFlow = "authorization_code_pkce"
)

func (m TNLDMode) RunsControl() bool { return m == TNLDModeStandalone || m == TNLDModeControl }
func (m TNLDMode) RunsIngress() bool { return m == TNLDModeStandalone || m == TNLDModeIngress }
func (m TNLDMode) RunsRelay() bool   { return m == TNLDModeStandalone || m == TNLDModeRelay }

// TNLD configures one tnld process. Migration configuration is intentionally
// absent: tnld migrate reads only TNLD_DATABASE_DIRECT_URL.
type TNLD struct {
	Mode TNLDMode `name:"mode" env:"TNLD_MODE" default:"standalone" enum:"standalone,control,ingress,relay" help:"Process role: ${enum}."`

	DatabaseURL   string `name:"database-url" env:"TNLD_DATABASE_URL" help:"Pooled PostgreSQL URL used by control and standalone."`
	MetricsListen string `name:"metrics-listen" env:"TNLD_METRICS_LISTEN" default:"127.0.0.1:9090" help:"Private Prometheus listen address; empty disables metrics."`

	ControlListen        string `name:"control-listen" env:"TNLD_CONTROL_LISTEN" help:"Public control HTTPS listen address."`
	IngressControlListen string `name:"ingress-control-listen" env:"TNLD_INGRESS_CONTROL_LISTEN" help:"Private service-mTLS ingress API listen address."`
	RelayControlListen   string `name:"relay-control-listen" env:"TNLD_RELAY_CONTROL_LISTEN" help:"Private service-mTLS relay API listen address."`
	IngressListen        string `name:"ingress-listen" env:"TNLD_INGRESS_LISTEN" help:"Public visitor TCP listen address."`
	RelayTCPListen       string `name:"relay-tcp-listen" env:"TNLD_RELAY_TCP_LISTEN" help:"Public TLS/TCP publisher-connection listen address."`
	RelayUDPListen       string `name:"relay-udp-listen" env:"TNLD_RELAY_UDP_LISTEN" help:"Public QUIC publisher-connection listen address."`
	InternalRelayListen  string `name:"internal-relay-listen" env:"TNLD_INTERNAL_RELAY_LISTEN" help:"Internal service-mTLS forwarding listen address."`
	DNSServer            string `name:"dns-server" env:"TNLD_DNS_SERVER" help:"DNS resolver used for readiness checks; defaults to the system resolver."`

	ServerDomain            string   `name:"server-domain" env:"TNLD_SERVER_DOMAIN" help:"Infrastructure DNS suffix used to derive control, ingress, and relay hostnames."`
	ControlHostname         string   `name:"control-hostname" env:"TNLD_CONTROL_HOSTNAME" help:"Control API hostname used by ingress and relay processes."`
	ManagedDeploymentDomain string   `name:"managed-deployment-domain" env:"TNLD_MANAGED_DEPLOYMENT_DOMAIN" help:"Managed public route DNS domain."`
	ReservedRouteNames      []string `name:"reserved-route-name" env:"TNLD_RESERVED_ROUTE_NAMES" help:"DNS labels unavailable for routes; repeat for each label."`

	ControlTLSCertificateFile string `name:"control-tls-certificate-file" env:"TNLD_CONTROL_TLS_CERTIFICATE_FILE" type:"path" help:"Optional static public control certificate chain override."`
	ControlTLSPrivateKeyFile  string `name:"control-tls-private-key-file" env:"TNLD_CONTROL_TLS_PRIVATE_KEY_FILE" type:"path" help:"Optional static public control private key override."`
	ACMEDirectoryURL          string `name:"acme-directory-url" env:"TNLD_ACME_DIRECTORY_URL" help:"ACME directory URL for automatic public certificates."`
	ACMEEmail                 string `name:"acme-email" env:"TNLD_ACME_EMAIL" help:"ACME account contact email."`
	ACMEAcceptTerms           bool   `name:"acme-accept-terms" env:"TNLD_ACME_ACCEPT_TERMS" help:"Explicitly accept the ACME directory terms."`
	ACMEProfile               string `name:"acme-profile" env:"TNLD_ACME_PROFILE" default:"tlsserver" help:"ACME certificate profile."`

	OIDCIssuer             string        `name:"oidc-issuer" env:"TNLD_OIDC_ISSUER" help:"OIDC issuer used by the authority."`
	OIDCClientID           string        `name:"oidc-client-id" env:"TNLD_OIDC_CLIENT_ID" help:"OIDC client ID used by the authority."`
	OIDCLoginFlow          OIDCLoginFlow `name:"oidc-login-flow" env:"TNLD_OIDC_LOGIN_FLOW" help:"OIDC login flow: device_code or authorization_code_pkce."`
	OIDCScopes             []string      `name:"oidc-scope" env:"TNLD_OIDC_SCOPES" help:"OIDC scope requested by clients; repeat for each scope."`
	LoginToken             string        `name:"login-token" env:"TNLD_LOGIN_TOKEN" help:"Bootstrap login token for the built-in administrator identity."`
	AuthorityEndpoint      string        `name:"authority-endpoint" env:"TNLD_AUTHORITY_ENDPOINT" help:"Exact external authority HTTPS origin; defaults to the control origin."`
	AuthorizationIssuer    string        `name:"authorization-issuer" env:"TNLD_AUTHORIZATION_ISSUER" help:"Exact trusted signed-authorization issuer."`
	AuthorizationReceiver  string        `name:"authorization-receiver" env:"TNLD_AUTHORIZATION_RECEIVER" help:"Expected signed-authorization receiver."`
	AuthorizationKeyID     string        `name:"authorization-key-id" env:"TNLD_AUTHORIZATION_KEY_ID" help:"Trusted authorization Ed25519 key ID."`
	AuthorizationPublicKey string        `name:"authorization-public-key" env:"TNLD_AUTHORIZATION_PUBLIC_KEY" help:"Trusted Ed25519 public key in unpadded base64url form."`
	AccessTokenLifetime    time.Duration `name:"access-token-lifetime" env:"TNLD_ACCESS_TOKEN_LIFETIME" default:"1h" help:"Lifetime of newly issued access tokens."`
	RefreshTokenLifetime   time.Duration `name:"refresh-token-lifetime" env:"TNLD_REFRESH_TOKEN_LIFETIME" default:"720h" help:"Absolute lifetime of newly issued control sessions."`

	RouteUsageURL   string `name:"route-usage-url" env:"TNLD_ROUTE_USAGE_URL" help:"Route usage receiver base URL."`
	RouteUsageToken string `name:"route-usage-token" env:"TNLD_ROUTE_USAGE_TOKEN" help:"Service token for the route usage receiver."`

	ServiceEnrollmentToken string `name:"service-enrollment-token" env:"TNLD_SERVICE_ENROLLMENT_TOKEN" help:"Reusable role-scoped service enrollment token."`
	IngressID              string `name:"ingress-id" env:"TNLD_INGRESS_ID" help:"Stable ingress process identity."`
	RelayID                string `name:"relay-id" env:"TNLD_RELAY_ID" help:"Stable relay process identity."`
	InternalRelayAddress   string `name:"internal-relay-address" env:"TNLD_INTERNAL_RELAY_ADDRESS" help:"Internal hostname and port advertised by this relay process."`

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

func (c TNLD) Validate() error {
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
		if err := validateControlHostname(c.ControlHostname); err != nil {
			return err
		}
		if !validServiceEnrollmentToken(c.ServiceEnrollmentToken) {
			return errors.New("service enrollment token is invalid")
		}
	}
	if c.Mode == TNLDModeIngress && !validProcessID(c.IngressID) {
		return errors.New("ingress ID is required and must be canonical")
	}
	if c.Mode == TNLDModeRelay {
		if !validProcessID(c.RelayID) {
			return errors.New("relay ID is required and must be canonical")
		}
		if err := validateListenAddress(c.InternalRelayAddress); err != nil {
			return fmt.Errorf("internal relay address: %w", err)
		}
	}
	for name, address := range map[string]string{
		"metrics": c.MetricsListen, "control": c.ControlListen,
		"ingress control": c.IngressControlListen, "relay control": c.RelayControlListen,
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

func (c TNLD) validateControl() error {
	if err := validatePostgresURL(c.DatabaseURL); err != nil {
		return err
	}
	if c.ControlListen == "" || c.IngressControlListen == "" || c.RelayControlListen == "" {
		return errors.New("control and private service listen addresses are required")
	}
	if err := validateCanonicalHostname(c.ServerDomain, "server domain"); err != nil {
		return err
	}
	if err := validateCanonicalHostname(c.ManagedDeploymentDomain, "managed deployment domain"); err != nil {
		return err
	}
	if c.ControlHostname != "" || c.ServiceEnrollmentToken != "" || c.IngressID != "" || c.RelayID != "" || c.InternalRelayAddress != "" {
		return errors.New("split-process configuration is invalid for control and standalone")
	}
	if c.LoginToken == "" {
		return errors.New("login token is required for control and standalone")
	}
	if _, err := credentials.ParseLoginToken(credentials.LoginToken(c.LoginToken)); err != nil {
		return errors.New("login token is invalid")
	}
	if err := c.validateReservedRouteNames(); err != nil {
		return err
	}
	if err := c.validateOIDC(); err != nil {
		return err
	}
	if err := c.validateAuthorization(); err != nil {
		return err
	}
	if err := c.validateACME(); err != nil {
		return err
	}
	if err := c.validateRouteUsage(); err != nil {
		return err
	}
	if c.AccessTokenLifetime < minimumAccessTokenLifetime || c.AccessTokenLifetime > maximumAccessTokenLifetime {
		return fmt.Errorf("access token lifetime must be between %s and %s", minimumAccessTokenLifetime, maximumAccessTokenLifetime)
	}
	if c.RefreshTokenLifetime < c.AccessTokenLifetime || c.RefreshTokenLifetime > maximumRefreshTokenLifetime {
		return fmt.Errorf("refresh token lifetime must be between the access token lifetime and %s", maximumRefreshTokenLifetime)
	}
	return nil
}

func (c TNLD) validateReservedRouteNames() error {
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

func (c TNLD) validateACME() error {
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

func (c TNLD) validateRouteUsage() error {
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

func (c TNLD) OIDCEnabled() bool { return c.OIDCIssuer != "" }

func (c TNLD) EffectiveOIDCScopes() []string {
	if len(c.OIDCScopes) == 0 {
		return []string{"openid"}
	}
	return append([]string(nil), c.OIDCScopes...)
}

func (c TNLD) validateOIDC() error {
	configured := c.OIDCIssuer != "" || c.OIDCClientID != "" || c.OIDCLoginFlow != "" || len(c.OIDCScopes) != 0
	if !configured {
		return nil
	}
	if c.OIDCIssuer == "" || c.OIDCClientID == "" || c.OIDCLoginFlow == "" {
		return errors.New("OIDC configuration is incomplete")
	}
	issuer, err := url.Parse(c.OIDCIssuer)
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.User != nil ||
		issuer.Path != "" && issuer.Path != "/" || issuer.RawQuery != "" || issuer.Fragment != "" {
		return errors.New("OIDC issuer must be an HTTPS origin")
	}
	if strings.TrimSpace(c.OIDCClientID) != c.OIDCClientID || c.OIDCClientID == "" || len(c.OIDCClientID) > 128 {
		return errors.New("OIDC client ID is invalid")
	}
	if c.OIDCLoginFlow != OIDCLoginFlowDeviceCode && c.OIDCLoginFlow != OIDCLoginFlowAuthorizationCodePKCE {
		return errors.New("OIDC login flow is invalid")
	}
	seen := make(map[string]struct{})
	for _, scope := range c.EffectiveOIDCScopes() {
		if scope == "" || len(scope) > 128 || strings.TrimSpace(scope) != scope || strings.ContainsAny(scope, " \t\r\n") {
			return errors.New("OIDC scopes are invalid")
		}
		if _, exists := seen[scope]; exists {
			return errors.New("OIDC scopes contain a duplicate")
		}
		seen[scope] = struct{}{}
	}
	return nil
}

func (c TNLD) SignedAuthorizationEnabled() bool { return c.AuthorityEndpoint != "" }

func (c TNLD) AuthorizationConfig() authorization.Config {
	publicKey, _ := base64.RawURLEncoding.DecodeString(c.AuthorizationPublicKey)
	return authorization.Config{
		Issuer: c.AuthorizationIssuer, Receiver: c.AuthorizationReceiver,
		KeyID: c.AuthorizationKeyID, PublicKey: ed25519.PublicKey(publicKey),
	}
}

func (c TNLD) validateAuthorization() error {
	values := []string{c.AuthorityEndpoint, c.AuthorizationIssuer, c.AuthorizationReceiver, c.AuthorizationKeyID, c.AuthorizationPublicKey}
	configured, complete := false, true
	for _, value := range values {
		configured = configured || value != ""
		complete = complete && value != ""
	}
	if !configured {
		return nil
	}
	if !complete {
		return errors.New("authority signing configuration is incomplete")
	}
	if !c.Mode.RunsControl() {
		return errors.New("authority signing configuration is valid only for control and standalone")
	}
	if err := validateHTTPSOrigin(c.AuthorityEndpoint, "authority endpoint"); err != nil {
		return err
	}
	for _, field := range []struct{ name, value string }{
		{name: "authorization issuer", value: c.AuthorizationIssuer},
		{name: "authorization receiver", value: c.AuthorizationReceiver},
	} {
		parsed, err := url.Parse(field.value)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			return fmt.Errorf("%s must be an HTTPS URL without credentials, query, or fragment", field.name)
		}
	}
	if strings.TrimSpace(c.AuthorizationKeyID) != c.AuthorizationKeyID || c.AuthorizationKeyID == "" || len(c.AuthorizationKeyID) > 128 {
		return errors.New("authorization key ID is invalid")
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(c.AuthorizationPublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(publicKey) != c.AuthorizationPublicKey {
		return errors.New("authorization public key must be a canonical unpadded base64url Ed25519 key")
	}
	if _, err := authorization.NewVerifier(c.AuthorizationConfig()); err != nil {
		return fmt.Errorf("authority signing configuration: %w", err)
	}
	return nil
}

func (c TNLD) ACMEEnabled() bool { return c.Mode.RunsControl() }

func (c TNLD) ServerHostname() string {
	if !c.Mode.RunsControl() || c.ServerDomain == "" {
		return ""
	}
	return "control." + c.ServerDomain
}

func (c TNLD) IngressHostname() string {
	if !c.Mode.RunsControl() || c.ServerDomain == "" {
		return ""
	}
	return "ingress." + c.ServerDomain
}

func (c TNLD) StandaloneRelayHostname() string {
	if c.Mode != TNLDModeStandalone || c.ServerDomain == "" {
		return ""
	}
	return "relay." + c.ServerDomain
}

// RelayServiceHostname derives one split relay service's public hostname.
func (c TNLD) RelayServiceHostname(relayServiceID string) string {
	if !c.Mode.RunsControl() || !validDNSLabel(relayServiceID) || c.ServerDomain == "" {
		return ""
	}
	return relayServiceID + "." + c.ServerDomain
}

// IngressControlEndpoint is the fixed private control endpoint returned during ingress enrollment.
func (c TNLD) IngressControlEndpoint() string {
	if hostname := c.ServerHostname(); hostname != "" {
		return "https://" + net.JoinHostPort(hostname, "9443")
	}
	return ""
}

// RelayControlEndpoint is the fixed private control endpoint returned during relay enrollment.
func (c TNLD) RelayControlEndpoint() string {
	if hostname := c.ServerHostname(); hostname != "" {
		return "https://" + net.JoinHostPort(hostname, "9444")
	}
	return ""
}

func (c TNLD) ManagedDomain() string { return c.ManagedDeploymentDomain }

func (c TNLD) AuthorityOrigin() string {
	if c.AuthorityEndpoint != "" {
		return c.AuthorityEndpoint
	}
	if hostname := c.ServerHostname(); hostname != "" {
		return "https://" + hostname
	}
	return ""
}

func (c TNLD) EffectiveReservedRouteNames() []string {
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

func ParseTNLD(args []string) (TNLD, error) {
	type arguments TNLD
	var flags arguments
	parser, err := kong.New(&flags, kong.Name("tnld"), kong.Description("tnl server."))
	if err != nil {
		return TNLD{}, err
	}
	if _, err := parser.Parse(args); err != nil {
		return TNLD{}, err
	}
	return ResolveTNLD(TNLD(flags))
}

func ResolveTNLD(config TNLD) (TNLD, error) {
	switch config.Mode {
	case TNLDModeStandalone:
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
	case TNLDModeControl:
		setControlDefaults(&config)
	case TNLDModeIngress:
		if config.IngressListen == "" {
			config.IngressListen = ":443"
		}
	case TNLDModeRelay:
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
		return TNLD{}, err
	}
	return config, nil
}

func setControlDefaults(config *TNLD) {
	if config.ControlListen == "" {
		config.ControlListen = ":443"
	}
	if config.IngressControlListen == "" {
		config.IngressControlListen = ":9443"
	}
	if config.RelayControlListen == "" {
		config.RelayControlListen = ":9444"
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

func validServiceEnrollmentToken(value string) bool {
	return strings.HasPrefix(value, "tnl_enrollment_") && len(value) >= 32 && len(value) <= 4096 &&
		strings.TrimSpace(value) == value && !strings.ContainsAny(value, " \t\r\n")
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
