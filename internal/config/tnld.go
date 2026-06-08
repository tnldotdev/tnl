package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/backup"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/pkg/protocol/workerv1"
)

// TNLDMode selects the responsibilities hosted by a tnld process.
type TNLDMode string

const (
	TNLDModeStandalone          TNLDMode = "standalone"
	TNLDModeEdge                TNLDMode = "edge"
	TNLDModeWorker              TNLDMode = "worker"
	maximumHostnameQuota                 = 100_000
	minimumAccessTokenLifetime           = 5 * time.Minute
	maximumAccessTokenLifetime           = 30 * 24 * time.Hour
	maximumRefreshTokenLifetime          = 365 * 24 * time.Hour
)

type OIDCLoginFlow string

const (
	OIDCLoginFlowDeviceCode            OIDCLoginFlow = "device_code"
	OIDCLoginFlowAuthorizationCodePKCE OIDCLoginFlow = "authorization_code_pkce"
)

// UsesState reports whether the mode owns durable server state.
func (m TNLDMode) UsesState() bool {
	return m != TNLDModeWorker
}

// TNLD configures the tnl server.
type TNLD struct {
	Mode                           TNLDMode      `name:"mode" env:"TNLD_MODE" default:"standalone" enum:"standalone,edge,worker" help:"Process role: ${enum}."`
	StateDir                       string        `name:"state-dir" env:"TNLD_STATE_DIR" help:"Directory for persistent state; defaults to the platform user-state directory."`
	BackupURL                      string        `name:"backup-url" env:"TNLD_BACKUP_URL" help:"S3 URL for continuous state backup and restore."`
	MetricsListen                  string        `name:"metrics-listen" env:"TNLD_METRICS_LISTEN" default:"127.0.0.1:9090" help:"Private Prometheus listen address; empty disables metrics."`
	DNSServer                      string        `name:"dns-server" env:"TNLD_DNS_SERVER" help:"DNS resolver address for public-hostname readiness checks; defaults to the system resolver."`
	PublicListen                   string        `name:"public-listen" env:"TNLD_PUBLIC_LISTEN" default:":443" help:"Public TLS listen address for the control API and routes; empty disables ingress."`
	Domain                         string        `name:"domain" env:"TNLD_DOMAIN" help:"Lowercase DNS domain without a scheme, port, path, or trailing dot; derives the control hostname and route hostname suffix."`
	ControlHostname                string        `name:"control-hostname" env:"TNLD_CONTROL_HOSTNAME" help:"Lowercase control API hostname without a trailing dot; overrides --domain derivation."`
	PublicHostnameSuffix           string        `name:"hostname-suffix" env:"TNLD_HOSTNAME_SUFFIX" help:"Lowercase deployment hostname suffix without a trailing dot; overrides --domain derivation."`
	ReservedRouteNames             []string      `name:"reserved-route-name" env:"TNLD_RESERVED_ROUTE_NAMES" help:"Route base unavailable for user hostnames; repeat for each name."`
	MaxActiveHostnames             int           `name:"max-active-hostnames" env:"TNLD_MAX_ACTIVE_HOSTNAMES" default:"128" help:"Maximum active hostnames per identity."`
	MaxHostnameRequests            int           `name:"max-hostname-requests" env:"TNLD_MAX_HOSTNAME_REQUESTS" default:"1024" help:"Maximum hostname request records per identity."`
	ACMEDirectoryURL               string        `name:"acme-directory-url" env:"TNLD_ACME_DIRECTORY_URL" default:"https://acme-v02.api.letsencrypt.org/directory" help:"ACME directory URL for automatic control and application certificates."`
	ACMEEmail                      string        `name:"acme-email" env:"TNLD_ACME_EMAIL" help:"ACME account contact email."`
	ACMEAcceptTerms                bool          `name:"acme-accept-terms" env:"TNLD_ACME_ACCEPT_TERMS" help:"Explicitly accept the ACME directory terms."`
	ACMEProfile                    string        `name:"acme-profile" env:"TNLD_ACME_PROFILE" default:"tlsserver" help:"ACME certificate profile advertised to publishers."`
	OIDCIssuer                     string        `name:"oidc-issuer" env:"TNLD_OIDC_ISSUER" help:"OIDC issuer used for login."`
	OIDCClientID                   string        `name:"oidc-client-id" env:"TNLD_OIDC_CLIENT_ID" help:"OIDC client ID used for login."`
	OIDCLoginFlow                  OIDCLoginFlow `name:"oidc-login-flow" env:"TNLD_OIDC_LOGIN_FLOW" help:"OIDC login flow: device_code or authorization_code_pkce."`
	AuthorizationAuthorityEndpoint string        `name:"authorization-authority-endpoint" env:"TNLD_AUTHORIZATION_AUTHORITY_ENDPOINT" help:"Exact HTTPS authorization authority origin advertised to clients."`
	AuthorizationIssuer            string        `name:"authorization-issuer" env:"TNLD_AUTHORIZATION_ISSUER" help:"Exact trusted signed-authorization issuer."`
	AuthorizationReceiver          string        `name:"authorization-receiver" env:"TNLD_AUTHORIZATION_RECEIVER" help:"Expected signed-authorization receiver."`
	AuthorizationKeyID             string        `name:"authorization-key-id" env:"TNLD_AUTHORIZATION_KEY_ID" help:"Trusted authorization Ed25519 key ID."`
	AuthorizationPublicKey         string        `name:"authorization-public-key" env:"TNLD_AUTHORIZATION_PUBLIC_KEY" help:"Trusted Ed25519 public key in unpadded base64url form."`
	AccessTokenLifetime            time.Duration `name:"access-token-lifetime" env:"TNLD_ACCESS_TOKEN_LIFETIME" default:"1h" help:"Lifetime of newly issued access tokens."`
	RefreshTokenLifetime           time.Duration `name:"refresh-token-lifetime" env:"TNLD_REFRESH_TOKEN_LIFETIME" default:"720h" help:"Absolute lifetime of newly issued control sessions."`
	RelayProvider                  string        `name:"relay-provider" env:"TNLD_RELAY_PROVIDER" help:"Hosted relay provider; set to tailcat to explicitly use Tailcat's public relays."`
	RelayMapFile                   string        `name:"relay-map-file" env:"TNLD_RELAY_MAP_FILE" type:"path" help:"Approved DERP map JSON file."`
	RelayRegion                    string        `name:"relay-region" env:"TNLD_RELAY_REGION" help:"DERP region code selected from a custom relay map."`
	EdgeURL                        string        `name:"edge-url" env:"TNLD_EDGE_URL" help:"WSS URL of the edge worker endpoint."`
	WorkerToken                    string        `name:"worker-token" env:"TNLD_WORKER_TOKEN" help:"Edge-to-worker authentication token."`
	RouteUsageURL                  string        `name:"route-usage-url" env:"TNLD_ROUTE_USAGE_URL" help:"Route usage receiver base URL."`
	RouteUsageToken                string        `name:"route-usage-token" env:"TNLD_ROUTE_USAGE_TOKEN" help:"Service token for the route usage receiver."`
	WorkerCapacity                 int           `name:"worker-capacity" env:"TNLD_WORKER_CAPACITY" default:"500" help:"Hard route capacity for this worker."`
	WorkerStreamLimit              int           `name:"worker-stream-limit" env:"TNLD_WORKER_STREAM_LIMIT" default:"4096" help:"Maximum multiplexed streams per worker session."`
	PublicConnLimit                int           `name:"public-connection-limit" env:"TNLD_PUBLIC_CONNECTION_LIMIT" default:"20000" help:"Maximum concurrent public connections."`
	RouteConnLimit                 int           `name:"route-connection-limit" env:"TNLD_ROUTE_CONNECTION_LIMIT" default:"500" help:"Maximum concurrent public connections per route."`
	RequireProxyHeader             bool          `name:"require-proxy-header" env:"TNLD_REQUIRE_PROXY_HEADER" help:"Require one trusted outer PROXY v2 header on public ingress."`
	DrainTimeout                   time.Duration `name:"drain-timeout" env:"TNLD_DRAIN_TIMEOUT" default:"30s" help:"Graceful stream drain deadline."`
}

// Validate rejects values that are present but unusable.
func (c TNLD) Validate() error {
	if c.Mode.UsesState() && strings.TrimSpace(c.StateDir) == "" {
		return errors.New("state directory must not be empty")
	}
	if c.BackupURL != "" && !c.Mode.UsesState() {
		return errors.New("backup requires standalone or edge mode")
	}
	if err := backup.ValidateURL(c.BackupURL); err != nil {
		return err
	}
	if err := validateListenAddress(c.MetricsListen); err != nil {
		return fmt.Errorf("metrics listen address: %w", err)
	}
	if err := validateListenAddress(c.DNSServer); err != nil {
		return fmt.Errorf("DNS server address: %w", err)
	}
	if err := validateListenAddress(c.PublicListen); err != nil {
		return fmt.Errorf("public listen address: %w", err)
	}
	if c.WorkerCapacity <= 0 || c.WorkerStreamLimit <= 0 || c.PublicConnLimit <= 0 || c.RouteConnLimit <= 0 {
		return errors.New("capacity and connection limits must be positive")
	}
	if c.MaxActiveHostnames <= 0 || c.MaxHostnameRequests <= 0 {
		return errors.New("hostname quotas must be positive")
	}
	if c.MaxActiveHostnames > maximumHostnameQuota ||
		c.MaxHostnameRequests > maximumHostnameQuota {
		return fmt.Errorf("hostname quotas must not exceed %d", maximumHostnameQuota)
	}
	if c.MaxHostnameRequests < c.MaxActiveHostnames {
		return errors.New("hostname request quota must be at least the active hostname quota")
	}
	if c.DrainTimeout <= 0 {
		return errors.New("drain timeout must be positive")
	}
	if c.AccessTokenLifetime < minimumAccessTokenLifetime || c.AccessTokenLifetime > maximumAccessTokenLifetime {
		return fmt.Errorf("access token lifetime must be between %s and %s", minimumAccessTokenLifetime, maximumAccessTokenLifetime)
	}
	if c.RefreshTokenLifetime < c.AccessTokenLifetime || c.RefreshTokenLifetime > maximumRefreshTokenLifetime {
		return fmt.Errorf("refresh token lifetime must be between the access token lifetime and %s", maximumRefreshTokenLifetime)
	}
	if c.RelayRegion != "" && !validRelayRegion(c.RelayRegion) {
		return errors.New("relay region must contain only lowercase letters, digits, and hyphens")
	}
	if c.RelayProvider != "" && c.RelayProvider != "tailcat" {
		return errors.New("relay provider must be tailcat")
	}
	if err := c.validateOIDC(); err != nil {
		return err
	}
	if err := c.validateAuthorization(); err != nil {
		return err
	}
	if err := c.validateHostnames(); err != nil {
		return err
	}
	if c.ACMEEmail != "" {
		if !validRelayRegion(c.ACMEProfile) {
			return errors.New("ACME profile must contain only lowercase letters, digits, and hyphens")
		}
		directory, err := url.Parse(c.ACMEDirectoryURL)
		if err != nil || directory.Scheme != "https" || directory.Host == "" || directory.User != nil ||
			directory.Fragment != "" {
			return errors.New("ACME directory must be an HTTPS URL")
		}
		address, err := mail.ParseAddress(c.ACMEEmail)
		if err != nil || address.Address != c.ACMEEmail || address.Name != "" {
			return errors.New("ACME email must be a plain email address")
		}
		if !c.Mode.UsesState() || c.PublicListen == "" {
			return errors.New("automatic certificates require state and public ingress")
		}
	}
	if c.PublicListen != "" {
		if !c.Mode.UsesState() {
			return errors.New("worker mode cannot serve public ingress")
		}
		if c.ServerHostname() == "" || c.HostnameSuffix() == "" {
			return errors.New("control hostname and hostname suffix are required when ingress is enabled")
		}
		if !c.ACMEEnabled() {
			return errors.New("ACME is required when ingress is enabled")
		}
		if !c.ACMEAcceptTerms {
			return errors.New("ACME terms must be explicitly accepted when ingress is enabled")
		}
		if c.RelayProvider == "" && c.RelayMapFile == "" {
			return errors.New("control requires a relay provider or custom relay map")
		}
		if c.RelayProvider != "" && c.RelayMapFile != "" {
			return errors.New("relay provider and custom relay map are mutually exclusive")
		}
		if c.Mode == TNLDModeEdge && c.WorkerToken == "" {
			return errors.New("edge control requires a worker token")
		}
		if c.Mode == TNLDModeEdge {
			if _, err := credentials.ParseWorkerToken(credentials.WorkerToken(c.WorkerToken)); err != nil {
				return errors.New("edge worker token is invalid")
			}
		}
	}
	if c.Mode == TNLDModeWorker && c.EdgeURL == "" {
		return errors.New("worker mode requires an edge URL")
	}
	if (c.RouteUsageURL == "") != (c.RouteUsageToken == "") {
		return errors.New("route usage URL and token must be configured together")
	}
	if c.RouteUsageURL != "" {
		if !c.Mode.UsesState() {
			return errors.New("worker mode cannot report route usage")
		}
		if _, err := credentials.ParseServiceToken(credentials.ServiceToken(c.RouteUsageToken)); err != nil {
			return errors.New("route usage token is invalid")
		}
		routeUsageURL, err := url.Parse(c.RouteUsageURL)
		if err != nil || routeUsageURL.Host == "" || routeUsageURL.User != nil || routeUsageURL.RawQuery != "" || routeUsageURL.Fragment != "" {
			return errors.New("route usage URL must be an HTTPS base URL or a loopback HTTP base URL")
		}
		if routeUsageURL.Scheme != "https" && (routeUsageURL.Scheme != "http" || !isLoopbackHost(routeUsageURL.Hostname())) {
			return errors.New("route usage URL must be an HTTPS base URL or a loopback HTTP base URL")
		}
	}
	if c.EdgeURL != "" {
		if c.Mode != TNLDModeWorker {
			return errors.New("edge URL is valid only in worker mode")
		}
		if c.WorkerToken == "" {
			return errors.New("worker token is required when edge URL is set")
		}
		if _, err := credentials.ParseWorkerToken(credentials.WorkerToken(c.WorkerToken)); err != nil {
			return errors.New("worker token is invalid")
		}
		edgeURL, err := url.Parse(c.EdgeURL)
		if err != nil || edgeURL.Scheme != "wss" || edgeURL.Host == "" || edgeURL.User != nil ||
			edgeURL.Path != workerv1.Endpoint || edgeURL.RawQuery != "" || edgeURL.Fragment != "" {
			return errors.New("worker endpoint must be a WSS URL with path /internal/v1/worker")
		}
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

func (c TNLD) OIDCEnabled() bool {
	return c.OIDCIssuer != ""
}

func (c TNLD) validateOIDC() error {
	configured := c.OIDCIssuer != "" || c.OIDCClientID != "" || c.OIDCLoginFlow != ""
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
	return nil
}

// SignedAuthorizationEnabled reports whether the server delegates hostname
// authorization to the configured authority.
func (c TNLD) SignedAuthorizationEnabled() bool {
	return c.AuthorizationAuthorityEndpoint != ""
}

// AuthorizationConfig returns validated verifier configuration. Callers must
// use it only after Validate succeeds and SignedAuthorizationEnabled is true.
func (c TNLD) AuthorizationConfig() authorization.Config {
	publicKey, _ := base64.RawURLEncoding.DecodeString(c.AuthorizationPublicKey)
	return authorization.Config{
		Issuer: c.AuthorizationIssuer, Receiver: c.AuthorizationReceiver,
		KeyID: c.AuthorizationKeyID, PublicKey: ed25519.PublicKey(publicKey),
	}
}

func (c TNLD) validateAuthorization() error {
	values := []string{
		c.AuthorizationAuthorityEndpoint,
		c.AuthorizationIssuer,
		c.AuthorizationReceiver,
		c.AuthorizationKeyID,
		c.AuthorizationPublicKey,
	}
	configured := false
	complete := true
	for _, value := range values {
		configured = configured || value != ""
		complete = complete && value != ""
	}
	if !configured {
		return nil
	}
	if !complete {
		return errors.New("authorization authority configuration is incomplete")
	}
	if !c.Mode.UsesState() {
		return errors.New("authorization authority requires standalone or edge mode")
	}
	authorityEndpoint, err := url.Parse(c.AuthorizationAuthorityEndpoint)
	if err != nil || authorityEndpoint.Scheme != "https" || authorityEndpoint.Host == "" || authorityEndpoint.User != nil ||
		authorityEndpoint.Path != "" || authorityEndpoint.RawQuery != "" || authorityEndpoint.Fragment != "" ||
		authorityEndpoint.Hostname() != strings.ToLower(authorityEndpoint.Hostname()) || authorityEndpoint.Port() == "443" {
		return errors.New("authorization authority endpoint must be a canonical HTTPS origin")
	}
	for name, value := range map[string]string{
		"authorization issuer":   c.AuthorizationIssuer,
		"authorization receiver": c.AuthorizationReceiver,
	} {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
			parsed.RawQuery != "" || parsed.Fragment != "" {
			return fmt.Errorf("%s must be an HTTPS URL without credentials, query, or fragment", name)
		}
	}
	if strings.TrimSpace(c.AuthorizationKeyID) != c.AuthorizationKeyID ||
		c.AuthorizationKeyID == "" || len(c.AuthorizationKeyID) > 128 {
		return errors.New("authorization key ID is invalid")
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(c.AuthorizationPublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize ||
		base64.RawURLEncoding.EncodeToString(publicKey) != c.AuthorizationPublicKey {
		return errors.New("authorization public key must be a canonical unpadded base64url Ed25519 key")
	}
	if _, err := authorization.NewVerifier(c.AuthorizationConfig()); err != nil {
		return fmt.Errorf("authorization authority configuration: %w", err)
	}
	return nil
}

func (c TNLD) validateHostnames() error {
	if c.Domain != "" {
		canonical, err := naming.CanonicalizeHostname(c.Domain)
		if err != nil || canonical != c.Domain {
			return errors.New("domain must be canonical")
		}
	}
	if hostname := c.ServerHostname(); hostname != "" {
		canonical, err := naming.CanonicalizeHostname(hostname)
		if err != nil || canonical != hostname {
			return errors.New("control hostname must be canonical")
		}
	}
	if suffix := c.HostnameSuffix(); suffix != "" {
		canonical, err := naming.CanonicalizeHostname(suffix)
		if err != nil || canonical != suffix || len(suffix)+naming.MaxLabelBytes+1 > naming.MaxHostnameBytes {
			return errors.New("hostname suffix must be canonical and leave room for a base label")
		}
	}
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

// ACMEEnabled reports whether automatic certificates are configured.
func (c TNLD) ACMEEnabled() bool { return c.ACMEDirectoryURL != "" && c.ACMEEmail != "" }

// ServerHostname returns the explicit or domain-derived control API hostname.
func (c TNLD) ServerHostname() string {
	if c.ControlHostname != "" {
		return c.ControlHostname
	}
	if c.Domain == "" {
		return ""
	}
	return "tnl." + c.Domain
}

// HostnameSuffix returns the explicit or domain-derived public application suffix.
func (c TNLD) HostnameSuffix() string {
	if c.PublicHostnameSuffix != "" {
		return c.PublicHostnameSuffix
	}
	if c.Domain == "" {
		return ""
	}
	return c.Domain
}

// EffectiveReservedRouteNames returns configured reservations plus domains and
// the control base when the control hostname is directly beneath the hostname suffix.
func (c TNLD) EffectiveReservedRouteNames() []string {
	result := make([]string, 0, len(c.ReservedRouteNames)+2)
	seen := make(map[string]struct{}, len(c.ReservedRouteNames)+2)
	add := func(name string) {
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
	hostname, suffix := c.ServerHostname(), c.HostnameSuffix()
	if base, found := strings.CutSuffix(hostname, "."+suffix); found && base != "" && !strings.Contains(base, ".") {
		add(base)
	}
	return result
}

// DefaultStateDir returns the native daemon and administration state path.
func DefaultStateDir() (string, error) {
	var root string
	var err error
	if runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		root = os.Getenv("XDG_STATE_HOME")
		if root == "" {
			root, err = os.UserHomeDir()
			root = filepath.Join(root, ".local", "state")
		}
	} else {
		root, err = os.UserConfigDir()
	}
	if err != nil {
		return "", fmt.Errorf("resolve user state directory: %w", err)
	}
	return filepath.Join(root, "tnl", "server"), nil
}

func validRelayRegion(profile string) bool {
	if len(profile) == 0 || len(profile) > 63 || (profile[0] < 'a' || profile[0] > 'z') && (profile[0] < '0' || profile[0] > '9') {
		return false
	}
	for _, char := range profile[1:] {
		if char != '-' && (char < 'a' || char > 'z') && (char < '0' || char > '9') {
			return false
		}
	}
	return true
}

func validateListenAddress(address string) error {
	if address == "" {
		return nil
	}
	if strings.TrimSpace(address) != address {
		return errors.New("must not contain leading or trailing whitespace")
	}
	_, portText, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 0 || port > 65535 {
		return fmt.Errorf("invalid port %q", portText)
	}
	return nil
}

// ParseTNLD parses tnld flags and environment variables.
func ParseTNLD(args []string) (TNLD, error) {
	type arguments TNLD
	var flags arguments
	parser, err := kong.New(
		&flags,
		kong.Name("tnld"),
		kong.Description("tnl server."),
	)
	if err != nil {
		return TNLD{}, err
	}
	if _, err := parser.Parse(args); err != nil {
		return TNLD{}, err
	}
	return ResolveTNLD(TNLD(flags))
}

// ResolveTNLD applies platform defaults and validates parsed daemon configuration.
func ResolveTNLD(config TNLD) (TNLD, error) {
	var err error
	if config.Mode.UsesState() && config.StateDir == "" {
		config.StateDir, err = DefaultStateDir()
		if err != nil {
			return TNLD{}, err
		}
	}
	if config.Mode == TNLDModeWorker && config.PublicListen == ":443" {
		config.PublicListen = ""
	}
	if err := config.Validate(); err != nil {
		return TNLD{}, err
	}
	return config, nil
}
