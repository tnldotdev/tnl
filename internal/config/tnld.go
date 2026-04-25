package config

import (
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/0xcadams/tnl/internal/credentials"
	"github.com/0xcadams/tnl/internal/naming"
	"github.com/0xcadams/tnl/pkg/protocol/workerv1"
	"github.com/alecthomas/kong"
)

// TNLDMode selects the responsibilities hosted by a tnld process.
type TNLDMode string

const (
	TNLDModeStandalone        TNLDMode = "standalone"
	TNLDModeEdge              TNLDMode = "edge"
	TNLDModeWorker            TNLDMode = "worker"
	maximumHostnameClaimQuota          = 100_000
)

// UsesState reports whether the mode owns durable server state.
func (m TNLDMode) UsesState() bool {
	return m != TNLDModeWorker
}

// TNLD configures the tnl server.
type TNLD struct {
	Mode                     TNLDMode      `name:"mode" env:"TNLD_MODE" default:"standalone" enum:"standalone,edge,worker" help:"Process role: ${enum}."`
	StateDir                 string        `name:"state-dir" env:"TNLD_STATE_DIR" help:"Directory for persistent state (required by standalone and edge modes)."`
	MetricsListen            string        `name:"metrics-listen" env:"TNLD_METRICS_LISTEN" default:"127.0.0.1:9090" help:"Private Prometheus listen address; empty disables metrics."`
	PublicListen             string        `name:"public-listen" env:"TNLD_PUBLIC_LISTEN" help:"Public TLS listen address for the control API and routes; empty disables ingress."`
	Domain                   string        `name:"domain" env:"TNLD_DOMAIN" help:"Canonical base domain; derives tnl.<domain> and apps.<domain>."`
	MaxActiveHostnameClaims  int           `name:"max-active-hostname-claims" env:"TNLD_MAX_ACTIVE_HOSTNAME_CLAIMS" default:"128" help:"Maximum active hostname claims per principal."`
	MaxHostnameClaimRequests int           `name:"max-hostname-claim-requests" env:"TNLD_MAX_HOSTNAME_CLAIM_REQUESTS" default:"1024" help:"Maximum hostname claim request records per principal."`
	ACMEDirectoryURL         string        `name:"acme-directory-url" env:"TNLD_ACME_DIRECTORY_URL" help:"ACME directory URL for automatic control and application certificates."`
	ACMEEmail                string        `name:"acme-email" env:"TNLD_ACME_EMAIL" help:"ACME account contact email."`
	ACMEAcceptTerms          bool          `name:"acme-accept-terms" env:"TNLD_ACME_ACCEPT_TERMS" help:"Explicitly accept the ACME directory terms."`
	ACMEProfile              string        `name:"acme-profile" env:"TNLD_ACME_PROFILE" default:"tlsserver" help:"ACME certificate profile advertised to agents."`
	OIDCIssuer               string        `name:"oidc-issuer" env:"TNLD_OIDC_ISSUER" help:"OIDC issuer used for login."`
	OIDCClientID             string        `name:"oidc-client-id" env:"TNLD_OIDC_CLIENT_ID" help:"OIDC client ID used for login."`
	RelayProvider            string        `name:"relay-provider" env:"TNLD_RELAY_PROVIDER" help:"Hosted relay provider; set to tailcat to explicitly use Tailcat's public relays."`
	RelayMapFile             string        `name:"relay-map-file" env:"TNLD_RELAY_MAP_FILE" type:"path" help:"Approved DERP map JSON file."`
	RelayProfile             string        `name:"relay-profile" env:"TNLD_RELAY_PROFILE" help:"DERP region code selected from a custom relay map."`
	WorkerURL                string        `name:"worker-url" env:"TNLD_WORKER_URL" help:"Worker-mode WSS edge URL."`
	WorkerToken              string        `name:"worker-token" env:"TNLD_WORKER_TOKEN" help:"Edge-to-worker authentication token."`
	ExportURL                string        `name:"export-url" env:"TNLD_EXPORT_URL" help:"Compatible route export receiver base URL."`
	ExportToken              string        `name:"export-token" env:"TNLD_EXPORT_TOKEN" help:"Service token for the route export receiver."`
	WorkerCapacity           int           `name:"worker-capacity" env:"TNLD_WORKER_CAPACITY" default:"500" help:"Hard route capacity for this worker."`
	WorkerStreamLimit        int           `name:"worker-stream-limit" env:"TNLD_WORKER_STREAM_LIMIT" default:"4096" help:"Maximum multiplexed streams per worker session."`
	PublicConnLimit          int           `name:"public-connection-limit" env:"TNLD_PUBLIC_CONNECTION_LIMIT" default:"20000" help:"Maximum concurrent public connections."`
	RouteConnLimit           int           `name:"route-connection-limit" env:"TNLD_ROUTE_CONNECTION_LIMIT" default:"500" help:"Maximum concurrent public connections per route."`
	RequireProxyHeader       bool          `name:"require-proxy-header" env:"TNLD_REQUIRE_PROXY_HEADER" help:"Require one trusted outer PROXY v2 header on public ingress."`
	DrainTimeout             time.Duration `name:"drain-timeout" env:"TNLD_DRAIN_TIMEOUT" default:"30s" help:"Graceful stream drain deadline."`
}

// Validate rejects values that are present but unusable.
func (c TNLD) Validate() error {
	if c.Mode.UsesState() && strings.TrimSpace(c.StateDir) == "" {
		return errors.New("state directory must not be empty")
	}
	if err := validateListenAddress(c.MetricsListen); err != nil {
		return fmt.Errorf("metrics listen address: %w", err)
	}
	if err := validateListenAddress(c.PublicListen); err != nil {
		return fmt.Errorf("public listen address: %w", err)
	}
	if c.WorkerCapacity <= 0 || c.WorkerStreamLimit <= 0 || c.PublicConnLimit <= 0 || c.RouteConnLimit <= 0 {
		return errors.New("capacity and connection limits must be positive")
	}
	if c.MaxActiveHostnameClaims <= 0 || c.MaxHostnameClaimRequests <= 0 {
		return errors.New("hostname claim quotas must be positive")
	}
	if c.MaxActiveHostnameClaims > maximumHostnameClaimQuota ||
		c.MaxHostnameClaimRequests > maximumHostnameClaimQuota {
		return fmt.Errorf("hostname claim quotas must not exceed %d", maximumHostnameClaimQuota)
	}
	if c.MaxHostnameClaimRequests < c.MaxActiveHostnameClaims {
		return errors.New("hostname claim request quota must be at least the active claim quota")
	}
	if c.DrainTimeout <= 0 {
		return errors.New("drain timeout must be positive")
	}
	if c.RelayProfile != "" && !validRelayProfile(c.RelayProfile) {
		return errors.New("relay profile must contain only lowercase letters, digits, and hyphens")
	}
	if c.RelayProvider != "" && c.RelayProvider != "tailcat" {
		return errors.New("relay provider must be tailcat")
	}
	if c.RelayProvider != "" && (c.RelayMapFile != "" || c.RelayProfile != "") {
		return errors.New("relay provider cannot be combined with a custom relay map or profile")
	}
	if err := c.validateOIDC(); err != nil {
		return err
	}
	if c.ACMEDirectoryURL != "" || c.ACMEEmail != "" {
		if !validRelayProfile(c.ACMEProfile) {
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
		if c.Domain == "" {
			return errors.New("domain is required when ingress is enabled")
		}
		canonicalDomain, err := naming.CanonicalizeHostname(c.Domain)
		if err != nil || canonicalDomain != c.Domain ||
			len("apps."+canonicalDomain) > naming.MaxHostnameBytes-naming.MaxLabelBytes-1 {
			return errors.New("domain must be canonical and leave room for derived hostnames and one route label")
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
		if c.Mode == TNLDModeEdge && c.WorkerToken == "" {
			return errors.New("edge control requires a worker token")
		}
		if c.Mode == TNLDModeEdge {
			if _, err := credentials.ParseWorkerToken(credentials.WorkerToken(c.WorkerToken)); err != nil {
				return errors.New("edge worker token is invalid")
			}
		}
	}
	if c.Mode == TNLDModeWorker && c.WorkerURL == "" {
		return errors.New("worker mode requires a worker URL")
	}
	if (c.ExportURL == "") != (c.ExportToken == "") {
		return errors.New("export URL and token must be configured together")
	}
	if c.ExportURL != "" {
		if !c.Mode.UsesState() {
			return errors.New("worker mode cannot export route usage")
		}
		if _, err := credentials.ParseServiceToken(credentials.ServiceToken(c.ExportToken)); err != nil {
			return errors.New("export token is invalid")
		}
		exportURL, err := url.Parse(c.ExportURL)
		if err != nil || exportURL.Host == "" || exportURL.User != nil || exportURL.RawQuery != "" || exportURL.Fragment != "" {
			return errors.New("export URL must be an HTTPS base URL or a loopback HTTP base URL")
		}
		if exportURL.Scheme != "https" && (exportURL.Scheme != "http" || !isLoopbackHost(exportURL.Hostname())) {
			return errors.New("export URL must be an HTTPS base URL or a loopback HTTP base URL")
		}
	}
	if c.WorkerURL != "" {
		if c.Mode != TNLDModeWorker {
			return errors.New("worker URL is valid only in worker mode")
		}
		if c.WorkerToken == "" {
			return errors.New("worker token is required when worker URL is set")
		}
		if _, err := credentials.ParseWorkerToken(credentials.WorkerToken(c.WorkerToken)); err != nil {
			return errors.New("worker token is invalid")
		}
		workerURL, err := url.Parse(c.WorkerURL)
		if err != nil || workerURL.Scheme != "wss" || workerURL.Host == "" || workerURL.User != nil ||
			workerURL.Path != workerv1.Endpoint || workerURL.RawQuery != "" || workerURL.Fragment != "" {
			return fmt.Errorf("worker URL must be a wss origin with path %s", workerv1.Endpoint)
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
	configured := c.OIDCIssuer != "" || c.OIDCClientID != ""
	if !configured {
		return nil
	}
	if c.OIDCIssuer == "" || c.OIDCClientID == "" {
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
	return nil
}

// ACMEEnabled reports whether automatic certificates are configured.
func (c TNLD) ACMEEnabled() bool { return c.ACMEDirectoryURL != "" && c.ACMEEmail != "" }

// ServerHostname returns the control API hostname derived from Domain.
func (c TNLD) ServerHostname() string {
	if c.Domain == "" {
		return ""
	}
	return "tnl." + c.Domain
}

// RouteSuffix returns the public application suffix derived from Domain.
func (c TNLD) RouteSuffix() string {
	if c.Domain == "" {
		return ""
	}
	return "apps." + c.Domain
}

func validRelayProfile(profile string) bool {
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
	var config TNLD
	parser, err := kong.New(
		&config,
		kong.Name("tnld"),
		kong.Description("tnl server."),
	)
	if err != nil {
		return TNLD{}, err
	}
	if _, err := parser.Parse(args); err != nil {
		return TNLD{}, err
	}
	return config, nil
}
