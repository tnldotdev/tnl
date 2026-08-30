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

// UsesState reports whether the mode owns durable core state.
func (m TNLDMode) UsesState() bool {
	return m != TNLDModeWorker
}

// TNLD configures the core daemon.
type TNLD struct {
	Mode                     TNLDMode      `name:"mode" env:"TNLD_MODE" default:"standalone" enum:"standalone,edge,worker" help:"Process role: ${enum}."`
	StateDir                 string        `name:"state-dir" env:"TNLD_STATE_DIR" help:"Directory for persistent state (required by standalone and edge modes)."`
	MetricsListen            string        `name:"metrics-listen" env:"TNLD_METRICS_LISTEN" default:"127.0.0.1:9090" help:"Private Prometheus listen address; empty disables metrics."`
	PublicListen             string        `name:"public-listen" env:"TNLD_PUBLIC_LISTEN" help:"Public TLS listen address for the control API and routes; empty disables ingress."`
	ControlHostname          string        `name:"control-hostname" env:"TNLD_CONTROL_HOSTNAME" help:"Canonical hostname for the control API."`
	RouteSuffix              string        `name:"route-suffix" env:"TNLD_ROUTE_SUFFIX" help:"Canonical DNS suffix for self-hosted public routes."`
	MaxActiveHostnameClaims  int           `name:"max-active-hostname-claims" env:"TNLD_MAX_ACTIVE_HOSTNAME_CLAIMS" default:"128" help:"Maximum active hostname claims per principal."`
	MaxHostnameClaimRequests int           `name:"max-hostname-claim-requests" env:"TNLD_MAX_HOSTNAME_CLAIM_REQUESTS" default:"1024" help:"Maximum hostname claim request records per principal."`
	ControlCertFile          string        `name:"control-cert-file" env:"TNLD_CONTROL_CERT_FILE" type:"path" help:"Control HTTPS certificate file."`
	ControlKeyFile           string        `name:"control-key-file" env:"TNLD_CONTROL_KEY_FILE" type:"path" help:"Control HTTPS private key file."`
	ACMEDirectoryURL         string        `name:"acme-directory-url" env:"TNLD_ACME_DIRECTORY_URL" help:"ACME directory URL for automatic control and application certificates."`
	ACMEEmail                string        `name:"acme-email" env:"TNLD_ACME_EMAIL" help:"ACME account contact email."`
	ACMEAcceptTerms          bool          `name:"acme-accept-terms" env:"TNLD_ACME_ACCEPT_TERMS" help:"Explicitly accept the ACME directory terms."`
	ACMEProfile              string        `name:"acme-profile" env:"TNLD_ACME_PROFILE" default:"tlsserver" help:"ACME certificate profile advertised to agents."`
	BootstrapToken           string        `name:"bootstrap-token" env:"TNLD_BOOTSTRAP_TOKEN" help:"Local deployment bootstrap credential."`
	RelayMapFile             string        `name:"relay-map-file" env:"TNLD_RELAY_MAP_FILE" type:"path" help:"Approved DERP map JSON file."`
	RelayProfile             string        `name:"relay-profile" env:"TNLD_RELAY_PROFILE" default:"default" help:"DERP region code advertised as the relay profile."`
	WorkerURL                string        `name:"worker-url" env:"TNLD_WORKER_URL" help:"Worker-mode WSS edge URL."`
	WorkerToken              string        `name:"worker-token" env:"TNLD_WORKER_TOKEN" help:"Edge-to-worker authentication token."`
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
	if !validRelayProfile(c.RelayProfile) {
		return errors.New("relay profile must contain only lowercase letters, digits, and hyphens")
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
		if c.ControlHostname == "" || c.BootstrapToken == "" || c.RouteSuffix == "" {
			return errors.New("control hostname, bootstrap token, and route suffix are required when ingress is enabled")
		}
		canonicalControl, err := naming.CanonicalizeHostname(c.ControlHostname)
		if err != nil || canonicalControl != c.ControlHostname {
			return errors.New("control hostname must be canonical")
		}
		if c.ControlCertFile == "" != (c.ControlKeyFile == "") {
			return errors.New("control certificate and key files must be configured together")
		}
		if c.ControlCertFile == "" && !c.ACMEEnabled() {
			return errors.New("ACME or control certificate and key files are required when ingress is enabled")
		}
		canonicalSuffix, err := naming.CanonicalizeHostname(c.RouteSuffix)
		if err != nil || canonicalSuffix != c.RouteSuffix ||
			len(canonicalSuffix) > naming.MaxHostnameBytes-naming.MaxLabelBytes-1 {
			return errors.New("route suffix must be canonical and leave room for one DNS label")
		}
		if _, err := credentials.ParseBootstrapToken(credentials.BootstrapToken(c.BootstrapToken)); err != nil {
			return errors.New("control bootstrap token is invalid")
		}
		if c.Mode == TNLDModeStandalone && c.RelayMapFile == "" {
			return errors.New("standalone control requires a relay map")
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
	if c.WorkerURL != "" {
		if c.Mode != TNLDModeWorker {
			return errors.New("worker URL is valid only in worker mode")
		}
		if c.WorkerToken == "" || c.RelayMapFile == "" {
			return errors.New("worker token and relay map are required when worker URL is set")
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

// ACMEEnabled reports whether automatic application certificates are configured.
func (c TNLD) ACMEEnabled() bool { return c.ACMEDirectoryURL != "" && c.ACMEEmail != "" }

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
		kong.Description("TNL core daemon."),
	)
	if err != nil {
		return TNLD{}, err
	}
	if _, err := parser.Parse(args); err != nil {
		return TNLD{}, err
	}
	return config, nil
}
