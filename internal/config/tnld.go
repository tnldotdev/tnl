package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/0xcadams/tnl/internal/credentials"
	"github.com/0xcadams/tnl/pkg/protocol/workerv1"
	"github.com/alecthomas/kong"
)

// TNLDMode selects the responsibilities hosted by a tnld process.
type TNLDMode string

const (
	TNLDModeStandalone TNLDMode = "standalone"
	TNLDModeEdge       TNLDMode = "edge"
	TNLDModeWorker     TNLDMode = "worker"
)

// UsesState reports whether the mode owns durable core state.
func (m TNLDMode) UsesState() bool {
	return m != TNLDModeWorker
}

// TNLD configures the core daemon.
type TNLD struct {
	Mode               TNLDMode      `name:"mode" env:"TNLD_MODE" default:"standalone" enum:"standalone,edge,worker" help:"Process role: ${enum}."`
	StateDir           string        `name:"state-dir" env:"TNLD_STATE_DIR" help:"Directory for persistent state (required by standalone and edge modes)."`
	MetricsListen      string        `name:"metrics-listen" env:"TNLD_METRICS_LISTEN" default:"127.0.0.1:9090" help:"Private Prometheus listen address; empty disables metrics."`
	ControlListen      string        `name:"control-listen" env:"TNLD_CONTROL_LISTEN" help:"HTTPS core API listen address; empty disables the API."`
	PublicListen       string        `name:"public-listen" env:"TNLD_PUBLIC_LISTEN" help:"Public opaque TLS listen address; empty disables ingress."`
	ControlCertFile    string        `name:"control-cert-file" env:"TNLD_CONTROL_CERT_FILE" type:"path" help:"Control HTTPS certificate file."`
	ControlKeyFile     string        `name:"control-key-file" env:"TNLD_CONTROL_KEY_FILE" type:"path" help:"Control HTTPS private key file."`
	BootstrapToken     string        `name:"bootstrap-token" env:"TNLD_BOOTSTRAP_TOKEN" help:"Local deployment bootstrap credential."`
	RelayMapFile       string        `name:"relay-map-file" env:"TNLD_RELAY_MAP_FILE" type:"path" help:"Approved DERP map JSON file."`
	RelayProfile       string        `name:"relay-profile" env:"TNLD_RELAY_PROFILE" default:"default" help:"DERP region code advertised as the relay profile."`
	WorkerURL          string        `name:"worker-url" env:"TNLD_WORKER_URL" help:"Worker-mode WSS edge URL."`
	WorkerToken        string        `name:"worker-token" env:"TNLD_WORKER_TOKEN" help:"Edge-to-worker authentication token."`
	WorkerCapacity     int           `name:"worker-capacity" env:"TNLD_WORKER_CAPACITY" default:"500" help:"Hard route capacity for this worker."`
	WorkerStreamLimit  int           `name:"worker-stream-limit" env:"TNLD_WORKER_STREAM_LIMIT" default:"4096" help:"Maximum multiplexed streams per worker session."`
	PublicConnLimit    int           `name:"public-connection-limit" env:"TNLD_PUBLIC_CONNECTION_LIMIT" default:"20000" help:"Maximum concurrent public connections."`
	RouteConnLimit     int           `name:"route-connection-limit" env:"TNLD_ROUTE_CONNECTION_LIMIT" default:"500" help:"Maximum concurrent public connections per route."`
	RequireProxyHeader bool          `name:"require-proxy-header" env:"TNLD_REQUIRE_PROXY_HEADER" help:"Require one trusted outer PROXY v2 header on public ingress."`
	DrainTimeout       time.Duration `name:"drain-timeout" env:"TNLD_DRAIN_TIMEOUT" default:"30s" help:"Graceful stream drain deadline."`
}

// Validate rejects values that are present but unusable.
func (c TNLD) Validate() error {
	if c.Mode.UsesState() && strings.TrimSpace(c.StateDir) == "" {
		return errors.New("state directory must not be empty")
	}
	if err := validateListenAddress(c.MetricsListen); err != nil {
		return fmt.Errorf("metrics listen address: %w", err)
	}
	if err := validateListenAddress(c.ControlListen); err != nil {
		return fmt.Errorf("control listen address: %w", err)
	}
	if err := validateListenAddress(c.PublicListen); err != nil {
		return fmt.Errorf("public listen address: %w", err)
	}
	if c.WorkerCapacity <= 0 || c.WorkerStreamLimit <= 0 || c.PublicConnLimit <= 0 || c.RouteConnLimit <= 0 {
		return errors.New("capacity and connection limits must be positive")
	}
	if c.DrainTimeout <= 0 {
		return errors.New("drain timeout must be positive")
	}
	if !validRelayProfile(c.RelayProfile) {
		return errors.New("relay profile must contain only lowercase letters, digits, and hyphens")
	}
	if c.ControlListen != "" {
		if !c.Mode.UsesState() {
			return errors.New("worker mode cannot serve the control API")
		}
		if c.ControlCertFile == "" || c.ControlKeyFile == "" || c.BootstrapToken == "" {
			return errors.New("control certificate, key, and bootstrap token are required when control is enabled")
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
	if c.PublicListen != "" && c.ControlListen == "" {
		return errors.New("public ingress requires the control API")
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
