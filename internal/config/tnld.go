// Package config parses command configuration.
package config

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

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
	Mode          TNLDMode `name:"mode" env:"TNLD_MODE" default:"standalone" enum:"standalone,edge,worker" help:"Process role: ${enum}."`
	StateDir      string   `name:"state-dir" env:"TNLD_STATE_DIR" help:"Directory for persistent state (required by standalone and edge modes)."`
	MetricsListen string   `name:"metrics-listen" env:"TNLD_METRICS_LISTEN" default:"127.0.0.1:9090" help:"Private Prometheus listen address; empty disables metrics."`
}

// Validate rejects values that are present but unusable.
func (c TNLD) Validate() error {
	if c.Mode.UsesState() && strings.TrimSpace(c.StateDir) == "" {
		return errors.New("state directory must not be empty")
	}
	if err := validateListenAddress(c.MetricsListen); err != nil {
		return fmt.Errorf("metrics listen address: %w", err)
	}
	return nil
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
