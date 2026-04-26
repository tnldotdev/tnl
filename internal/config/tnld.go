// Package config parses command configuration.
package config

import (
	"errors"
	"strings"

	"github.com/alecthomas/kong"
)

// TNLD configures the core daemon.
type TNLD struct {
	StateDir string `name:"state-dir" env:"TNLD_STATE_DIR" required:"" help:"Directory for persistent state."`
}

// Validate rejects values that are present but unusable.
func (c TNLD) Validate() error {
	if strings.TrimSpace(c.StateDir) == "" {
		return errors.New("state directory must not be empty")
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
