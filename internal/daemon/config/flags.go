//go:build !js || !wasm

package config

import (
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/tnldotdev/tnl/internal/cliflags"
)

func Parse(args []string) (Config, error) {
	var settings Config
	cmd := &cobra.Command{Use: "tnld"}
	cliflags.Bind(cmd, &settings, false)
	if err := cmd.ParseFlags(args); err != nil {
		return Config{}, err
	}
	if err := cmd.ValidateArgs(cmd.Flags().Args()); err != nil {
		return Config{}, err
	}
	supplied := map[string]bool{}
	cmd.Flags().Visit(func(f *pflag.Flag) { supplied[strings.ReplaceAll(f.Name, "-", "_")] = true })
	return ResolveExplicit(settings, supplied)
}
