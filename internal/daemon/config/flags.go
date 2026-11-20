//go:build !js || !wasm

package config

import (
	"strings"

	"github.com/alecthomas/kong"
)

func Parse(args []string) (Config, error) {
	type arguments Config
	var flags arguments
	parser, err := kong.New(&flags, kong.Name("tnld"), kong.Description("tnl server."))
	if err != nil {
		return Config{}, err
	}
	parsed, err := parser.Parse(args)
	if err != nil {
		return Config{}, err
	}
	supplied := map[string]bool{}
	for _, element := range parsed.Path {
		if element.Flag != nil && !element.Resolved {
			supplied[strings.ReplaceAll(element.Flag.Name, "-", "_")] = true
		}
	}
	return ResolveExplicit(Config(flags), supplied)
}
