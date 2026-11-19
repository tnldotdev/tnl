//go:build !js || !wasm

package config

import "github.com/alecthomas/kong"

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
