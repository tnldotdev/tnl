package main

import (
	"testing"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/config"
)

func TestPublishPostQuantumFlagOverridesProjectDefault(t *testing.T) {
	for _, test := range []struct {
		name       string
		args       []string
		configured *bool
		want       *bool
	}{
		{"omitted", nil, nil, nil},
		{"flag", []string{"--require-post-quantum"}, nil, new(true)},
		{"config", nil, new(true), new(true)},
		{"explicit false", []string{"--require-post-quantum=false"}, new(true), new(false)},
	} {
		t.Run(test.name, func(t *testing.T) {
			var flags cli
			parser, err := kong.New(&flags)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parser.Parse(append([]string{"publish", "3000"}, test.args...)); err != nil {
				t.Fatal(err)
			}
			applyTunnelConfiguration(&flags.Publish.tunnelFlags, &config.Tunnel{RequirePostQuantum: test.configured})
			got := publicOptions(flags.Publish).RequirePostQuantum
			if (got == nil) != (test.want == nil) || got != nil && *got != *test.want {
				t.Fatalf("public HTTPS requirement = %v, want %v", got, test.want)
			}
		})
	}
}
