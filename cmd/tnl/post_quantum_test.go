package main

import (
	"io"
	"testing"

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
			parser := commandForTest(&flags, io.Discard)
			if _, err := parser(append([]string{"publish", "3000"}, test.args...)); err != nil {
				t.Fatal(err)
			}
			applyServiceConfiguration(&flags.Publish.tunnelFlags, config.Service{RequirePostQuantum: test.configured})
			got := publicOptions(flags.Publish).RequirePostQuantum
			if (got == nil) != (test.want == nil) || got != nil && *got != *test.want {
				t.Fatalf("public HTTPS requirement = %v, want %v", got, test.want)
			}
		})
	}
}
