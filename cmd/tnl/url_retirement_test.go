package main

import (
	"io"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/failure"
)

func TestURLRetirementFlags(t *testing.T) {
	for _, choice := range []string{"--keep", "--auto-retire"} {
		var flags cli
		parser, err := kong.New(&flags)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parser.Parse([]string{"url", "update", "public_url_example", choice}); err != nil {
			t.Fatal(err)
		}
		if flags.URL.Update.Keep != (choice == "--keep") || flags.URL.Update.AutoRetire != (choice == "--auto-retire") {
			t.Fatalf("URL retirement choice %q = %+v", choice, flags.URL.Update)
		}
	}
	err := runURLUpdate(t.Context(), publicURLUpdateCommand{Keep: true, AutoRetire: true}, io.Discard, io.Discard)
	if reason, _, ok := failure.Describe(err); !ok || reason != failure.InvalidTunnelFlags {
		t.Fatalf("contradictory retention choice = %v", err)
	}
}
