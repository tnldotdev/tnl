package main

import (
	"errors"
	"io"
	"slices"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/region"
)

func TestPublishProviderRegionFlags(t *testing.T) {
	for _, args := range [][]string{
		{"publish", "3000"},
		{"publish", "3000", "--prefer-region=fly:sjc", "--prefer-region=aws:us-west-1"},
	} {
		t.Setenv("TNL_PREFERRED_REGIONS", "fly:sjc,aws:us-west-1")
		var root cli
		parser, err := kong.New(&root)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parser.Parse(args); err != nil {
			t.Fatal(err)
		}
		options := publicOptions(root.Publish)
		if !slices.Equal(options.PreferredRegions, []string{"fly:sjc", "aws:us-west-1"}) {
			t.Fatal("publisher options lost provider-qualified flag order", options.PreferredRegions)
		}
	}
	for _, value := range []string{"sjc", "aws:sjc", "gcp:us-west-1"} {
		err := runPublish(t.Context(), publishCommand{PreferredRegions: []string{value}}, io.Discard, io.Discard, nil)
		typed, ok := failure.Of(err)
		if !errors.Is(err, region.ErrPreference) || !ok || typed.Reason() != failure.InvalidTunnelFlags {
			t.Fatal("invalid region opened publisher state or lost its diagnostic", value, err)
		}
	}
}
