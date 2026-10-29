package main

import (
	"os"
	"testing"

	"github.com/alecthomas/kong"
)

func TestTelemetryOptOutRetainsKongBooleanGrammar(t *testing.T) {
	for _, test := range []struct {
		value string
		want  bool
		valid bool
	}{
		{"true", true, true}, {"TRUE", true, true}, {"TrUe", true, true},
		{"yes", true, true}, {"YES", true, true}, {"1", true, true},
		{"false", false, true}, {"FALSE", false, true}, {"FaLsE", false, true},
		{"no", false, true}, {"NO", false, true}, {"0", false, true},
		{"", false, false}, {"t", false, false}, {"T", false, false},
		{"f", false, false}, {"F", false, false}, {" true", false, false},
		{"false ", false, false}, {"on", false, false}, {"off", false, false},
		{"2", false, false}, {"private", false, false},
	} {
		t.Run("environment/"+test.value, func(t *testing.T) {
			t.Setenv("TNL_NO_TELEMETRY", test.value)
			var flags cli
			parser, err := kong.New(&flags)
			if err != nil {
				t.Fatal(err)
			}
			_, err = parser.Parse([]string{"version"})
			if (err == nil) != test.valid || err == nil && flags.NoTelemetry != test.want {
				t.Fatalf("Kong environment %q: disabled=%t err=%v", test.value, flags.NoTelemetry, err)
			}
		})
		t.Run("flag/"+test.value, func(t *testing.T) {
			t.Setenv("TNL_NO_TELEMETRY", "false")
			var flags cli
			parser, err := kong.New(&flags)
			if err != nil {
				t.Fatal(err)
			}
			_, err = parser.Parse([]string{"--no-telemetry=" + test.value, "version"})
			if (err == nil) != test.valid || err == nil && flags.NoTelemetry != test.want {
				t.Fatalf("Kong flag %q: disabled=%t err=%v", test.value, flags.NoTelemetry, err)
			}
		})
	}
	t.Run("absent", func(t *testing.T) {
		t.Setenv("TNL_NO_TELEMETRY", "false")
		if err := os.Unsetenv("TNL_NO_TELEMETRY"); err != nil {
			t.Fatal(err)
		}
		var flags cli
		parser, err := kong.New(&flags)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parser.Parse([]string{"version"}); err != nil || flags.NoTelemetry {
			t.Fatalf("absent opt-out: disabled=%t err=%v", flags.NoTelemetry, err)
		}
	})
}
