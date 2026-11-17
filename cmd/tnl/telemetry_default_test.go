package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
)

func TestTelemetryDefaultAndPersistentOptOutAtCLIEntrypoints(t *testing.T) {
	for _, entry := range []string{"publish", "demo"} {
		t.Run(entry, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "state")
			t.Setenv("TNL_STATE_DIR", root)
			t.Setenv("TNL_NO_TELEMETRY", "")
			if err := os.Unsetenv("TNL_NO_TELEMETRY"); err != nil {
				t.Fatal(err)
			}
			config := filepath.Join(t.TempDir(), "invalid.json")
			if err := os.WriteFile(config, []byte("{"), 0o600); err != nil {
				t.Fatal(err)
			}
			args := []string{"--config", config, "publish", "3000"}
			if entry == "demo" {
				// invalid control origin stops before any external network request,
				// after normal CLI telemetry selection and demo preparation.
				args = []string{"publish", "--demo", "--open=false", "--server=http://control.example"}
			}
			recorded := recordTelemetry(t)
			invoke := func(prefix ...string) {
				t.Helper()
				command := append(append([]string{}, prefix...), args...)
				if err := run(t.Context(), command, io.Discard, io.Discard, recorded.factory); err == nil {
					t.Fatal("fixture did not stop at its intentional setup failure")
				}
			}
			preference := func(action string) {
				t.Helper()
				if err := run(t.Context(), []string{"telemetry", action}, io.Discard, io.Discard, recorded.factory); err != nil {
					t.Fatal(err)
				}
			}
			expect := func(count int) {
				t.Helper()
				if got := len(recorded.events()); got != count {
					t.Fatalf("delivered command events = %d, want %d", got, count)
				}
			}
			invoke()
			expect(1)
			preference("off")
			for range 2 {
				invoke()
				expect(1)
			}
			enabled, err := clientstate.TelemetryEnabledAt(t.Context(), root)
			if err != nil || enabled {
				t.Fatal("command restart reset the saved opt-out", err)
			}
			preference("on")
			invoke("--no-telemetry")
			expect(1)
			invoke()
			expect(2)
			t.Setenv("TNL_NO_TELEMETRY", "true")
			invoke()
			expect(2)
			if err := os.Unsetenv("TNL_NO_TELEMETRY"); err != nil {
				t.Fatal(err)
			}
			invoke()
			expect(3)
			enabled, err = clientstate.TelemetryEnabledAt(t.Context(), root)
			if err != nil || !enabled {
				t.Fatal("one-command opt-out changed the shared saved preference", err)
			}
		})
	}
}
