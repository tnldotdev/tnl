package clientstate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTelemetryPreferenceIsPersistentAndDoesNotCreateStateOnRead(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	read := func(want bool) {
		t.Helper()
		enabled, err := TelemetryEnabledAt(t.Context(), root)
		if err != nil || enabled != want {
			t.Fatalf("telemetry enabled = %t, error = %v; want %t", enabled, err, want)
		}
	}
	readDemo := func(want bool) {
		t.Helper()
		enabled, err := DemoTelemetryEnabledAt(t.Context(), root)
		if err != nil || enabled != want {
			t.Fatalf("demo telemetry enabled = %t, error = %v; want %t", enabled, err, want)
		}
	}
	read(true)
	readDemo(false)
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("read of absent client state created files: %v", err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	// an old client.db must not be opened or imported when client-v1.db is absent.
	if err := os.WriteFile(filepath.Join(root, "client.db"), []byte("old database"), 0o600); err != nil {
		t.Fatal(err)
	}
	read(true)
	readDemo(false)
	if _, err := os.Stat(DatabasePath(root)); !os.IsNotExist(err) {
		t.Fatalf("telemetry read created versioned state: %v", err)
	}
	state, err := Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.SetTelemetryEnabled(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	read(false)
	readDemo(false)
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	state, err = Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	enabled, err := state.TelemetryEnabled(t.Context())
	if err != nil || enabled {
		t.Fatalf("reopened telemetry preference = %t, error = %v", enabled, err)
	}
	if err := state.SetTelemetryEnabled(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	read(true)
	readDemo(true)
}
