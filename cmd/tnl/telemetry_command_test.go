package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestTelemetryCommandControlsFutureCommandEvents(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	t.Setenv("TNL_STATE_DIR", root)
	r := recordTelemetry(t)
	invoke := func(args ...string) string {
		t.Helper()
		var stdout, stderr bytes.Buffer
		if err := run(t.Context(), args, &stdout, &stderr, r.factory); err != nil {
			t.Fatalf("tnl %v: %v (%s)", args, err, stderr.String())
		}
		return stdout.String()
	}
	if result := invoke("telemetry", "status"); result != "Usage telemetry is on.\n" {
		t.Fatalf("initial status output = %q", result)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("status created client state: %v", err)
	}
	if result := invoke("telemetry", "off"); result != "Usage telemetry is off.\n" {
		t.Fatalf("off output = %q", result)
	}
	if result := invoke("telemetry", "status"); result != "Usage telemetry is off.\n" {
		t.Fatalf("status output = %q", result)
	}
	invoke("version")
	if events := r.events(); len(events) != 0 {
		t.Fatalf("telemetry commands or disabled client sent events: %#v", events)
	}
	if result := invoke("telemetry", "on"); result != "Usage telemetry is on.\n" {
		t.Fatalf("on output = %q", result)
	}
	invoke("--no-telemetry", "version")
	t.Setenv("TNL_NO_TELEMETRY", "true")
	invoke("version")
	if events := r.events(); len(events) != 0 {
		t.Fatalf("disabled one-run overrides sent events: %#v", events)
	}
	t.Setenv("TNL_NO_TELEMETRY", "false")
	invoke("version")
	if events := r.events(); len(events) != 0 {
		t.Fatalf("version sent telemetry: %#v", events)
	}
}
