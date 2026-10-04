package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTelemetryCommandControlsFutureCommandEvents(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	t.Setenv("TNL_STATE_DIR", root)
	var events []telemetryPayload
	factory := func(string) telemetryReporter {
		return telemetryReporterFunc(func(event telemetryPayload) { events = append(events, event) })
	}
	invoke := func(args ...string) string {
		t.Helper()
		var stdout, stderr bytes.Buffer
		if err := run(t.Context(), args, &stdout, &stderr, factory); err != nil {
			t.Fatalf("tnl %v: %v (%s)", args, err, stderr.String())
		}
		return stdout.String()
	}
	if result := invoke("telemetry", "status"); !strings.Contains(result, "usage telemetry  on") ||
		strings.Contains(result, "demo telemetry") {
		t.Fatalf("initial status output = %q", result)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("status created client state: %v", err)
	}
	if result := invoke("telemetry", "off"); !strings.Contains(result, "usage telemetry  off") {
		t.Fatalf("off output = %q", result)
	}
	if result := invoke("telemetry", "status"); !strings.Contains(result, "usage telemetry  off") {
		t.Fatalf("status output = %q", result)
	}
	invoke("version")
	if len(events) != 0 {
		t.Fatalf("telemetry commands or disabled client sent events: %#v", events)
	}
	if result := invoke("telemetry", "on"); !strings.Contains(result, "usage telemetry  on") {
		t.Fatalf("on output = %q", result)
	}
	invoke("--no-telemetry", "version")
	t.Setenv("TNL_NO_TELEMETRY", "true")
	invoke("version")
	if len(events) != 0 {
		t.Fatalf("disabled one-run overrides sent events: %#v", events)
	}
	t.Setenv("TNL_NO_TELEMETRY", "false")
	invoke("version")
	if len(events) != 0 {
		t.Fatalf("version sent telemetry: %#v", events)
	}
}
