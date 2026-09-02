package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/tnldotdev/tnl/internal/publisher"
)

func TestTelemetryInstallationIDRetries(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	if err := os.WriteFile(root, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	reporter := newTelemetryReporter(root)
	if id, err := reporter.installationID(t.Context()); err == nil {
		t.Fatalf("installation ID = %q after invalid state root", id)
	}
	if err := os.Remove(root); err != nil {
		t.Fatal(err)
	}
	id, err := reporter.installationID(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	cached, err := reporter.installationID(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if id == "" || cached != id {
		t.Fatalf("installation IDs = %q, %q", id, cached)
	}
}

func TestTelemetryObserverReportsReadyOnce(t *testing.T) {
	for _, test := range []struct {
		name       string
		serverURL  string
		serverKind string
	}{
		{name: "hosted", serverURL: defaultServerURL, serverKind: "hosted"},
		{name: "self hosted", serverURL: "https://control.example.com", serverKind: "self_hosted"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var payloads []telemetryPayload
			var events []publisher.Event
			observe := withTelemetryObserver(
				telemetryReporterFunc(func(payload telemetryPayload) {
					payloads = append(payloads, payload)
				}),
				"publish",
				test.serverURL,
				func(event publisher.Event) error {
					events = append(events, event)
					return nil
				},
			)
			for _, event := range []publisher.Event{
				{Type: publisher.EventRoute},
				{Type: publisher.EventReady},
				{Type: publisher.EventReady},
			} {
				if err := observe(event); err != nil {
					t.Fatal(err)
				}
			}
			if len(events) != 3 {
				t.Fatalf("forwarded events = %d, want 3", len(events))
			}
			if len(payloads) != 1 || payloads[0].Event != "route_started" ||
				payloads[0].Command != "publish" || payloads[0].ServerKind != test.serverKind {
				t.Fatalf("telemetry payloads = %#v", payloads)
			}
		})
	}

	wantErr := errors.New("observe failed")
	reported := false
	observe := withTelemetryObserver(
		telemetryReporterFunc(func(telemetryPayload) { reported = true }),
		"publish",
		defaultServerURL,
		func(publisher.Event) error { return wantErr },
	)
	if err := observe(publisher.Event{Type: publisher.EventReady}); !errors.Is(err, wantErr) {
		t.Fatalf("observer error = %v, want %v", err, wantErr)
	}
	if reported {
		t.Fatal("reported readiness after wrapped observer failed")
	}
}
