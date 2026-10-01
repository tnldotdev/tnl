package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/publisher"
)

type telemetryReporterFunc func(telemetryPayload)

func (f telemetryReporterFunc) Report(payload telemetryPayload) { f(payload) }

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
				nil,
				func(event publisher.Event) error {
					events = append(events, event)
					return nil
				},
			)
			for _, event := range []publisher.Event{
				{Type: publisher.EventPublicURLAssigned},
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
			if len(payloads) != 1 || payloads[0].Event != "publish_run_started" ||
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
		nil,
		func(publisher.Event) error { return wantErr },
	)
	if err := observe(publisher.Event{Type: publisher.EventReady}); !errors.Is(err, wantErr) {
		t.Fatalf("observer error = %v, want %v", err, wantErr)
	}
	if reported {
		t.Fatal("reported readiness after wrapped observer failed")
	}
}

func TestTelemetryFramework(t *testing.T) {
	for _, test := range []struct {
		framework string
		want      string
	}{
		{framework: "", want: ""},
		{framework: "vite", want: "vite"},
		{framework: "next", want: "next"},
		{framework: "astro", want: "other"},
		{framework: "private-project-name", want: "other"},
	} {
		if got := telemetryFramework(test.framework); got != test.want {
			t.Errorf("telemetryFramework(%q) = %q, want %q", test.framework, got, test.want)
		}
	}
}

func TestTelemetryInvocationEmitsBoundedFailureOnceBeforeReady(t *testing.T) {
	var events []telemetryPayload
	invocation, err := newTelemetryInvocation(telemetryReporterFunc(func(event telemetryPayload) {
		events = append(events, event)
	}))
	if err != nil {
		t.Fatal(err)
	}
	invocation.Report(newTelemetryPayload("command_started", "dev", "", ""))
	invocation.failed("dev", "command", diagnostic.Wrap(diagnostic.TargetUnavailable, errors.New("private target URL")))
	if len(events) != 2 || events[0].InvocationID != invocation.id || events[1].InvocationID != invocation.id ||
		events[1].FailureStage != "local_service" || events[1].DiagnosticCode != string(diagnostic.TargetUnavailable) {
		t.Fatalf("invocation events = %#v", events)
	}
	if events[1].Framework != "" || events[1].ServerKind != "" {
		t.Fatalf("failure included a URL or target: %#v", events[1])
	}
	invocation.Report(newTelemetryPayload("publish_run_started", "dev", "hosted", "vite"))
	invocation.failed("dev", "command", io.EOF)
	if len(events) != 3 {
		t.Fatalf("failure after readiness = %#v", events)
	}
}

func TestTelemetryReportsConfigurationFailureBeforeStartingDev(t *testing.T) {
	config := filepath.Join(t.TempDir(), "tnl.json")
	if err := os.WriteFile(config, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TNL_STATE_DIR", filepath.Join(t.TempDir(), "state"))
	var events []telemetryPayload
	factory := func(string) telemetryReporter {
		return telemetryReporterFunc(func(event telemetryPayload) { events = append(events, event) })
	}
	if err := run(t.Context(), []string{"--config", config, "dev"}, io.Discard, io.Discard, factory); err == nil {
		t.Fatal("invalid configuration was accepted")
	}
	if len(events) != 2 || events[0].Event != "command_started" || events[1].Event != "command_failed" ||
		events[1].FailureStage != "setup" || events[0].InvocationID != events[1].InvocationID {
		t.Fatalf("configuration telemetry = %#v", events)
	}
	events = nil
	_ = run(t.Context(), []string{"--no-telemetry", "--config", config, "dev"}, io.Discard, io.Discard, factory)
	if len(events) != 0 {
		t.Fatalf("disabled telemetry = %#v", events)
	}
}
