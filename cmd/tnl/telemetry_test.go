package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/tnldotdev/tnl/internal/demo"
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

func TestOptionalTelemetryReporterDoesNotWrapDisabledInvocation(t *testing.T) {
	var disabled *telemetryInvocation
	reporter := optionalTelemetryReporter([]telemetryReporter{disabled})
	if reporter != nil {
		t.Fatalf("disabled telemetry reporter = %#v", reporter)
	}
	observed := false
	observer := withTelemetryObserver(reporter, telemetryDev, defaultServerURL, nil, func(publisher.Event) error {
		observed = true
		return nil
	})
	if err := observer(publisher.Event{Type: publisher.EventReady}); err != nil || !observed {
		t.Fatalf("ready event was not forwarded: observed=%t, err=%v", observed, err)
	}
}

func TestDemoTelemetryUsesBoundedModesAndReportsOnlyFirstPing(t *testing.T) {
	var events []telemetryPayload
	invocation, err := newTelemetryInvocation(telemetryReporterFunc(func(event telemetryPayload) {
		events = append(events, event)
	}))
	if err != nil {
		t.Fatal(err)
	}
	invocation.SetPublishMode(telemetryPublishDemo)
	invocation.Report(newTelemetryStarted(telemetryPublish))
	invocation.SetPublishMode(telemetryPublishDemoGuest)
	invocation.Report(newTelemetryReady(telemetryPublish, telemetryHosted, ""))
	output, err := newPublishOutput(publishOutputHuman, "tnl publish", io.Discard, io.Discard, nil)
	if err != nil {
		t.Fatal(err)
	}
	ping := demoPingHandler(output, invocation)
	for count := uint64(1); count <= 2; count++ {
		if err := ping(demo.State{PublicURL: "https://private.example", RequestCount: count, GeneratedAt: "secret time"}); err != nil {
			t.Fatal(err)
		}
	}
	if len(events) != 3 || events[0].PublishMode != telemetryPublishDemo ||
		events[1].PublishMode != telemetryPublishDemoGuest ||
		events[2].Event != telemetryDemoPingReceived || events[2].PublishMode != telemetryPublishDemoGuest {
		t.Fatalf("demo telemetry = %+v", events)
	}
	for _, event := range events {
		wire, err := json.Marshal(event)
		if err != nil || bytes.Contains(wire, []byte("private.example")) || bytes.Contains(wire, []byte("secret time")) {
			t.Fatalf("demo telemetry leaked page data: %q, %v", wire, err)
		}
	}
}

func TestTelemetryObserverReportsReadyOnce(t *testing.T) {
	for _, test := range []struct {
		name       string
		serverURL  string
		serverKind telemetryServerKind
	}{
		{name: "hosted", serverURL: defaultServerURL, serverKind: telemetryHosted},
		{name: "self hosted", serverURL: "https://control.example.com", serverKind: telemetrySelfHosted},
	} {
		t.Run(test.name, func(t *testing.T) {
			var payloads []telemetryPayload
			var events []publisher.Event
			observe := withTelemetryObserver(
				telemetryReporterFunc(func(payload telemetryPayload) {
					payloads = append(payloads, payload)
				}),
				telemetryPublish,
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
			if len(payloads) != 1 || payloads[0].Event != telemetryPublishRunStarted ||
				payloads[0].Command != telemetryPublish || payloads[0].ServerKind != test.serverKind {
				t.Fatalf("telemetry payloads = %#v", payloads)
			}
		})
	}

	wantErr := errors.New("observe failed")
	reported := false
	observe := withTelemetryObserver(
		telemetryReporterFunc(func(telemetryPayload) { reported = true }),
		telemetryPublish,
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
		want      telemetryFrameworkName
	}{
		{framework: "", want: ""},
		{framework: "vite", want: telemetryVite},
		{framework: "next", want: telemetryNext},
		{framework: "astro", want: telemetryOther},
		{framework: "private-project-name", want: telemetryOther},
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
	invocation.Report(newTelemetryStarted(telemetryDev))
	invocation.failed(telemetryDev, telemetryCommandStage, diagnostic.Wrap(diagnostic.TargetUnavailable, errors.New("private target URL")))
	if len(events) != 2 || events[0].InvocationID != invocation.id || events[1].InvocationID != invocation.id ||
		events[1].FailureStage != telemetryLocalServiceStage || events[1].DiagnosticCode != diagnostic.TargetUnavailable {
		t.Fatalf("invocation events = %#v", events)
	}
	if events[1].Framework != "" || events[1].ServerKind != "" {
		t.Fatalf("failure included a URL or target: %#v", events[1])
	}
	invocation.Report(newTelemetryReady(telemetryDev, telemetryHosted, telemetryVite))
	invocation.failed(telemetryDev, telemetryCommandStage, io.EOF)
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

func TestTypedTelemetryKeepsWireValues(t *testing.T) {
	ready := newTelemetryReady(telemetryDev, telemetryHosted, telemetryVite)
	ready.InstallationID = "installation_0123456789abcdef0123456789abcdef"
	ready.InvocationID = "invocation_0123456789abcdef0123456789abcdef"
	body, err := json.Marshal(ready)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatal(err)
	}
	for field, want := range map[string]string{
		"event": "publish_run_started", "command": "dev", "server_kind": "hosted", "framework": "vite",
	} {
		if wire[field] != want {
			t.Errorf("%s = %v, want %q", field, wire[field], want)
		}
	}
	if _, ok := wire["failure_stage"]; ok {
		t.Fatal("ready report included failure stage")
	}
}
