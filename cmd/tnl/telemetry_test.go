package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"

	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/publisher/demo"
	api "github.com/tnldotdev/tnl/pkg/api/integrations/telemetry/v1"
)

type telemetryReporterFunc func(clienttelemetry.Observation)

func (f telemetryReporterFunc) Report(event clienttelemetry.Observation) { f(event) }

func TestTelemetryCollectorRetriesInvalidStateRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	if err := os.WriteFile(root, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if collector := newTelemetryReporter(t.Context(), root); collector != nil {
		collector.Close(context.Background())
		t.Fatal("opened telemetry under invalid state root")
	}
	if err := os.Remove(root); err != nil {
		t.Fatal(err)
	}
	collector := newTelemetryReporter(t.Context(), root)
	if collector == nil {
		t.Fatal("previous open failure prevented creating telemetry state")
	}
	collector.Close(context.Background())
}

func TestOptionalTelemetryReporterDoesNotWrapDisabledInvocation(t *testing.T) {
	var disabled *telemetryInvocation
	reporter := optionalTelemetryReporter([]telemetryReporter{disabled})
	if reporter != nil {
		t.Fatalf("disabled telemetry reporter = %#v", reporter)
	}
	observed := false
	observer := withTelemetryObserver(reporter, defaultServerURL, nil, func(publisher.Event) error {
		observed = true
		return nil
	})
	if err := observer(publisher.Event{Type: publisher.EventReady}); err != nil || !observed {
		t.Fatalf("ready event was not forwarded: observed=%t, err=%v", observed, err)
	}
}

func TestDemoTelemetryReportsOnlyFirstPingWithoutPageData(t *testing.T) {
	var events []clienttelemetry.Observation
	invocation := newTelemetryInvocation(telemetryReporterFunc(func(event clienttelemetry.Observation) { events = append(events, event) }))
	invocation.SetPublishMode(telemetryPublishDemo)
	invocation.Report(newTelemetryReady(telemetryHosted, ""))
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
	if len(events) != 2 || events[0].Event != clienttelemetry.PublicationReady || events[0].PublishMode != telemetryPublishDemo || events[1].Event != clienttelemetry.DemoFirstPing {
		t.Fatalf("demo observations = %+v", events)
	}
	for _, event := range events {
		if bytes.Contains([]byte(event.ServerKind), []byte("private.example")) || bytes.Contains([]byte(event.Framework), []byte("secret time")) {
			t.Fatal("demo event included page data")
		}
	}
}

type flushingReporter struct {
	observations []clienttelemetry.Observation
	flushes      int
}

func (r *flushingReporter) Report(event clienttelemetry.Observation) {
	r.observations = append(r.observations, event)
}
func (r *flushingReporter) Flush() { r.flushes++ }

func TestTelemetryObserverReportsReadyAndFlushesOnce(t *testing.T) {
	for _, test := range []struct {
		name, serverURL string
		kind            telemetryServerKind
	}{
		{"hosted", defaultServerURL, telemetryHosted},
		{"self hosted", "https://control.example.com", telemetrySelfHosted},
	} {
		t.Run(test.name, func(t *testing.T) {
			reporter := &flushingReporter{}
			invocation := newTelemetryInvocation(reporter)
			invocation.SetPublishMode(telemetryPublishApp)
			var observed []publisher.Event
			observe := withTelemetryObserver(invocation, test.serverURL, nil, func(event publisher.Event) error {
				observed = append(observed, event)
				return nil
			})
			for _, event := range []publisher.Event{{Type: publisher.EventPublicURLAssigned}, {Type: publisher.EventReady}, {Type: publisher.EventReady}} {
				if err := observe(event); err != nil {
					t.Fatal(err)
				}
			}
			if len(observed) != 3 || len(reporter.observations) != 1 || reporter.flushes != 1 || reporter.observations[0].ServerKind != test.kind || reporter.observations[0].PublishMode != telemetryPublishApp {
				t.Fatalf("observer lost ready or flush: observations=%+v flushes=%d", reporter.observations, reporter.flushes)
			}
		})
	}
	want := errors.New("observe failed")
	reported := false
	observe := withTelemetryObserver(telemetryReporterFunc(func(clienttelemetry.Observation) { reported = true }), defaultServerURL, nil, func(publisher.Event) error { return want })
	if err := observe(publisher.Event{Type: publisher.EventReady}); !errors.Is(err, want) || reported {
		t.Fatalf("observer reported readiness after failure: %v, %t", err, reported)
	}
}

func TestTelemetryFramework(t *testing.T) {
	for _, test := range []struct {
		name string
		want telemetryFrameworkName
	}{
		{"", ""}, {"vite", telemetryVite}, {"next", telemetryNext}, {"astro", telemetryOther}, {"private-project-name", telemetryOther},
	} {
		if got := telemetryFramework(test.name); got != test.want {
			t.Errorf("framework %q = %q, want %q", test.name, got, test.want)
		}
	}
}

func TestTelemetryFailureStageIsBounded(t *testing.T) {
	var events []clienttelemetry.Observation
	invocation := newTelemetryInvocation(telemetryReporterFunc(func(event clienttelemetry.Observation) { events = append(events, event) }))
	invocation.failed(telemetryPublish, api.CommandOutcomeActionStart, telemetryCommandStage, diagnostic.Wrap(diagnostic.TargetUnavailable, errors.New("private target URL")))
	if len(events) != 1 || events[0].Event != clienttelemetry.CommandFailed || events[0].FailureStage != telemetryLocalServiceStage || events[0].Command != telemetryPublish || events[0].Action != api.CommandOutcomeActionStart {
		t.Fatalf("failure included the wrong semantic facts: %+v", events)
	}
}

func TestTelemetryReportsConfigurationFailureBeforePublishing(t *testing.T) {
	config := filepath.Join(t.TempDir(), "tnl.json")
	if err := os.WriteFile(config, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TNL_STATE_DIR", filepath.Join(t.TempDir(), "state"))
	var events []clienttelemetry.Observation
	factory := func(string) telemetryReporter {
		return telemetryReporterFunc(func(event clienttelemetry.Observation) { events = append(events, event) })
	}
	if err := run(t.Context(), []string{"--config", config, "publish", "3000"}, io.Discard, io.Discard, factory); err == nil {
		t.Fatal("invalid configuration was accepted")
	}
	if len(events) != 1 || events[0].Event != clienttelemetry.CommandFailed || events[0].FailureStage != telemetrySetupStage {
		t.Fatalf("configuration outcome = %+v", events)
	}
	events = nil
	_ = run(t.Context(), []string{"--no-telemetry", "--config", config, "publish", "3000"}, io.Discard, io.Discard, factory)
	if len(events) != 0 {
		t.Fatalf("disabled telemetry = %+v", events)
	}
}

func TestIntegrationTelemetryIntegrationOutcomesOnce(t *testing.T) {
	var mu sync.Mutex
	var events []clienttelemetry.Observation
	invocation := newTelemetryInvocation(telemetryReporterFunc(func(event clienttelemetry.Observation) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, event)
	}))
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for _, event := range []clienttelemetry.Observation{
				newIntegrationTelemetry("oauth_callback_url_ready", ""),
				newIntegrationTelemetry("oauth_callback_redirected", ""),
				newIntegrationTelemetry("webhook_endpoint_ready", telemetrySelected),
				newIntegrationTelemetry("webhook_delivery_reached_receiver", telemetryFanout),
			} {
				invocation.Report(event)
			}
		})
	}
	workers.Wait()
	if len(events) != 4 {
		t.Fatalf("integration observations = %+v", events)
	}
	want := map[clienttelemetry.EventKind]bool{clienttelemetry.OAuthReady: true, clienttelemetry.OAuthRedirected: true, clienttelemetry.WebhookReady: true, clienttelemetry.WebhookReached: true}
	for _, event := range events {
		if !want[event.Event] {
			t.Fatalf("duplicate or unexpected integration observation: %+v", event)
		}
		delete(want, event.Event)
	}
	if len(want) != 0 {
		t.Fatalf("missing integration observations: %+v", want)
	}
}
