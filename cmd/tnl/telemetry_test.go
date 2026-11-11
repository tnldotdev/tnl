package main

import (
	"bytes"
	"context"
	"encoding/json"
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

type telemetryReporterFunc func(telemetryPayload)

func (f telemetryReporterFunc) Report(event telemetryPayload) { f(event) }
func (telemetryReporterFunc) Flush()                          {}
func (telemetryReporterFunc) BeginScope(api.TransportReportRole, bool) *clienttelemetry.Scope {
	return nil
}

type recordingTelemetryReporter struct {
	payloads []telemetryPayload
	flushes  int
}

func (r *recordingTelemetryReporter) Report(event telemetryPayload) {
	r.payloads = append(r.payloads, event)
}
func (r *recordingTelemetryReporter) Flush() { r.flushes++ }
func (*recordingTelemetryReporter) BeginScope(api.TransportReportRole, bool) *clienttelemetry.Scope {
	return nil
}

func diagnosticError() error {
	return diagnostic.Wrap(diagnostic.AuthenticationRequired, errors.New("private target URL"))
}

func TestDisabledTelemetryForwardsPublisherEvents(t *testing.T) {
	observed := false
	observer := withTelemetryObserver(nil, telemetryPublish, defaultServerURL, nil, func(publisher.Event) error { observed = true; return nil })
	if err := observer(publisher.Event{Type: publisher.EventReady}); err != nil || !observed {
		t.Fatalf("observed=%t err=%v", observed, err)
	}
}

func TestDemoTelemetryUsesBoundedModesAndReportsOnlyFirstPing(t *testing.T) {
	r := &recordingTelemetryReporter{}
	i := newTelemetryInvocation(r)
	i.SetPublishMode(telemetryPublishDemo)
	i.Report(newTelemetryReady(telemetryPublish, telemetryHosted, ""))
	output, err := newPublishOutput(publishOutputHuman, "tnl publish", io.Discard, io.Discard, nil)
	if err != nil {
		t.Fatal(err)
	}
	ping := demoPingHandler(output, i)
	for count := uint64(1); count <= 2; count++ {
		if err := ping(demo.State{PublicURL: "https://private.example", RequestCount: count, GeneratedAt: "secret time"}); err != nil {
			t.Fatal(err)
		}
	}
	if len(r.payloads) != 2 {
		t.Fatalf("events=%d", len(r.payloads))
	}
	ready, _ := r.payloads[0].AsReadyEvent()
	name, _ := r.payloads[1].Discriminator()
	if ready.Payload.PublishMode != api.Demo || name != "demo.first_ping" {
		t.Fatal("lost demo facts")
	}
	for _, event := range r.payloads {
		data, _ := json.Marshal(event)
		if api.ValidateEvent(data) != nil || bytes.Contains(data, []byte("private.example")) || bytes.Contains(data, []byte("secret time")) {
			t.Fatalf("invalid/private event %s", data)
		}
	}
}

func TestTelemetryObserverReportsReadyOnce(t *testing.T) {
	for _, server := range []string{defaultServerURL, "https://control.example.com"} {
		for _, rejected := range []bool{false, true} {
			for _, wrapped := range []bool{false, true} {
				r := &recordingTelemetryReporter{}
				var reporter telemetryReporter = r
				if wrapped {
					reporter = newTelemetryInvocation(r)
				}
				observed := 0
				wantErr := errors.New("observe failed")
				observe := withTelemetryObserver(reporter, telemetryPublish, server, nil, func(publisher.Event) error {
					observed++
					if rejected {
						return wantErr
					}
					return nil
				})
				for range 2 {
					err := observe(publisher.Event{Type: publisher.EventReady})
					if rejected && !errors.Is(err, wantErr) || !rejected && err != nil {
						t.Fatal(err)
					}
				}
				if observed != 2 {
					t.Fatal("did not forward readiness")
				}
				want := 1
				if rejected {
					want = 0
				}
				if len(r.payloads) != want || r.flushes != want {
					t.Fatalf("events=%d flushes=%d want=%d", len(r.payloads), r.flushes, want)
				}
				if want != 0 {
					event, _ := r.payloads[0].AsReadyEvent()
					kind := api.Hosted
					if server != defaultServerURL {
						kind = api.SelfHosted
					}
					if event.Payload.ServerKind != kind {
						t.Fatal("wrong server kind")
					}
				}
			}
		}
	}
}

func TestTelemetryFramework(t *testing.T) {
	for _, test := range []struct {
		framework string
		want      telemetryFrameworkName
	}{{"", ""}, {"vite", telemetryVite}, {"next", telemetryNext}, {"astro", telemetryOther}, {"private-project-name", telemetryOther}} {
		if got := telemetryFramework(test.framework); got != test.want {
			t.Fatalf("%q: %q", test.framework, got)
		}
	}
}

func TestTelemetryCommandOutcomeIsSelfContained(t *testing.T) {
	r := &recordingTelemetryReporter{}
	i := newTelemetryInvocation(r)
	i.action = "show"
	i.finished(telemetryLogin, telemetryCommandStage, diagnosticError())
	event, _ := r.payloads[0].AsCommandEvent()
	if event.Payload.FailureStage == nil || *event.Payload.FailureStage != telemetryAuthenticationStage || event.Payload.Action == nil || *event.Payload.Action != "show" {
		t.Fatalf("outcome=%+v", event.Payload)
	}
	i.Report(newTelemetryReady(telemetryPublish, telemetryHosted, telemetryVite))
	i.finished(telemetryPublish, telemetryCommandStage, io.EOF)
	if len(r.payloads) != 3 {
		t.Fatal("lost failure after readiness")
	}
}

func TestTelemetryCancellationDoesNotHideCleanupFailure(t *testing.T) {
	for _, test := range []struct {
		err     error
		outcome api.Outcome
	}{{context.Canceled, api.Canceled}, {errors.Join(context.Canceled, errors.New("cleanup failed")), api.Failed}} {
		r := &recordingTelemetryReporter{}
		i := newTelemetryInvocation(r)
		i.finished(telemetryPublish, telemetryCommandStage, test.err)
		event, _ := r.payloads[0].AsCommandEvent()
		if event.Payload.Outcome != test.outcome {
			t.Fatalf("%v: outcome=%s", test.err, event.Payload.Outcome)
		}
	}
}

func TestTelemetryReportsConfigurationFailureBeforePublishing(t *testing.T) {
	config := filepath.Join(t.TempDir(), "tnl.json")
	if err := os.WriteFile(config, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TNL_STATE_DIR", filepath.Join(t.TempDir(), "state"))
	var events []telemetryPayload
	factory := func(string) telemetryReporter {
		return telemetryReporterFunc(func(event telemetryPayload) { events = append(events, event) })
	}
	if err := run(t.Context(), []string{"--config", config, "publish", "3000"}, io.Discard, io.Discard, factory); err == nil {
		t.Fatal("invalid config accepted")
	}
	if len(events) != 1 {
		t.Fatalf("events=%d", len(events))
	}
	event, _ := events[0].AsCommandEvent()
	if event.Payload.Outcome != api.Failed || event.Payload.FailureStage == nil || *event.Payload.FailureStage != api.Setup {
		t.Fatalf("event=%+v", event)
	}
	events = nil
	_ = run(t.Context(), []string{"--no-telemetry", "--config", config, "publish", "3000"}, io.Discard, io.Discard, factory)
	if len(events) != 0 {
		t.Fatal("disabled telemetry collected")
	}
}

func TestIntegrationTelemetryIsTypedPrivateAndOncePerInvocation(t *testing.T) {
	var mu sync.Mutex
	var events []telemetryPayload
	i := newTelemetryInvocation(telemetryReporterFunc(func(event telemetryPayload) { mu.Lock(); defer mu.Unlock(); events = append(events, event) }))
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for _, event := range []telemetryPayload{newIntegrationTelemetry(telemetryOAuthReady, ""), newIntegrationTelemetry(telemetryOAuthRedirected, ""), newIntegrationTelemetry(telemetryWebhookReady, telemetrySelected), newIntegrationTelemetry(telemetryWebhookReached, telemetryFanout)} {
				i.Report(event)
			}
		})
	}
	workers.Wait()
	if len(events) != 4 {
		t.Fatalf("events=%d", len(events))
	}
	seen := map[string]bool{}
	for _, event := range events {
		data, _ := json.Marshal(event)
		if api.ValidateEvent(data) != nil || bytes.Contains(data, []byte("secret")) || bytes.Contains(data, []byte("https://")) {
			t.Fatalf("event=%s", data)
		}
		integration, _ := event.AsIntegrationEvent()
		key := string(integration.Payload.Kind) + "/" + string(integration.Payload.Outcome)
		if seen[key] {
			t.Fatal("duplicate integration outcome")
		}
		seen[key] = true
		if integration.Payload.Kind == "oauth" && integration.Payload.Delivery != nil {
			t.Fatal("OAuth included delivery context")
		}
	}
}
