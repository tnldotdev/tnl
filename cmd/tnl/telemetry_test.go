package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	api "github.com/tnldotdev/tnl/pkg/api/integrations/telemetry/v1"
)

type telemetryTransport func(*http.Request) (*http.Response, error)

func (f telemetryTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type recordingTelemetry struct {
	t          *testing.T
	collectors []*clienttelemetry.Collector
	mu         sync.Mutex
	payloads   []api.Event
}

func recordTelemetry(t *testing.T) *recordingTelemetry {
	r := &recordingTelemetry{t: t}
	t.Cleanup(func() { r.events() })
	return r
}

func (r *recordingTelemetry) factory(config clienttelemetry.Config) *clienttelemetry.Collector {
	r.t.Helper()
	state, err := clientstate.OpenWithOptions(r.t.Context(), config.Root, clientstate.OpenOptions{Protection: config.Protection})
	if err != nil {
		r.t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		r.t.Fatal(err)
	}
	config.Client = &http.Client{Transport: telemetryTransport(func(request *http.Request) (*http.Response, error) {
		var batch api.Batch
		if err := json.NewDecoder(request.Body).Decode(&batch); err != nil {
			r.t.Error(err)
		}
		r.mu.Lock()
		for _, collected := range batch.Events {
			r.payloads = append(r.payloads, collected.Event)
		}
		r.mu.Unlock()
		return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody}, nil
	})}
	c, err := clienttelemetry.New(context.WithoutCancel(r.t.Context()), config)
	if err != nil {
		r.t.Fatal(err)
	}
	r.collectors = append(r.collectors, c)
	return c
}

func (r *recordingTelemetry) events() []api.Event {
	for _, c := range r.collectors {
		closeTelemetry(c)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]api.Event(nil), r.payloads...)
}

func diagnosticError() error {
	return diagnostic.Wrap(diagnostic.AuthenticationRequired, errors.New("private target URL"))
}

func TestTelemetryCommandOutcomeIsSelfContained(t *testing.T) {
	payload := commandOutcome(api.CommandOutcomeCommandLogin, "show", api.Command, diagnosticError())
	if payload.FailureStage == nil || *payload.FailureStage != api.Authentication || payload.Action == nil || *payload.Action != "show" {
		t.Fatalf("outcome=%+v", payload)
	}
	data, _ := json.Marshal(clienttelemetry.Command(payload))
	if api.ValidateEvent(data) != nil || bytes.Contains(data, []byte("private target")) {
		t.Fatalf("invalid/private event %s", data)
	}
}

func TestTelemetryCancellationDoesNotHideCleanupFailure(t *testing.T) {
	for _, test := range []struct {
		err     error
		outcome api.Outcome
	}{
		{context.Canceled, api.Canceled}, {errors.Join(context.Canceled, errors.New("cleanup failed")), api.Failed},
	} {
		payload := commandOutcome("publish", "", api.Command, test.err)
		if payload.Outcome != test.outcome {
			t.Fatalf("%v: outcome=%s", test.err, payload.Outcome)
		}
	}
}

func TestTelemetryReportsConfigurationFailureBeforePublishing(t *testing.T) {
	config := filepath.Join(t.TempDir(), "tnl.json")
	if err := os.WriteFile(config, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TNL_STATE_DIR", filepath.Join(t.TempDir(), "state"))
	r := recordTelemetry(t)
	if err := run(t.Context(), []string{"--config", config, "publish", "3000"}, io.Discard, io.Discard, r.factory); err == nil {
		t.Fatal("invalid config accepted")
	}
	events := r.events()
	if len(events) != 1 {
		t.Fatalf("events=%d", len(events))
	}
	event, _ := events[0].AsCommandEvent()
	if event.Payload.Outcome != api.Failed || event.Payload.FailureStage == nil || *event.Payload.FailureStage != api.Setup {
		t.Fatalf("event=%+v", event)
	}
	_ = run(t.Context(), []string{"--no-telemetry", "--config", config, "publish", "3000"}, io.Discard, io.Discard, r.factory)
	if len(r.events()) != 1 {
		t.Fatal("disabled telemetry collected")
	}
}
