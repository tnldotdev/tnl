package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"slices"
	"testing"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/publisher"
)

type telemetryTransportFunc func(*http.Request) (*http.Response, error)

func (f telemetryTransportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func preparedTelemetryReporter(t *testing.T) (string, *asyncTelemetryReporter) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "state")
	state, err := clientstate.Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	return root, newTelemetryReporter(root)
}

func TestTelemetryBatchKeepsEventsUntilAcknowledged(t *testing.T) {
	root, reporter := preparedTelemetryReporter(t)
	var received []byte
	status := http.StatusServiceUnavailable
	reporter.client.Transport = telemetryTransportFunc(func(request *http.Request) (*http.Response, error) {
		if got := request.Header.Get("User-Agent"); got != "tnl" {
			t.Errorf("telemetry User-Agent = %q", got)
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		received = body
		return &http.Response{StatusCode: status, Body: io.NopCloser(&emptyReader{}), Header: make(http.Header)}, nil
	})
	reporter.Report(newTelemetryStarted(telemetryDev))
	reporter.Report(newTelemetryReady(telemetryDev, telemetryHosted, telemetryVite))
	reporter.Wait(context.Background())
	if received != nil {
		t.Fatal("telemetry sent before the command boundary")
	}
	reporter.flush(context.Background())
	var batch struct {
		SchemaVersion int `json:"schema_version"`
		Events        []struct {
			EventID string `json:"event_id"`
			Name    string `json:"name"`
		} `json:"events"`
	}
	if err := json.Unmarshal(received, &batch); err != nil || batch.SchemaVersion != 1 || len(batch.Events) != 2 || batch.Events[0].EventID == batch.Events[1].EventID {
		t.Fatalf("batch = %+v, %v", batch, err)
	}
	state, err := clientstate.Open(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	items, err := state.PendingTelemetryEvents(context.Background(), 25)
	if err != nil || len(items) != 2 {
		t.Fatalf("pending after failure = %+v, %v", items, err)
	}
	_ = state.Close()
	status = http.StatusNoContent
	reporter.flush(context.Background())
	state, err = clientstate.Open(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	items, err = state.PendingTelemetryEvents(context.Background(), 25)
	if err != nil || len(items) != 0 {
		t.Fatalf("pending after success = %+v, %v", items, err)
	}
}

func TestReadyFlushesStartedAndReadyTogether(t *testing.T) {
	_, reporter := preparedTelemetryReporter(t)
	var received []byte
	reporter.client.Transport = telemetryTransportFunc(func(request *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		received = body
		return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(&emptyReader{}), Header: make(http.Header)}, nil
	})
	invocation, err := newTelemetryInvocation(reporter)
	if err != nil {
		t.Fatal(err)
	}
	invocation.Report(newTelemetryStarted(telemetryDev))
	observe := withTelemetryObserver(invocation, telemetryDev, defaultServerURL, nil, nil)
	if err := observe(publisher.Event{Type: publisher.EventReady}); err != nil {
		t.Fatal(err)
	}
	reporter.Wait(context.Background())
	var batch struct {
		Events []struct {
			Name string `json:"name"`
		} `json:"events"`
	}
	if err := json.Unmarshal(received, &batch); err != nil || len(batch.Events) != 2 ||
		batch.Events[0].Name != "command.started" || batch.Events[1].Name != "tunnel.ready" {
		t.Fatalf("ready batch = %+v, %v", batch, err)
	}
}

func TestTypedFailureEventKeepsBoundedFields(t *testing.T) {
	payload := newTelemetryBase(telemetryLogin)
	payload.Event = telemetryCommandFailed
	payload.InvocationID = "ivk_0123456789abcdefghijkl"
	payload.FailureStage = telemetryAuthenticationStage
	payload.DiagnosticCode = diagnostic.AuthenticationRequired
	event := payload.wireEvent("tev_0123456789abcdefghijkl")
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Name    string `json:"name"`
		Payload struct {
			Command        string `json:"command"`
			FailureStage   string `json:"failure_stage"`
			DiagnosticCode string `json:"diagnostic_code"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Name != "command.failed" || decoded.Payload.Command != "login" ||
		decoded.Payload.FailureStage != "authentication" || decoded.Payload.DiagnosticCode != "TNL_AUTHENTICATION_REQUIRED" {
		t.Fatalf("failure wire event = %s", encoded)
	}
}

func TestProviderTelemetryFlushesMultipleBoundedBatches(t *testing.T) {
	root, reporter := preparedTelemetryReporter(t)
	var sizes []int
	reporter.client.Transport = telemetryTransportFunc(func(request *http.Request) (*http.Response, error) {
		var batch struct {
			Events []json.RawMessage `json:"events"`
		}
		if err := json.NewDecoder(request.Body).Decode(&batch); err != nil {
			t.Error(err)
		}
		sizes = append(sizes, len(batch.Events))
		return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(&emptyReader{}), Header: make(http.Header)}, nil
	})
	for range 53 {
		reporter.Report(newProviderTelemetry(telemetryProviderConfigured, "stripe"))
	}
	reporter.flush(context.Background())
	if !slices.Equal(sizes, []int{25, 25, 3}) {
		t.Fatalf("telemetry batches = %v", sizes)
	}
	state, err := clientstate.Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	remaining, err := state.PendingTelemetryEvents(t.Context(), 25)
	if err != nil || len(remaining) != 0 {
		t.Fatalf("unsent provider events = %d, %v", len(remaining), err)
	}
}

func TestTelemetryOptOutDoesNotQueueProviderNames(t *testing.T) {
	root, reporter := preparedTelemetryReporter(t)
	state, err := clientstate.Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.SetTelemetryEnabled(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	_ = state.Close()
	reporter.Report(newProviderTelemetry(telemetryProviderConfigured, "stripe"))
	state, err = clientstate.Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	remaining, err := state.PendingTelemetryEvents(t.Context(), 25)
	if err != nil || len(remaining) != 0 {
		t.Fatalf("disabled telemetry queued %d events: %v", len(remaining), err)
	}
}

type emptyReader struct{}

func (*emptyReader) Read([]byte) (int, error) { return 0, io.EOF }
