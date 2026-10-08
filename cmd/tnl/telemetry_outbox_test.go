package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/publisher"
)

type telemetryTransportFunc func(*http.Request) (*http.Response, error)

func (f telemetryTransportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestTelemetryBatchKeepsEventsUntilAcknowledged(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	reporter := newTelemetryReporter(root)
	var received []byte
	status := http.StatusServiceUnavailable
	reporter.client.Transport = telemetryTransportFunc(func(request *http.Request) (*http.Response, error) {
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
	root := filepath.Join(t.TempDir(), "state")
	reporter := newTelemetryReporter(root)
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

type emptyReader struct{}

func (*emptyReader) Read([]byte) (int, error) { return 0, io.EOF }
