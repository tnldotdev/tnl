package tnl

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
	"github.com/tnldotdev/tnl/internal/publisher/identity/publishingtest"
	"github.com/tnldotdev/tnl/internal/testutil"
	api "github.com/tnldotdev/tnl/pkg/api/integrations/telemetry/v1"
)

type sdkTelemetryTransport struct {
	next http.RoundTripper
	mu   sync.Mutex
	data [][]byte
}

func (r *sdkTelemetryTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.String() != clienttelemetry.ReceiverURL {
		return r.next.RoundTrip(request)
	}
	data, err := io.ReadAll(io.LimitReader(request.Body, api.MaximumBatchBytes+1))
	if err != nil {
		return nil, err
	}
	if err := api.ValidateBatch(data); err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.data = append(r.data, data)
	r.mu.Unlock()
	return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody}, nil
}

func (r *sdkTelemetryTransport) connections(t *testing.T, private ...string) int64 {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	var count int64
	seen := make(map[[2]string][]byte)
	for _, data := range r.data {
		for _, value := range private {
			if value != "" && strings.Contains(string(data), value) {
				t.Error("SDK telemetry included private publication context")
			}
		}
		var batch api.Batch
		if err := json.Unmarshal(data, &batch); err != nil {
			t.Fatal(err)
		}
		for _, item := range batch.Events {
			if event, err := item.Event.AsTransportEvent(); err == nil && event.Name == "transport.report" && event.Payload.Role == api.TransportReportRolePublisher {
				// delivery can retry an accepted event. match the receiver's
				// installation/event key, without hiding changed observations.
				key := [2]string{batch.InstallationId, event.EventId}
				encoded, err := json.Marshal(item)
				if err != nil {
					t.Fatal(err)
				}
				if previous, found := seen[key]; found {
					if !bytes.Equal(previous, encoded) {
						t.Fatal("SDK telemetry retry changed its collected event")
					}
					continue
				}
				seen[key] = encoded
				for _, measurement := range event.Payload.Measurements {
					if measurement.Operation == api.RelayConnect && measurement.Outcome == api.Succeeded {
						count += measurement.Count
					}
				}
			}
		}
	}
	return count
}

func (r *sdkTelemetryTransport) batches() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.data)
}

func TestSDKTelemetryReceiverCountsDistinctObservations(t *testing.T) {
	recorded := &sdkTelemetryTransport{}
	deliver := func(installation, id string) {
		t.Helper()
		var event api.Event
		if err := event.FromTransportEvent(api.TransportEvent{
			EventId: id, EventVersion: 1, Name: "transport.report",
			Payload: api.TransportReport{Role: api.TransportReportRolePublisher, Measurements: []api.Measurement{{
				Operation: api.RelayConnect, Path: api.Wss, Outcome: api.Succeeded, Duration: api.Lt1s, Count: 2,
			}}},
		}); err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(api.Batch{SchemaVersion: 1, InstallationId: installation, Events: []api.CollectedEvent{{
			Client: api.Client{Version: "test", Os: "linux", Arch: "amd64"}, Event: event,
		}}})
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, clienttelemetry.ReceiverURL, bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		response, err := recorded.RoundTrip(request)
		if err != nil {
			t.Fatal(err)
		}
		if err := response.Body.Close(); err != nil {
			t.Fatal(err)
		}
	}
	const first = "inst_AAAAAAAAAAAAAAAAAAAAAA"
	const second = "inst_BBBBBBBBBBBBBBBBBBBBBB"
	const original = "tev_AAAAAAAAAAAAAAAAAAAAAA"
	const independent = "tev_BBBBBBBBBBBBBBBBBBBBBB"
	deliver(first, original)
	deliver(first, original)
	if got := recorded.connections(t); got != 2 {
		t.Errorf("retry counted as new relay observations: got %d, want 2", got)
	}
	deliver(first, independent)
	if got := recorded.connections(t); got != 4 {
		t.Errorf("independent event lost: got %d, want 4", got)
	}
	deliver(second, original)
	if got := recorded.connections(t); got != 6 {
		t.Errorf("independent installation lost: got %d, want 6", got)
	}
	if recorded.batches() != 4 {
		t.Fatal("receiver hid a delivery attempt")
	}
}

func TestOpenDefaultsTelemetryOnAcrossPublicationRestarts(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	t.Setenv("TNL_NO_TELEMETRY", "")
	if err := os.Unsetenv("TNL_NO_TELEMETRY"); err != nil {
		t.Fatal(err)
	}
	fixture := publishingtest.New(t, testutil.PublishingHooks{})
	options := preparedSDKOptions(t, fixture)
	original := http.DefaultTransport
	recorded := &sdkTelemetryTransport{next: original}
	http.DefaultTransport = recorded
	defer func() { http.DefaultTransport = original }()
	for attempt := range 2 {
		tunnel, err := Open(t.Context(), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}), options)
		if err != nil {
			t.Fatal(err)
		}
		if err := tunnel.Close(); err != nil {
			t.Fatal(err)
		}
		if got := recorded.connections(t, fixture.URL, fixture.OwnerToken, options.StateDir, tunnel.URL(), tunnel.Service().Id); got != int64((attempt+1)*2) {
			t.Fatalf("default SDK publication delivered %d relay connection observations, want %d", got, (attempt+1)*2)
		}
	}
}

func TestOpenTelemetryOptOutNeverChangesSiblingOrSavedPreference(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	t.Setenv("TNL_NO_TELEMETRY", "")
	if err := os.Unsetenv("TNL_NO_TELEMETRY"); err != nil {
		t.Fatal(err)
	}
	fixture := publishingtest.New(t, testutil.PublishingHooks{})
	options := preparedSDKOptions(t, fixture)
	original := http.DefaultTransport
	recorded := &sdkTelemetryTransport{next: original}
	http.DefaultTransport = recorded
	defer func() { http.DefaultTransport = original }()
	var publications []*Tunnel
	defer func() {
		for _, tunnel := range publications {
			if err := tunnel.Close(); err != nil {
				t.Error("SDK telemetry publication cleanup", err)
			}
		}
	}()
	open := func(selected Options) *Tunnel {
		t.Helper()
		tunnel, err := Open(t.Context(), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}), selected)
		if err != nil {
			t.Fatal(err)
		}
		publications = append(publications, tunnel)
		return tunnel
	}
	close := func(tunnel *Tunnel) {
		t.Helper()
		if err := tunnel.Close(); err != nil {
			t.Fatal(err)
		}
	}
	expect := func(count int64) {
		t.Helper()
		if got := recorded.connections(t, fixture.URL, fixture.OwnerToken, options.StateDir); got != count {
			t.Fatalf("delivered SDK relay observations = %d, want %d", got, count)
		}
	}
	enabled := open(options)
	disabledOptions := options
	disabledOptions.NoTelemetry = true
	for range 2 {
		disabled := open(disabledOptions)
		if saved, err := clientstate.TelemetryEnabledAt(t.Context(), options.StateDir); err != nil || !saved {
			t.Fatal("per-publication opt-out reset its sibling's saved preference", err)
		}
		close(disabled)
	}
	close(enabled)
	expect(2)
	batches := recorded.batches()
	close(open(disabledOptions))
	if recorded.batches() != batches {
		t.Fatal("option opt-out delivered new SDK telemetry")
	}
	for _, value := range []string{"1", "true"} {
		t.Setenv("TNL_NO_TELEMETRY", value)
		close(open(options))
	}
	expect(2)
	if recorded.batches() != batches {
		t.Fatal("environment opt-out delivered new SDK telemetry")
	}
	if err := os.Unsetenv("TNL_NO_TELEMETRY"); err != nil {
		t.Fatal(err)
	}
	close(open(options))
	expect(4)
	state, err := clientstate.OpenWithOptions(t.Context(), options.StateDir, clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	if err := state.SetTelemetryEnabled(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	batches = recorded.batches()
	for range 2 {
		close(open(options))
	}
	expect(4)
	if recorded.batches() != batches {
		t.Fatal("saved opt-out delivered new SDK telemetry after restart")
	}
	if saved, err := clientstate.TelemetryEnabledAt(t.Context(), options.StateDir); err != nil || saved {
		t.Fatal("SDK restart reset its saved opt-out", err)
	}
}
