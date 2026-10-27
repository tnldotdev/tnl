package telemetry

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	api "github.com/tnldotdev/tnl/pkg/api/integrations/telemetry/v1"
)

func TestCollectorRetriesSameEventAndStopsAfterPreferenceChange(t *testing.T) {
	var mu sync.Mutex
	var batches [][]byte
	status := http.StatusServiceUnavailable
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		batches = append(batches, body)
		code := status
		mu.Unlock()
		w.WriteHeader(code)
	}))
	defer server.Close()
	root := filepath.Join(t.TempDir(), "state")
	metadata := api.Client{Version: "v1-test", Os: api.ClientOsLinux, Arch: api.ClientArchArm64}
	c, err := New(t.Context(), Config{Root: root, Endpoint: server.URL, Metadata: &metadata, FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(context.Background())
	state, err := clientstate.Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	c.Report(Observation{Event: CommandFailed, Command: api.CommandOutcomeCommandPublish, FailureStage: api.Setup})
	flush := func() {
		t.Helper()
		ack := make(chan struct{})
		select {
		case c.flush <- ack:
		case <-time.After(3 * time.Second):
			t.Fatal("collector stopped accepting flushes")
		}
		select {
		case <-ack:
		case <-time.After(3 * time.Second):
			t.Fatal("collector did not join flush")
		}
	}
	flush()
	flush()
	mu.Lock()
	if len(batches) != 2 || string(batches[0]) != string(batches[1]) || api.ValidateBatch(batches[0]) != nil {
		t.Fatalf("failed upload changed event ID or wire batch: %q", batches)
	}
	mu.Unlock()
	if err := state.SetTelemetryEnabled(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	c.Report(Observation{Event: DemoFirstPing})
	flush()
	mu.Lock()
	count := len(batches)
	mu.Unlock()
	if count != 2 {
		t.Fatal("opted-out collector uploaded another batch")
	}
	if err := state.SetTelemetryEnabled(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	// even if the preference watcher has not run, the queue's epoch fence
	// prevents a writer with old authority from repopulating this state.
	flush()
	items, err := state.PendingTelemetryEvents(t.Context(), 25)
	if err != nil || len(items) != 0 {
		t.Fatalf("disabled-period event survived re-enable: %+v %v", items, err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for c.preference.Load().Epoch < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	status = http.StatusNoContent
	mu.Unlock()
	c.Report(Observation{Event: DemoFirstPing})
	flush()
	mu.Lock()
	defer mu.Unlock()
	if len(batches) != 3 {
		t.Fatalf("re-enabled collector uploaded %d batches, want 3", len(batches))
	}
	var batch api.Batch
	if err := json.Unmarshal(batches[2], &batch); err != nil || len(batch.Events) != 1 {
		t.Fatalf("re-enabled batch: %s %v", batches[2], err)
	}
}

func TestCollectorOptOutCancelsInflightDelivery(t *testing.T) {
	entered := make(chan struct{}, 1)
	canceled := make(chan struct{}, 1)
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		entered <- struct{}{}
		<-r.Context().Done()
		canceled <- struct{}{}
		return nil, r.Context().Err()
	})}
	root := filepath.Join(t.TempDir(), "state")
	c, err := New(t.Context(), Config{Root: root, Endpoint: "https://tnl.dev/api/telemetry", Client: client, FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(context.Background())
	state, err := clientstate.Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	c.Report(Observation{Event: DemoFirstPing})
	c.Flush()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("collector did not start delivery")
	}
	if err := state.SetTelemetryEnabled(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	select {
	case <-canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("persistent opt-out did not cancel delivery")
	}
	items, err := state.PendingTelemetryEvents(t.Context(), 25)
	if err != nil || len(items) != 0 {
		t.Fatalf("opt-out kept pending observations: %+v %v", items, err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
