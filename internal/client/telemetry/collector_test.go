package telemetry

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	api "github.com/tnldotdev/tnl/pkg/api/integrations/telemetry/v1"
	"github.com/zalando/go-keyring"
)

func TestMain(m *testing.M) {
	keyring.MockInit()
	os.Exit(m.Run())
}

func TestCollectorRetriesSameEventAndStopsAfterPreferenceChange(t *testing.T) {
	var mu sync.Mutex
	var batches [][]byte
	status := http.StatusServiceUnavailable
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		batches = append(batches, body)
		code := status
		mu.Unlock()
		return &http.Response{StatusCode: code, Body: http.NoBody}, nil
	})}
	root := filepath.Join(t.TempDir(), "state")
	metadata := api.Client{Version: "v1-test", Os: api.ClientOsLinux, Arch: api.ClientArchArm64}
	c, err := New(t.Context(), Config{Root: root, Client: client, Metadata: &metadata, FlushInterval: time.Hour})
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

func TestCollectorKeepsDistinctEventsUntilExplicitFlushAcknowledges(t *testing.T) {
	var mu sync.Mutex
	var bodies [][]byte
	status := http.StatusServiceUnavailable
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if got := request.Header.Get("User-Agent"); got != "tnl" {
			t.Errorf("telemetry User-Agent = %q", got)
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}
		mu.Lock()
		bodies = append(bodies, body)
		code := status
		mu.Unlock()
		return &http.Response{StatusCode: code, Body: io.NopCloser(http.NoBody), Header: make(http.Header)}, nil
	})}
	metadata := api.Client{Version: "captured-version", Os: api.ClientOsLinux, Arch: api.ClientArchArm64}
	c, err := New(t.Context(), Config{Root: filepath.Join(t.TempDir(), "state"), Protection: clientstate.ProtectionFile, Client: client, Metadata: &metadata, FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(context.Background())
	metadata.Version = "later-version"
	c.Report(Observation{Event: CommandCompleted, Command: api.CommandOutcomeCommandPublish})
	c.Report(Observation{Event: PublicationReady, ServerKind: api.Hosted, PublishMode: api.App})
	deadline := time.Now().Add(3 * time.Second)
	for {
		rows, err := c.state.PendingTelemetryEvents(t.Context(), 25)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("collector did not queue both observations")
		}
		time.Sleep(time.Millisecond)
	}
	mu.Lock()
	sent := len(bodies)
	mu.Unlock()
	if sent != 0 {
		t.Fatal("collector sent before the explicit flush boundary")
	}
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
	rows, err := c.state.PendingTelemetryEvents(t.Context(), 25)
	if err != nil || len(rows) != 2 || rows[0].ID == rows[1].ID {
		t.Fatalf("failed upload lost distinct events: %+v %v", rows, err)
	}
	mu.Lock()
	if len(bodies) != 1 {
		mu.Unlock()
		t.Fatalf("explicit flush sent %d batches, want 1", len(bodies))
	}
	var batch api.Batch
	decodeErr := json.Unmarshal(bodies[0], &batch)
	validErr := api.ValidateBatch(bodies[0])
	status = http.StatusNoContent
	mu.Unlock()
	if decodeErr != nil || validErr != nil || len(batch.Events) != 2 || batch.Client.Version != "captured-version" {
		t.Fatalf("batch lost observations or captured metadata: %+v %v %v", batch, decodeErr, validErr)
	}
	flush()
	rows, err = c.state.PendingTelemetryEvents(t.Context(), 25)
	if err != nil || len(rows) != 0 {
		t.Fatalf("acknowledged events remained queued: %+v %v", rows, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 2 || string(bodies[0]) != string(bodies[1]) {
		t.Fatalf("retry changed event IDs or captured metadata: %q", bodies)
	}
}

func TestObservationsKeepOnlySelfContainedBoundedWireFacts(t *testing.T) {
	for _, test := range []struct {
		observation Observation
		name        string
		payload     string
	}{
		{Observation{Event: PublicationReady, ServerKind: api.Hosted, PublishMode: api.Demo, Framework: api.PublicationReadyFrameworkVite, FailureStage: api.Setup}, "tunnel.ready", `{"server_kind":"hosted","publish_mode":"demo","framework":"vite"}`},
		{Observation{Event: DemoFirstPing}, "demo.first_ping", `{}`},
		{Observation{Event: OAuthReady, Delivery: api.Fanout}, "integration.outcome", `{"kind":"oauth","outcome":"ready"}`},
		{Observation{Event: OAuthRedirected}, "integration.outcome", `{"kind":"oauth","outcome":"redirected"}`},
		{Observation{Event: WebhookReady, Delivery: api.Selected}, "integration.outcome", `{"kind":"webhook","outcome":"ready","delivery":"selected"}`},
		{Observation{Event: WebhookReached, Delivery: api.Fanout}, "integration.outcome", `{"kind":"webhook","outcome":"reached_receiver","delivery":"fanout"}`},
		{Observation{Event: CommandCompleted, Command: api.CommandOutcomeCommandPublish, FailureStage: api.Setup}, "command.outcome", `{"command":"publish","outcome":"completed"}`},
		{Observation{Event: CommandCanceled, Command: api.CommandOutcomeCommandPublish}, "command.outcome", `{"command":"publish","outcome":"canceled"}`},
		{Observation{Event: CommandFailed, Command: api.CommandOutcomeCommandAuth, FailureStage: api.Authentication}, "command.outcome", `{"command":"auth","outcome":"failed","failure_stage":"authentication"}`},
	} {
		t.Run(test.name+"/"+test.payload, func(t *testing.T) {
			const id = "tev_0123456789abcdefghijkl"
			event, err := test.observation.wire(id)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(event)
			if err != nil || api.ValidateEvent(encoded) != nil {
				t.Fatalf("invalid bounded observation: %s %v", encoded, err)
			}
			var actual, expected map[string]any
			want := `{"event_id":"` + id + `","event_version":1,"name":"` + test.name + `","payload":` + test.payload + `}`
			if err := json.Unmarshal(encoded, &actual); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(want), &expected); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(actual, expected) {
				t.Fatalf("observation gained context or changed wire facts: %s want %s", encoded, want)
			}
		})
	}
}
