package telemetry

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	api "github.com/tnldotdev/tnl/pkg/api/integrations/telemetry/v1"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func collectorForTest(t *testing.T, cfg Config) *Collector {
	t.Helper()
	if cfg.Root == "" {
		cfg.Root = filepath.Join(t.TempDir(), "state")
	}
	cfg.Protection, cfg.Interval = clientstate.ProtectionFile, time.Hour
	// the optional collector's short setup budget is not a schema-creation
	// benchmark. prepare native state before starting the collector under -race.
	state, err := clientstate.OpenWithOptions(t.Context(), cfg.Root, clientstate.OpenOptions{Protection: cfg.Protection})
	if err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 503, Body: http.NoBody}, nil
		})}
	}
	c, err := New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, stop := context.WithTimeout(context.Background(), RequestTimeout)
		defer stop()
		c.Close(ctx)
	})
	return c
}

func flushForTest(t *testing.T, c *Collector) {
	t.Helper()
	ack := make(chan struct{})
	select {
	case c.flush <- ack:
	case <-time.After(3 * time.Second):
		t.Fatal("flush did not start")
	}
	select {
	case <-ack:
	case <-time.After(3 * time.Second):
		t.Fatal("flush did not finish")
	}
}

func TestTelemetryRetriesKeepIDsAndCollectedMetadata(t *testing.T) {
	var bodies [][]byte
	status := 503
	client := &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("User-Agent") != "tnl" {
			t.Error("missing user agent")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		bodies = append(bodies, body)
		return &http.Response{StatusCode: status, Body: http.NoBody}, nil
	})}
	metadata := api.Client{Version: "collected-version", Os: "linux", Arch: "arm64", Ci: true}
	c := collectorForTest(t, Config{Client: client, Metadata: &metadata})
	metadata.Version = "later-version"
	c.Report(Command(api.CommandOutcome{Command: "publish", Outcome: api.Succeeded}))
	c.Report(Ready(api.PublicationReady{ServerKind: "hosted", PublishMode: "app"}))
	flushForTest(t, c)
	flushForTest(t, c)
	if len(bodies) != 2 || string(bodies[0]) != string(bodies[1]) || api.ValidateBatch(bodies[0]) != nil {
		t.Fatalf("unstable/invalid batches: %q", bodies)
	}
	var batch api.Batch
	if json.Unmarshal(bodies[0], &batch) != nil || batch.Client.Version != "collected-version" || len(batch.Events) != 2 {
		t.Fatalf("batch: %s", bodies[0])
	}
	first, _ := batch.Events[0].AsCommandEvent()
	second, _ := batch.Events[1].AsReadyEvent()
	if first.EventId == second.EventId {
		t.Fatal("events shared an ID")
	}
	rows, err := c.state.PendingTelemetryEvents(t.Context(), 25)
	if err != nil || len(rows) != 2 {
		t.Fatalf("lost failed upload: %v %v", rows, err)
	}
	status = 204
	flushForTest(t, c)
	rows, err = c.state.PendingTelemetryEvents(t.Context(), 25)
	if err != nil || len(rows) != 0 {
		t.Fatalf("kept acknowledged events: %v %v", rows, err)
	}
}

func TestTelemetryLaterSenderKeepsOriginalMetadata(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	old := api.Client{Version: "old", Os: "linux", Arch: "arm64", Ci: true}
	c := collectorForTest(t, Config{Root: root, Metadata: &old})
	c.Report(Demo())
	flushForTest(t, c)
	c.Close(context.Background())
	var batches []api.Batch
	client := &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		var batch api.Batch
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			t.Error(err)
		}
		batches = append(batches, batch)
		return &http.Response{StatusCode: 204, Body: http.NoBody}, nil
	})}
	current := api.Client{Version: "new", Os: "darwin", Arch: "amd64"}
	next := collectorForTest(t, Config{Root: root, Client: client, Metadata: &current})
	next.Report(Demo())
	flushForTest(t, next)
	flushForTest(t, next)
	if len(batches) != 2 || batches[0].Client != old || batches[1].Client != current {
		t.Fatalf("relabelled queued events: %+v", batches)
	}
}

func TestTelemetryPreferenceFencesRapidOffOnAndScopeCounters(t *testing.T) {
	c := collectorForTest(t, Config{})
	scope := c.BeginScope("publisher", false)
	defer scope.Close()
	scope.Record(api.RelayConnect, api.Quic, api.Succeeded, time.Second)
	old, _ := json.Marshal(Demo())
	if err := c.state.SetTelemetryEnabled(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	if err := c.state.SetTelemetryEnabled(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	// neither a stale in-memory event nor an old scope can refill the cleared queue.
	c.store(queuedEvent{old, 0})
	scope.flush()
	flushForTest(t, c)
	rows, err := c.state.PendingTelemetryEvents(t.Context(), 25)
	if err != nil || len(rows) != 0 {
		t.Fatalf("revived old epoch: %+v %v", rows, err)
	}
	c.refreshPreference()
	scope.Record(api.RelayConnect, api.TlsTcp, api.Succeeded, time.Second)
	scope.Close()
	flushForTest(t, c)
	rows, err = c.state.PendingTelemetryEvents(t.Context(), 25)
	if err != nil || len(rows) != 1 {
		t.Fatalf("lost new epoch: %+v %v", rows, err)
	}
}

func TestTelemetryOffCancelsInflightAndCloseJoins(t *testing.T) {
	entered := make(chan struct{}, 1)
	canceled := make(chan struct{}, 1)
	client := &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		entered <- struct{}{}
		<-r.Context().Done()
		canceled <- struct{}{}
		return nil, r.Context().Err()
	})}
	c := collectorForTest(t, Config{Client: client})
	c.Report(Demo())
	c.Flush()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("request did not start")
	}
	if err := c.state.SetTelemetryEnabled(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	select {
	case <-canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("opt-out did not cancel delivery")
	}
	ctx, stop := context.WithCancel(context.Background())
	stop()
	c.Close(ctx)
	select {
	case <-c.done:
	default:
		t.Fatal("close did not join workers")
	}
}

func TestTelemetryCollectionIsBoundedAndDoesNotWaitForIO(t *testing.T) {
	// no state handle, HTTP client or worker exists: collection must only fill
	// the bounded channel and drop overflow, without attempting external I/O.
	c := &Collector{queue: make(chan queuedEvent, 64)}
	c.preference.Store(&clientstate.TelemetryPreference{Enabled: true})
	var work sync.WaitGroup
	for range 4 {
		work.Go(func() {
			for range 1000 {
				c.Report(Demo())
			}
		})
	}
	finished := make(chan struct{})
	go func() { work.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("collection waited for I/O")
	}
	if len(c.queue) != 64 || cap(c.queue) != 64 {
		t.Fatal("unbounded queue")
	}
}

func TestTelemetrySetupCanRetryAfterInvalidRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	if err := os.WriteFile(root, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if c, err := New(t.Context(), Config{Root: root, Protection: clientstate.ProtectionFile}); err == nil || c != nil {
		t.Fatal("invalid root accepted")
	}
	if err := os.Remove(root); err != nil {
		t.Fatal(err)
	}
	c := collectorForTest(t, Config{Root: root})
	id, err := c.state.InstallationID(t.Context())
	if err != nil || id == "" {
		t.Fatalf("installation: %q %v", id, err)
	}
}

func TestTelemetrySiblingScopesStaySeparate(t *testing.T) {
	c := collectorForTest(t, Config{})
	optedOut := c.BeginScope("publisher", true)
	optedIn := c.BeginScope("publisher", false)
	defer optedIn.Close()
	for range 10 {
		optedOut.Record(api.RelayConnect, api.Quic, api.Succeeded, time.Second)
	}
	optedIn.Record(api.RelayConnect, api.TlsTcp, api.Succeeded, time.Second)
	optedOut.Close()
	optedIn.Close()
	flushForTest(t, c)
	rows, err := c.state.PendingTelemetryEvents(t.Context(), 25)
	if err != nil || len(rows) != 1 {
		t.Fatalf("sibling reports: %+v %v", rows, err)
	}
	var event api.Event
	_ = json.Unmarshal(rows[0].JSON, &event)
	report, _ := event.AsTransportEvent()
	if len(report.Payload.Measurements) != 1 || report.Payload.Measurements[0].Count != 1 || report.Payload.Measurements[0].Path != api.TlsTcp {
		t.Fatalf("mixed siblings: %+v", report)
	}
}
