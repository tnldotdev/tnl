package telemetry

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	api "github.com/tnldotdev/tnl/pkg/api/integrations/telemetry/v1"
)

func TestDeferredStartsAndReportsWhileCollectorOpens(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	allowOpen := make(chan struct{})
	opening := make(chan struct{})
	batches := make(chan api.Batch, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if api.ValidateBatch(body) != nil {
			t.Errorf("invalid telemetry batch: %s", body)
		}
		var batch api.Batch
		if err := json.Unmarshal(body, &batch); err != nil {
			t.Errorf("decode batch: %v", err)
		}
		select {
		case batches <- batch:
		default:
			t.Error("unexpected second telemetry batch")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	config := Config{Root: root, Endpoint: server.URL, FlushInterval: time.Hour}
	start := time.Now()
	d, err := newDeferred(t.Context(), config, func(ctx context.Context, config Config) (*Collector, error) {
		close(opening)
		select {
		case <-allowOpen:
			return New(ctx, config)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	if err != nil || d == nil {
		t.Fatalf("start deferred reporter: %v", err)
	}
	defer closeDeferred(t, d)
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("collector open held up command startup")
	}
	select {
	case <-opening:
	case <-time.After(2 * time.Second):
		t.Fatal("collector did not begin opening")
	}
	start = time.Now()
	d.Report(Observation{Event: CommandCompleted, Command: api.CommandOutcomeCommandPublish})
	d.Flush()
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("report or flush waited for collector startup")
	}
	close(allowOpen)
	select {
	case batch := <-batches:
		if len(batch.Events) != 1 {
			t.Fatalf("initial command observation was lost: %+v", batch.Events)
		}
		command, err := batch.Events[0].AsCommandEvent()
		if err != nil || command.Payload.Command != api.CommandOutcomeCommandPublish || command.Payload.Outcome != api.Completed {
			t.Fatalf("initial command observation = %+v, error = %v", command, err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("queued command observation was not delivered after open")
	}
}

func TestDeferredFencesQueuedObservationsAcrossOffOn(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	state, err := clientstate.Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	allowOpen := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	config := Config{Root: root, Endpoint: server.URL, FlushInterval: time.Hour}
	d, err := newDeferred(t.Context(), config, func(ctx context.Context, config Config) (*Collector, error) {
		select {
		case <-allowOpen:
			return New(ctx, config)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	if err != nil || d == nil {
		t.Fatalf("start deferred reporter: %v", err)
	}
	defer closeDeferred(t, d)
	d.Report(Observation{Event: CommandCompleted, Command: api.CommandOutcomeCommandPublish})
	if err := state.SetTelemetryEnabled(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	if err := state.SetTelemetryEnabled(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	// even an observation made after re-enabling cannot be assigned the new
	// epoch until the reporter has observed that epoch.
	d.Report(Observation{Event: CommandCanceled, Command: api.CommandOutcomeCommandPublish})
	close(allowOpen)
	deadline := time.After(2 * time.Second)
	for d.ready.Load() == nil {
		select {
		case <-deadline:
			t.Fatal("collector did not open")
		case <-time.After(5 * time.Millisecond):
		}
	}
	d.Report(Observation{Event: CommandFailed, Command: api.CommandOutcomeCommandPublish, FailureStage: api.Setup})
	closeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	d.Close(closeCtx)
	if closeCtx.Err() != nil {
		t.Fatalf("collector failed to close within budget: %v", closeCtx.Err())
	}
	items, err := state.PendingTelemetryEvents(t.Context(), 25)
	if err != nil || len(items) != 1 {
		t.Fatalf("stale queued observations reappeared: %+v, error = %v", items, err)
	}
	var event api.Event
	if err := json.Unmarshal(items[0].JSON, &event); err != nil {
		t.Fatal(err)
	}
	command, err := event.AsCommandEvent()
	if err != nil || command.Payload.Outcome != api.Failed {
		t.Fatalf("retained observation = %+v, error = %v; want post-toggle failure", command, err)
	}
}

func TestDeferredPreferenceReadDoesNotWaitForLockedState(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	state, err := clientstate.Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	// an exclusive rollback-journal writer prevents the read-only preference
	// query from completing; optional telemetry must not hold up the command.
	connection, err := sql.Open("sqlite", clientstate.DatabasePath(root))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := connection.ExecContext(t.Context(), "PRAGMA journal_mode=DELETE"); err != nil {
		t.Fatal(err)
	}
	locked, err := connection.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer locked.Close()
	if _, err := locked.ExecContext(t.Context(), "BEGIN EXCLUSIVE"); err != nil {
		t.Fatal(err)
	}
	defer locked.ExecContext(context.Background(), "ROLLBACK")
	start := time.Now()
	d, err := NewDeferred(t.Context(), Config{Root: root})
	if d != nil {
		closeDeferred(t, d)
		t.Fatal("started telemetry without reading its preference")
	}
	if err == nil {
		t.Fatal("locked preference was treated as enabled")
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatalf("optional preference read blocked command startup: %v", err)
	}
}

func TestDeferredDoesNotOpenCollectorWhenOptedOut(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	state, err := clientstate.Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	if err := state.SetTelemetryEnabled(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	d, err := newDeferred(t.Context(), Config{Root: root}, func(context.Context, Config) (*Collector, error) {
		t.Error("opened telemetry collector after opt-out")
		return nil, nil
	})
	if err != nil || d != nil {
		closeDeferred(t, d)
		t.Fatalf("opted-out reporter = %v, error = %v", d, err)
	}
}

func closeDeferred(t *testing.T, d *Deferred) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	d.Close(ctx)
	if ctx.Err() != nil {
		t.Errorf("deferred reporter did not close within budget: %v", ctx.Err())
	}
}

func TestDeferredCloseCancelsAndJoinsPendingOpen(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	opening := make(chan struct{})
	exited := make(chan struct{})
	d, err := newDeferred(t.Context(), Config{Root: root}, func(ctx context.Context, _ Config) (*Collector, error) {
		close(opening)
		<-ctx.Done()
		close(exited)
		return nil, ctx.Err()
	})
	if err != nil || d == nil {
		t.Fatalf("start deferred reporter: %v", err)
	}
	<-opening
	d.Report(Observation{Event: CommandCompleted})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	d.Close(ctx)
	if time.Since(start) > time.Second {
		t.Fatal("close waited for optional collector startup")
	}
	select {
	case <-exited:
	default:
		t.Fatal("close returned without joining the opening worker")
	}
	select {
	case <-d.done:
	default:
		t.Fatal("close returned before deferred worker exited")
	}
}

func TestDeferredCloseJoinsCollectorOpenBlockedBySQLiteWriter(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	state, err := clientstate.Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	allowOpen := make(chan struct{})
	d, err := newDeferred(t.Context(), Config{Root: root}, func(ctx context.Context, config Config) (*Collector, error) {
		<-allowOpen
		return New(ctx, config)
	})
	if err != nil || d == nil {
		t.Fatalf("start deferred reporter: %v", err)
	}
	defer closeDeferred(t, d)
	connection, err := sql.Open("sqlite", clientstate.DatabasePath(root))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := connection.ExecContext(t.Context(), "PRAGMA journal_mode=DELETE"); err != nil {
		t.Fatal(err)
	}
	locked, err := connection.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer locked.Close()
	if _, err := locked.ExecContext(t.Context(), "BEGIN EXCLUSIVE"); err != nil {
		t.Fatal(err)
	}
	defer locked.ExecContext(context.Background(), "ROLLBACK")
	close(allowOpen)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	d.Close(ctx)
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("close did not join a locked collector open within the shutdown budget")
	}
	select {
	case <-d.done:
	default:
		t.Fatal("close returned before locked collector open exited")
	}
}

func TestDeferredCloseJoinsCollectorWithLockedOutbox(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	state, err := clientstate.Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	d, err := NewDeferred(t.Context(), Config{Root: root, FlushInterval: time.Hour})
	if err != nil || d == nil {
		t.Fatalf("start deferred reporter: %v", err)
	}
	defer closeDeferred(t, d)
	deadline := time.After(2 * time.Second)
	for d.ready.Load() == nil {
		select {
		case <-deadline:
			t.Fatal("collector did not open")
		case <-time.After(5 * time.Millisecond):
		}
	}
	connection, err := sql.Open("sqlite", clientstate.DatabasePath(root))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	locked, err := connection.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer locked.Close()
	if _, err := locked.ExecContext(t.Context(), "BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	defer locked.ExecContext(context.Background(), "ROLLBACK")
	d.Report(Observation{Event: CommandCompleted, Command: api.CommandOutcomeCommandPublish})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	d.Close(ctx)
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("close did not join a locked collector outbox within the shutdown budget")
	}
	select {
	case <-d.done:
	default:
		t.Fatal("close returned before collector exited")
	}
}
