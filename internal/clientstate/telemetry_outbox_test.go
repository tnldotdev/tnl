package clientstate

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

func TestTelemetryOutboxSurvivesOpenAndOptOutClears(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	state, err := Open(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	id := "tev_0123456789abcdefghijkl"
	if err := state.QueueTelemetryEvent(context.Background(), id, json.RawMessage(`{"event_id":"tev_0123456789abcdefghijkl"}`)); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	state, err = Open(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	items, err := state.PendingTelemetryEvents(context.Background(), 25)
	if err != nil || len(items) != 1 || items[0].ID != id {
		t.Fatalf("items = %+v, %v", items, err)
	}
	if err := state.SetTelemetryEnabled(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	items, err = state.PendingTelemetryEvents(context.Background(), 25)
	if err != nil || len(items) != 0 {
		t.Fatalf("disabled outbox = %+v, %v", items, err)
	}
}

func TestTelemetryOutboxDeletesAcknowledgedEventsTogether(t *testing.T) {
	ctx := context.Background()
	state, err := Open(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	ids := []string{"tev_0123456789abcdefghijkl", "tev_abcdefghijklmnopqrstuv", "tev_ABCDEFGHIJKLMNOPQRSTUV"}
	for _, id := range ids {
		if err := state.QueueTelemetryEvent(ctx, id, json.RawMessage(`{"name":"command.started"}`)); err != nil {
			t.Fatal(err)
		}
	}
	if err := state.DeleteTelemetryEvents(ctx, []TelemetryOutboxEvent{{ID: ids[0]}, {ID: ids[2]}}); err != nil {
		t.Fatal(err)
	}
	remaining, err := state.PendingTelemetryEvents(ctx, 25)
	if err != nil || len(remaining) != 1 || remaining[0].ID != ids[1] {
		t.Fatalf("remaining events = %+v, %v", remaining, err)
	}
}

func TestTelemetryQueueRollsBackWhenPruningFails(t *testing.T) {
	ctx := context.Background()
	state, err := Open(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	if _, err := state.db.ExecContext(ctx, `INSERT INTO telemetry_outbox (event_id, created_at, event_json) VALUES (?, ?, ?)`,
		"tev_abcdefghijklmnopqrstuv", time.Now().Add(-8*24*time.Hour).UnixNano(), `{"name":"old"}`); err != nil {
		t.Fatal(err)
	}
	if _, err := state.db.ExecContext(ctx, `CREATE TRIGGER fail_telemetry_prune BEFORE DELETE ON telemetry_outbox
		BEGIN SELECT RAISE(ABORT, 'cannot prune'); END`); err != nil {
		t.Fatal(err)
	}
	id := "tev_0123456789abcdefghijkl"
	if err := state.QueueTelemetryEvent(ctx, id, json.RawMessage(`{"name":"command.started"}`)); err == nil {
		t.Fatal("queue succeeded after pruning failed")
	}
	var count int
	if err := state.db.QueryRowContext(ctx, `SELECT count(*) FROM telemetry_outbox`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("outbox count after rollback = %d, %v", count, err)
	}
}
