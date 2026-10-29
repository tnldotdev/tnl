package state

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
	if err := state.QueueTelemetryEvent(context.Background(), id, json.RawMessage(`{"event_id":"tev_0123456789abcdefghijkl"}`), json.RawMessage(`{}`), 0); err != nil {
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
		if err := state.QueueTelemetryEvent(ctx, id, json.RawMessage(`{"name":"command.outcome"}`), json.RawMessage(`{}`), 0); err != nil {
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
	if _, err := state.db.ExecContext(ctx, `INSERT INTO telemetry_outbox (event_id, created_at, event_json, client_json) VALUES (?, ?, ?, ?)`,
		"tev_abcdefghijklmnopqrstuv", time.Now().Add(-8*24*time.Hour).UnixNano(), `{"name":"old"}`, `{}`); err != nil {
		t.Fatal(err)
	}
	if _, err := state.db.ExecContext(ctx, `CREATE TRIGGER fail_telemetry_prune BEFORE DELETE ON telemetry_outbox
		BEGIN SELECT RAISE(ABORT, 'cannot prune'); END`); err != nil {
		t.Fatal(err)
	}
	id := "tev_0123456789abcdefghijkl"
	if err := state.QueueTelemetryEvent(ctx, id, json.RawMessage(`{"name":"command.outcome"}`), json.RawMessage(`{}`), 0); err == nil {
		t.Fatal("queue succeeded after pruning failed")
	}
	var count int
	if err := state.db.QueryRowContext(ctx, `SELECT count(*) FROM telemetry_outbox`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("outbox count after rollback = %d, %v", count, err)
	}
}

func TestTelemetryPreferenceEpochFencesLateWritesAcrossReenable(t *testing.T) {
	ctx := t.Context()
	root := filepath.Join(t.TempDir(), "state")
	writer, err := Open(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	preference, err := writer.TelemetryPreference(ctx)
	if err != nil || !preference.Enabled {
		t.Fatalf("initial preference = %+v, %v", preference, err)
	}
	admin, err := Open(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	queue := func(id string, epoch int64) {
		t.Helper()
		if err := writer.QueueTelemetryEvent(ctx, id, json.RawMessage(`{"name":"command.outcome"}`), json.RawMessage(`{}`), epoch); err != nil {
			t.Fatal(err)
		}
	}
	queue("tev_0123456789abcdefghijkl", preference.Epoch)
	if err := admin.SetTelemetryEnabled(ctx, false); err != nil {
		t.Fatal(err)
	}
	queue("tev_abcdefghijklmnopqrstuv", preference.Epoch)
	if pending, err := writer.PendingTelemetryEvents(ctx, 25); err != nil || len(pending) != 0 {
		t.Fatalf("late writer repopulated disabled queue: %+v, %v", pending, err)
	}
	if err := admin.SetTelemetryEnabled(ctx, true); err != nil {
		t.Fatal(err)
	}
	current, err := writer.TelemetryPreference(ctx)
	if err != nil || !current.Enabled || current.Epoch <= preference.Epoch {
		t.Fatalf("re-enabled preference = %+v, %v", current, err)
	}
	queue("tev_abcdefghijklmnopqrstuv", preference.Epoch)
	queue("tev_ABCDEFGHIJKLMNOPQRSTUV", current.Epoch)
	pending, err := writer.PendingTelemetryEvents(ctx, 25)
	if err != nil || len(pending) != 1 || pending[0].ID != "tev_ABCDEFGHIJKLMNOPQRSTUV" {
		t.Fatalf("re-enable admitted disabled-period data: %+v, %v", pending, err)
	}
	if err := admin.SetTelemetryEnabled(ctx, true); err != nil {
		t.Fatal(err)
	}
	unchanged, err := writer.TelemetryPreference(ctx)
	if err != nil || unchanged != current {
		t.Fatalf("unchanged preference fenced current collection: %+v, %v", unchanged, err)
	}
}
