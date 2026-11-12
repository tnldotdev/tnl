package state

import (
	"context"
	"encoding/json"
	"fmt"
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
	if err := state.QueueTelemetryEvent(context.Background(), id, json.RawMessage(`{"event_id":"tev_0123456789abcdefghijkl"}`), 0); err != nil {
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

func TestTelemetryNoWaitDoesNotHoldShutdownBehindWriter(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	writer, err := OpenWithOptions(t.Context(), root, OpenOptions{Protection: ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	optional, err := OpenWithOptions(t.Context(), root, OpenOptions{Protection: ProtectionFile, NoWait: true})
	if err != nil {
		t.Fatal(err)
	}
	defer optional.Close()
	tx, err := writer.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	started := time.Now()
	if err := optional.QueueTelemetryEvent(t.Context(), "tev_0123456789abcdefghijkl", json.RawMessage(`{}`), 0); err == nil {
		t.Fatal("optional write bypassed active writer")
	}
	if time.Since(started) > time.Second {
		t.Fatal("optional write waited behind SQLite writer")
	}
}

func TestTelemetryOutboxRejectsStaleCollectionEpoch(t *testing.T) {
	database, err := Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.SetTelemetryEnabled(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	if err := database.SetTelemetryEnabled(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	if err := database.QueueTelemetryEvent(t.Context(), "tev_0123456789abcdefghijkl", json.RawMessage(`{}`), 0); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := database.db.QueryRowContext(t.Context(), "SELECT count(*) FROM telemetry_outbox").Scan(&count); err != nil || count != 0 {
		t.Fatalf("stale epoch repopulated queue: %d %v", count, err)
	}
}

func TestTelemetryOutboxPrunesAgeAndCount(t *testing.T) {
	database, err := Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	now := time.Now()
	tx, err := database.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for i := range telemetryOutboxMax + 2 {
		created := now.Add(time.Duration(i) * time.Nanosecond)
		if i == 0 {
			created = now.Add(-8 * 24 * time.Hour)
		}
		if _, err := tx.ExecContext(t.Context(), "INSERT INTO telemetry_outbox (event_id,created_at,event_json) VALUES (?,?,'{}')", fmt.Sprintf("tev_%022d", i), created.UnixNano()); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := database.PruneTelemetryOutbox(t.Context()); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := database.db.QueryRowContext(t.Context(), "SELECT count(*) FROM telemetry_outbox").Scan(&count); err != nil || count != telemetryOutboxMax {
		t.Fatalf("outbox count=%d err=%v", count, err)
	}
	rows, err := database.PendingTelemetryEvents(t.Context(), 25)
	if err != nil || len(rows) != 25 || rows[0].ID != fmt.Sprintf("tev_%022d", 2) {
		t.Fatalf("oldest pending: %+v %v", rows, err)
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
		if err := state.QueueTelemetryEvent(ctx, id, json.RawMessage(`{"name":"command.outcome"}`), 0); err != nil {
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
	if err := state.QueueTelemetryEvent(ctx, id, json.RawMessage(`{"name":"command.outcome"}`), 0); err == nil {
		t.Fatal("queue succeeded after pruning failed")
	}
	var count int
	if err := state.db.QueryRowContext(ctx, `SELECT count(*) FROM telemetry_outbox`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("outbox count after rollback = %d, %v", count, err)
	}
}
