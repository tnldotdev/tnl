package clientstate

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
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
