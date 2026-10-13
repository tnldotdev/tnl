package clientstate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/opaqueid"
)

func TestTelemetryPreferenceIsPersistentAndDoesNotCreateStateOnRead(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	read := func(want bool) {
		t.Helper()
		enabled, err := TelemetryEnabledAt(t.Context(), root)
		if err != nil || enabled != want {
			t.Fatalf("telemetry enabled = %t, error = %v; want %t", enabled, err, want)
		}
	}
	read(true)
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("read of absent client state created files: %v", err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	// an old client.db must not be opened or imported when client-v2.db is absent.
	if err := os.WriteFile(filepath.Join(root, "client.db"), []byte("old database"), 0o600); err != nil {
		t.Fatal(err)
	}
	read(true)
	if _, err := os.Stat(DatabasePath(root)); !os.IsNotExist(err) {
		t.Fatalf("telemetry read created versioned state: %v", err)
	}
	state, err := Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.SetTelemetryEnabled(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	read(false)
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	state, err = Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	enabled, err := state.TelemetryEnabled(t.Context())
	if err != nil || enabled {
		t.Fatalf("reopened telemetry preference = %t, error = %v", enabled, err)
	}
	if err := state.SetTelemetryEnabled(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	read(true)
}

func TestReadyTelemetryDeduplicatesAcrossPublisherRestartsAndRespectsPreference(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	state, err := Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	key := strings.Repeat("a", 64)
	event := json.RawMessage(`{"name":"tunnel.ready"}`)
	queue := func(db *Database, key string) bool {
		t.Helper()
		id, err := opaqueid.New(opaqueid.TelemetryEventPrefix)
		if err != nil {
			t.Fatal(err)
		}
		inserted, err := db.QueueReadyTelemetryEvent(t.Context(), key, id, event)
		if err != nil {
			t.Fatal(err)
		}
		return inserted
	}
	if !queue(state, key) {
		t.Fatal("first ready event was not queued")
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	state, err = Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	if queue(state, key) {
		t.Fatal("publisher restart queued a second ready event")
	}
	if err := state.SetTelemetryEnabled(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	other := strings.Repeat("b", 64)
	if queue(state, other) {
		t.Fatal("disabled telemetry queued a ready event")
	}
	if err := state.SetTelemetryEnabled(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	if !queue(state, other) {
		t.Fatal("disabled telemetry marked an invocation as sent")
	}
	pending, err := state.PendingTelemetryEvents(t.Context(), 25)
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending ready events = %d, error=%v", len(pending), err)
	}
}
