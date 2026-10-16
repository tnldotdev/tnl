package clientruntime

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestJournalAdapterUsesNativeTransactionAndOpaqueCursor(t *testing.T) {
	database, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	project := t.TempDir()
	snapshot, err := ReadSnapshotFrom(t.Context(), database, project)
	if err != nil {
		t.Fatal(err)
	}
	initial := snapshot.Cursor
	snapshot.Services = []Service{{Project: project, Name: "web", Directory: project, Readiness: Readiness{Path: "/health"}}}
	// retain the caller's service pointer: manager operations may still hold it
	// while the adapter refreshes cursor, publications, and history.
	service := &snapshot.Services[0]
	if err := CommitSnapshot(t.Context(), database, &snapshot, "runtime.started", nil); err != nil {
		t.Fatal(err)
	}
	if service != &snapshot.Services[0] {
		t.Fatal("commit invalidated caller service pointer")
	}
	if snapshot.Cursor == initial || len(snapshot.Events) != 1 || snapshot.Events[0].Snapshot == nil || snapshot.Events[0].Snapshot.Cursor != snapshot.Cursor {
		t.Fatalf("committed app snapshot: %#v", snapshot)
	}
	started := snapshot.Cursor
	tunnel, err := database.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{
		Command: clientstate.TunnelCommandPublish, Server: "https://server.example", Target: "5432", Project: project, Service: "database", ServiceProtocol: controlv1.Postgres,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Finish(context.Background(), nil)
	service.Registered = true
	if err := CommitSnapshot(t.Context(), database, &snapshot, "service.registered", service); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Publications) != 1 || len(snapshot.Events) != 3 {
		t.Fatalf("unified adapter snapshot: %#v", snapshot)
	}
	if err := CommitSnapshot(t.Context(), database, &snapshot, "runtime.configured", nil); err != nil {
		t.Fatal(err)
	}
	last := snapshot.Events[len(snapshot.Events)-1]
	if last.Snapshot == nil || len(last.Snapshot.Publications) != 1 || last.Snapshot.Publications[0].ID != tunnel.ID() || last.Snapshot.Cursor != snapshot.Cursor {
		t.Fatal("snapshot event is not the exact committed native project view")
	}
	events, err := EventsAfter(snapshot, started)
	if err != nil || len(events) != 3 || events[0].Publication == nil || events[0].Publication.ID != tunnel.ID() || events[1].Service == nil {
		t.Fatalf("unified resume: %#v, %v", events, err)
	}
	if !reflect.DeepEqual(*events[0].Publication, snapshot.Publications[0]) || !reflect.DeepEqual(*events[0].Publication, last.Snapshot.Publications[0]) {
		t.Fatal("publication event and snapshot event decoded different tunnel observations")
	}
	nativeEvents, err := EventsAfterFrom(t.Context(), database, project, started)
	if err != nil || len(nativeEvents) != len(events) || nativeEvents[len(nativeEvents)-1].Cursor != events[len(events)-1].Cursor {
		t.Fatalf("native resume differs from snapshot resume: %#v, %v", nativeEvents, err)
	}
	data, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Snapshot
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Cursor != snapshot.Cursor || len(decoded.Services) != 1 || len(decoded.Publications) != 1 || len(decoded.Events) != 0 {
		t.Fatalf("external JSON: %s", data)
	}
	persisted, err := ReadSnapshotFrom(t.Context(), database, project)
	if err != nil || persisted.Cursor != snapshot.Cursor || !persisted.Services[0].Registered {
		t.Fatalf("persisted adapter: %#v, %v", persisted, err)
	}
	if _, err := EventsAfter(persisted, "0:1"); !errors.Is(err, ErrCursorExpired) {
		t.Fatalf("legacy cursor accepted: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := clientstate.OpenWithOptions(t.Context(), database.Root(), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	listed, err := ListSnapshotsFrom(t.Context(), reopened)
	if err != nil || len(listed) != 1 || listed[0].Cursor != persisted.Cursor {
		t.Fatalf("restart adapter: %#v, %v", listed, err)
	}
}

func TestJournalAdapterRejectedWritePreservesCommittedCursor(t *testing.T) {
	database, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	project := t.TempDir()
	first, err := ReadSnapshotFrom(t.Context(), database, project)
	if err != nil {
		t.Fatal(err)
	}
	stale := first
	if err := CommitSnapshot(t.Context(), database, &first, "runtime.started", nil); err != nil {
		t.Fatal(err)
	}
	if err := CommitSnapshot(t.Context(), database, &stale, "runtime.started", nil); !errors.Is(err, clientstate.ErrRuntimeConflict) {
		t.Fatalf("stale app writer: %v", err)
	}
	if len(stale.Events) != 0 || stale.Cursor == first.Cursor {
		t.Fatal("failed write advanced in-memory cursor")
	}
}
