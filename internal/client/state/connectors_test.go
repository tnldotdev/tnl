package state

import (
	"path/filepath"
	"testing"
	"time"
)

func TestConnectorLifecycleScopesAndFencesLocalProcesses(t *testing.T) {
	db := openFileDatabase(t, filepath.Join(t.TempDir(), "state"))
	store, err := db.Server(t.Context(), "https://control.example")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	db.now = func() time.Time { return now }
	value := Connector{IdentityID: "identity", ServiceID: "service", Protocol: "postgres", ProcessID: 123, ListenPort: 15432, State: "starting", LeaseExpiresAt: now.Add(time.Minute)}
	if err := store.SaveConnector(t.Context(), value); err != nil {
		t.Fatal(err)
	}
	value.State = "ready"
	if err := store.SaveConnector(t.Context(), value); err != nil {
		t.Fatal(err)
	}
	value.ProcessID = 456
	if err := store.SaveConnector(t.Context(), value); err == nil {
		t.Fatal("another process replaced a live supervisor")
	}
	if err := store.RemoveConnector(t.Context(), "identity", "service", 456); err != nil {
		t.Fatal(err)
	}
	statuses, err := store.Connectors(t.Context(), "identity")
	if err != nil || len(statuses) != 1 || statuses[0].ProcessID != 123 || statuses[0].State != "ready" {
		t.Fatalf("ready connector status: %+v %v", statuses, err)
	}
	if other, err := store.Connectors(t.Context(), "other"); err != nil || len(other) != 0 {
		t.Fatalf("connector crossed identity boundary: %v", err)
	}
	now = now.Add(2 * time.Minute)
	statuses, err = store.Connectors(t.Context(), "identity")
	if err != nil || len(statuses) != 1 || statuses[0].State != "stale" {
		t.Fatalf("stale connector status: %+v %v", statuses, err)
	}
	value.LeaseExpiresAt = now.Add(time.Minute)
	if err := store.SaveConnector(t.Context(), value); err != nil {
		t.Fatal(err)
	}
	if err := store.RemoveConnector(t.Context(), "identity", "service", 123); err != nil {
		t.Fatal(err)
	}
	statuses, err = store.Connectors(t.Context(), "identity")
	if err != nil || len(statuses) != 1 || statuses[0].ProcessID != 456 {
		t.Fatalf("old process removed replacement: %+v %v", statuses, err)
	}
}
