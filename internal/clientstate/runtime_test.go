package clientstate

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestRuntimeJournalRetainsBoundedTransactionalHistory(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	db, err := Open(t.Context(), state)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	project := "/project"
	payload := []byte(`{"data":"` + strings.Repeat("x", 3<<20) + `"}`)
	for cursor := int64(1); cursor <= 4; cursor++ {
		assigned, err := db.SaveRuntimeJournal(t.Context(), project, []byte(`{"cursor":"0"}`), payload)
		if err != nil || assigned != cursor {
			t.Fatalf("assigned cursor = %d, want %d: %v", assigned, cursor, err)
		}
	}
	journal, found, err := db.ReadRuntimeJournal(t.Context(), project)
	if err != nil || !found || len(journal.Events) != 2 || string(journal.Snapshot) != `{"cursor":"4"}` {
		t.Fatalf("bounded journal = %d events, found=%t, snapshot=%s, error=%v", len(journal.Events), found, journal.Snapshot, err)
	}
	list, err := db.ListRuntimeJournals(t.Context())
	if err != nil || len(list) != 1 || string(list[0].Snapshot) != `{"cursor":"4"}` || len(list[0].Events) != 2 {
		t.Fatalf("transactional journal list = %d projects, error=%v", len(list), err)
	}
	if _, err := db.SaveRuntimeJournal(t.Context(), project, []byte(`{"cursor":"5"}`), []byte(`{"data":"`+strings.Repeat("x", 8<<20)+`"}`)); err == nil {
		t.Fatal("accepted an oversized event")
	}
	_, found, err = db.ReadRuntimeJournal(t.Context(), "/missing")
	if err != nil || found {
		t.Fatalf("missing journal: found=%t, error=%v", found, err)
	}
}

func TestDirectTunnelEventsBoundSharedProjectJournal(t *testing.T) {
	database, err := Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	project := t.TempDir()
	tunnel, err := database.BeginTunnel(t.Context(), BeginTunnelOptions{
		Command: TunnelCommandPublish, Server: "https://server.example", Target: "127.0.0.1:5432",
		Project: project, ServiceProtocol: controlv1.Postgres,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Finish(context.Background(), nil)
	for run := uint64(1); run <= 2050; run++ {
		if err := tunnel.SetProvisioning(t.Context(), run); err != nil {
			t.Fatal(err)
		}
	}
	journal, found, err := database.ReadRuntimeJournal(t.Context(), project)
	if err != nil || !found || len(journal.Events) != 2048 {
		t.Fatalf("direct tunnel event history = %d, found=%t, error=%v", len(journal.Events), found, err)
	}
	var snapshot struct {
		Cursor string `json:"cursor"`
	}
	var first, last struct {
		Cursor string `json:"cursor"`
	}
	if err := json.Unmarshal(journal.Snapshot, &snapshot); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(journal.Events[0], &first); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(journal.Events[len(journal.Events)-1], &last); err != nil {
		t.Fatal(err)
	}
	if snapshot.Cursor != "2051" || first.Cursor != "4" || last.Cursor != snapshot.Cursor {
		t.Fatalf("bounded direct tunnel cursors: snapshot=%q, first=%q, last=%q", snapshot.Cursor, first.Cursor, last.Cursor)
	}
}

func TestDirectHTTPPublishUsesTheSameProjectJournal(t *testing.T) {
	database, err := Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	project := t.TempDir()
	tunnel, err := database.BeginTunnel(t.Context(), BeginTunnelOptions{
		Command: TunnelCommandPublish, Server: "https://server.example", Target: "3000", Project: project,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Finish(context.Background(), nil)
	if err := tunnel.SetPublicURL(t.Context(), testPublicURLID, "web.example"); err != nil {
		t.Fatal(err)
	}
	if err := tunnel.SetReady(t.Context(), "https://web.example", 1); err != nil {
		t.Fatal(err)
	}
	journal, found, err := database.ReadRuntimeJournal(t.Context(), project)
	if err != nil || !found || len(journal.Events) != 3 {
		t.Fatalf("direct HTTP journal = %d events, found=%t, error=%v", len(journal.Events), found, err)
	}
	var event struct {
		Type   string `json:"type"`
		Cursor string `json:"cursor"`
		Tunnel struct {
			ID        string `json:"tunnel_id"`
			PublicURL string `json:"public_url"`
		} `json:"tunnel"`
	}
	if err := json.Unmarshal(journal.Events[2], &event); err != nil || event.Type != "tunnel.ready" || event.Cursor != "3" ||
		event.Tunnel.ID != tunnel.ID() || event.Tunnel.PublicURL != "https://web.example" {
		t.Fatalf("direct HTTP ready event = %#v, error=%v", event, err)
	}
}
