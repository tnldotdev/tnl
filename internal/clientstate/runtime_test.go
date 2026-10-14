package clientstate

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestProjectJournalRetainsBoundedTransactionalHistory(t *testing.T) {
	db, err := Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	project := t.TempDir()
	large := []byte(`{"data":"` + strings.Repeat("x", 3<<20) + `"}`)
	for i := int64(1); i <= 4; i++ {
		cursor, err := db.SaveRuntimeJournal(t.Context(), project, []byte(`{"cursor":"0"}`), large)
		if err != nil || cursor != i {
			t.Fatalf("cursor %d: %v", cursor, err)
		}
	}
	journal, found, err := db.ReadRuntimeJournal(t.Context(), project)
	if err != nil || !found || journal.Cursor != 4 || len(journal.Events) != 2 {
		t.Fatalf("journal = %#v, %v", journal.Cursor, err)
	}
	if _, err := db.SaveRuntimeJournal(t.Context(), project, []byte(`{"cursor":"0"}`), []byte(`{"data":"`+strings.Repeat("x", 8<<20)+`"}`)); err == nil {
		t.Fatal("accepted oversized event")
	}
	journal, _, err = db.ReadRuntimeJournal(t.Context(), project)
	if err != nil || journal.Cursor != 4 {
		t.Fatalf("failed write advanced cursor: %d, %v", journal.Cursor, err)
	}
}

func TestProjectJournalConcurrentDirectAndManagerWriters(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	owner, err := Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	other, err := Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	project := t.TempDir()
	tunnel, err := owner.BeginTunnel(t.Context(), BeginTunnelOptions{Command: TunnelCommandPublish, Server: "https://server.example", Target: "127.0.0.1:5432", Project: project, ServiceProtocol: controlv1.Postgres})
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Finish(context.Background(), nil)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := uint64(1); i <= 12; i++ {
			if err := tunnel.SetProvisioning(t.Context(), i); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 12; i++ {
			if _, err := other.SaveRuntimeJournal(t.Context(), project, []byte(`{"schema_version":1,"project":"`+project+`","cursor":"0","services":[]}`), []byte(`{"type":"service.warning"}`)); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	wg.Wait()
	j, found, err := owner.ReadRuntimeJournal(t.Context(), project)
	if err != nil || !found || j.Cursor != 25 || len(j.Events) != 25 {
		t.Fatalf("shared cursor = %d events=%d, err=%v", j.Cursor, len(j.Events), err)
	}
	for i, encoded := range j.Events {
		var event struct {
			Cursor string `json:"cursor"`
		}
		if err := json.Unmarshal(encoded, &event); err != nil || event.Cursor != strconv.Itoa(i+1) {
			t.Fatalf("event %d = %q, %v", i, event.Cursor, err)
		}
	}
}

func TestProjectJournalRetainsDirectTransitionsAcrossStateOpens(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	owner, err := Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	project := t.TempDir()
	tunnel, err := owner.BeginTunnel(t.Context(), BeginTunnelOptions{
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
	reader, err := Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	j, found, err := reader.ReadRuntimeJournal(t.Context(), project)
	if err != nil || !found || j.Cursor != 2051 || len(j.Events) != 2048 {
		t.Fatalf("bounded direct journal: found=%t cursor=%d events=%d err=%v", found, j.Cursor, len(j.Events), err)
	}
	var first, last struct {
		Cursor string `json:"cursor"`
	}
	if err := json.Unmarshal(j.Events[0], &first); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(j.Events[len(j.Events)-1], &last); err != nil {
		t.Fatal(err)
	}
	if first.Cursor != "4" || last.Cursor != "2051" {
		t.Fatalf("retained cursors = %q..%q", first.Cursor, last.Cursor)
	}
}
