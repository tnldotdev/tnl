package clientstate

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"
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
		if err := db.SaveRuntimeJournal(t.Context(), project, cursor, []byte(`{"cursor":`+strconv.FormatInt(cursor, 10)+`}`), payload); err != nil {
			t.Fatal(err)
		}
	}
	journal, found, err := db.ReadRuntimeJournal(t.Context(), project)
	if err != nil || !found || len(journal.Events) != 2 || string(journal.Snapshot) != `{"cursor":4}` {
		t.Fatalf("bounded journal = %d events, found=%t, snapshot=%s, error=%v", len(journal.Events), found, journal.Snapshot, err)
	}
	if err := db.SaveRuntimeJournal(t.Context(), project, 4, []byte(`{"cursor":5}`), []byte(`{}`)); err == nil {
		t.Fatal("duplicate cursor advanced the journal")
	}
	list, err := db.ListRuntimeJournals(t.Context())
	if err != nil || len(list) != 1 || string(list[0].Snapshot) != `{"cursor":4}` || len(list[0].Events) != 2 {
		t.Fatalf("transactional journal list = %d projects, error=%v", len(list), err)
	}
	if err := db.SaveRuntimeJournal(t.Context(), project, 5, []byte(`{"cursor":5}`), []byte(`{"data":"`+strings.Repeat("x", 8<<20)+`"}`)); err == nil {
		t.Fatal("accepted an oversized event")
	}
	_, found, err = db.ReadRuntimeJournal(t.Context(), "/missing")
	if err != nil || found {
		t.Fatalf("missing journal: found=%t, error=%v", found, err)
	}
}
