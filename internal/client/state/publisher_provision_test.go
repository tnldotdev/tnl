package clientstate

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"
)

func TestPublisherProvisionJournalProtectsTransitions(t *testing.T) {
	store := testStore(t, filepath.Join(t.TempDir(), "state"), "https://control.example")
	first := []byte(`{"key":"private-signing-key","token":"private-token","stage":"creating"}`)
	if err := store.AppendPublisherProvision(t.Context(), "aws", "deployment", 0, first); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendPublisherProvision(t.Context(), "aws", "deployment", 0, []byte(`{"key":"replacement"}`)); !errors.Is(err, ErrPublisherStateConflict) {
		t.Fatal("stale writer replaced key", err)
	}
	second := []byte(`{"key":"private-signing-key","token":"private-token","stage":"durable"}`)
	if err := store.AppendPublisherProvision(t.Context(), "aws", "deployment", 1, second); err != nil {
		t.Fatal(err)
	}
	data, revision, err := store.PublisherProvision(t.Context(), "aws", "deployment")
	if err != nil || revision != 2 || !bytes.Equal(data, second) {
		t.Fatal("latest transition lost", err)
	}
	var count int
	if err := store.database.db.QueryRow(`SELECT count(*) FROM publisher_provision_journal`).Scan(&count); err != nil || count != 2 {
		t.Fatal("transition history overwritten", err)
	}
	var sealed []byte
	if err := store.database.db.QueryRow(`SELECT document_ciphertext FROM publisher_provision_journal WHERE revision=1`).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("private-signing-key")) || bytes.Contains(sealed, []byte("private-token")) {
		t.Fatal("journal secrets stored as plaintext")
	}
	if _, err := store.database.db.Exec(`UPDATE publisher_provision_journal SET document_ciphertext=? WHERE revision=2`, sealed); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.PublisherProvision(t.Context(), "aws", "deployment"); err == nil {
		t.Fatal("ciphertext replay crossed transition context")
	}
}
