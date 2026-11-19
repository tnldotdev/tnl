package state

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"testing"
)

func TestMigrationOneIsImmutable(t *testing.T) {
	data, err := migrationFiles.ReadFile("migrations/00001_schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	// frozen baseline: add a numbered migration instead of updating this digest.
	const want = "01cb64f87d6710f284d7a06dbb2213eca4eb5758b81bca1c7b1dcbfbc9de336f"
	if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != want {
		t.Fatalf("migration 1 changed: SHA-256 = %s, want %s; restore it and add a numbered migration instead", got, want)
	}
}

func TestPreviousBaselineIdentityPreservesClientState(t *testing.T) {
	ctx := t.Context()
	root := filepath.Join(t.TempDir(), "state")
	database := openFileDatabase(t, root)
	var identity string
	if err := database.db.QueryRowContext(ctx, `SELECT identity FROM baseline_identity WHERE id=1`).Scan(&identity); err != nil || identity != "v1-client" {
		t.Fatalf("fresh baseline = %q, %v; want v1-client", identity, err)
	}
	document := []byte("saved publisher jobs")
	if err := database.SavePublisherJobRegistry(ctx, document); err != nil {
		t.Fatal(err)
	}
	var ciphertext []byte
	if err := database.db.QueryRowContext(ctx, `SELECT jobs_ciphertext FROM publisher_job_registry`).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`DROP TABLE baseline_identity`,
		`CREATE TABLE baseline_identity (
			id INTEGER PRIMARY KEY CHECK (id=1),
			identity TEXT NOT NULL CHECK (identity='tnl-client-fresh-v1-service-integrations')
		) STRICT`,
		`INSERT INTO baseline_identity VALUES (1, 'tnl-client-fresh-v1-service-integrations')`,
	} {
		if _, err := database.db.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	reader, err := openReadOnlySQLite(ctx, DatabasePath(root))
	if err != nil {
		t.Fatal("read-only state rejected the previous baseline name", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openFileDatabase(t, root)
	got, found, err := reopened.PublisherJobRegistry(ctx)
	if err != nil || !found || !bytes.Equal(got, document) {
		t.Fatalf("saved publisher jobs did not survive reopening: found=%t, %v", found, err)
	}
	if err := reopened.db.QueryRowContext(ctx, `SELECT identity FROM baseline_identity WHERE id=1`).Scan(&identity); err != nil || identity != "tnl-client-fresh-v1-service-integrations" {
		t.Fatalf("existing baseline was rewritten: %q, %v", identity, err)
	}
	var preserved []byte
	if err := reopened.db.QueryRowContext(ctx, `SELECT jobs_ciphertext FROM publisher_job_registry`).Scan(&preserved); err != nil || !bytes.Equal(ciphertext, preserved) {
		t.Fatal("reopening rewrote protected state", err)
	}
	if err := reopened.SavePublisherJobRegistry(ctx, []byte("updated publisher jobs")); err != nil {
		t.Fatal("previous baseline no longer accepts writes", err)
	}
}
