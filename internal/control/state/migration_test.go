package state

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

func TestMigrationOneIsImmutable(t *testing.T) {
	data, err := migrationFiles.ReadFile("migrations/00001_schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	// pinned after the approved PostgreSQL-only hosted naming baseline.
	const want = "2440c8ccc0cbb21591221416992ed777761383d83c2167a66f6a7dae3a3ca311"
	if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != want {
		t.Fatalf("migration 1 changed: SHA-256 = %s, want %s; add a numbered migration unless a schema reset is explicitly approved", got, want)
	}
}
