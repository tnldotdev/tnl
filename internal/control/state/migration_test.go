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
	// pinned after the approved PostgreSQL-only branded DNS replacement.
	const want = "38b355b86536cda6e9d25f45561fee98ba59718a22ba862759b62e86ef22367a"
	if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != want {
		t.Fatalf("migration 1 changed: SHA-256 = %s, want %s; add a numbered migration unless a schema reset is explicitly approved", got, want)
	}
}
