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
	// pinned after the approved PostgreSQL-only publisher watch replacement.
	const want = "4117fcc948d0736c8341ffc4136f31dd9f60cc05897f5405acc52e764ae982d4"
	if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != want {
		t.Fatalf("migration 1 changed: SHA-256 = %s, want %s; add a numbered migration unless a schema reset is explicitly approved", got, want)
	}
}
