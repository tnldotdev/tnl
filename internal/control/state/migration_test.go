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
	// pinned schema after the explicitly approved prerelease reset in #791.
	const want = "688042e29090852c42bbdd67cacfdfe1d3f2843875ea6ceb8718763325825a14"
	if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != want {
		t.Fatalf("migration 1 changed: SHA-256 = %s, want %s; add a numbered migration unless a schema reset is explicitly approved", got, want)
	}
}
