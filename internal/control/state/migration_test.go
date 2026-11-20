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
	const want = "e29c9bd45b4a50558cbc4ee9547cc386b1943d988506333efdf53676ca292c8c"
	if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != want {
		t.Fatalf("migration 1 changed: SHA-256 = %s, want %s; add a numbered migration unless a schema reset is explicitly approved", got, want)
	}
}
