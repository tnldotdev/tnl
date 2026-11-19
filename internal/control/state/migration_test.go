package state

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

func TestMigrationOneIsImmutable(t *testing.T) {
	data, err := migrationFiles.ReadFile("migrations/00001_baseline.sql")
	if err != nil {
		t.Fatal(err)
	}
	// frozen baseline: add a numbered migration instead of updating this digest.
	const want = "4e5977bc3c30eb4e9000dc24758c1084231e5f6440d36d47f7aa3f4c3158a5fe"
	if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != want {
		t.Fatalf("migration 1 changed: SHA-256 = %s, want %s; restore it and add a numbered migration instead", got, want)
	}
}
