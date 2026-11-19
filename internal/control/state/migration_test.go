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
	// frozen migration: add a numbered migration instead of updating this digest.
	const want = "5b85863076237723b53a4db8e1c30f3f3cd21affc54395f72baf9e3477e37139"
	if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != want {
		t.Fatalf("migration 1 changed: SHA-256 = %s, want %s; restore it and add a numbered migration instead", got, want)
	}
}
