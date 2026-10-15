//go:build !darwin

package clientstate

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestV1FileWrappingKeyProtectsPrivateState(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	database, err := Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	store, err := database.Server(t.Context(), "https://control.example.test")
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := store.secrets.Seal(t.Context(), "test-credential", []byte("private value"))
	if err != nil || bytes.Contains(sealed, []byte("private value")) {
		t.Fatalf("private value was not protected: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	store, err = reopened.Server(t.Context(), "https://control.example.test")
	if err != nil {
		t.Fatal(err)
	}
	value, err := store.secrets.Open(t.Context(), "test-credential", sealed)
	if err != nil || string(value) != "private value" {
		t.Fatalf("private value did not survive reopening: %q, %v", value, err)
	}
	if _, err := store.secrets.Open(t.Context(), "different-credential", sealed); err == nil {
		t.Fatal("protected value was accepted under another context")
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(WrappingKeyPath(root)); err != nil {
		t.Fatal(err)
	}
	if database, err := Open(t.Context(), root); err == nil {
		database.Close()
		t.Fatal("existing database reopened without its wrapping key")
	}
}
