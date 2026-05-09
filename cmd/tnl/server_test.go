package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tnldotdev/tnl/internal/clientstate"
)

func TestResolveServerPrefersExplicitValue(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	if err := clientstate.SaveServer(root, "https://saved.example"); err != nil {
		t.Fatal(err)
	}
	server, _, err := resolveServer(root, "https://explicit.example")
	if err != nil || server != "https://explicit.example" {
		t.Fatalf("resolved server = %q, %v", server, err)
	}
	server, _, err = resolveServer(root, "")
	if err != nil || server != "https://saved.example" {
		t.Fatalf("saved server = %q, %v", server, err)
	}
}

func TestResolveServerDefaultsToHostedWithoutSavingSelection(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	server, _, err := resolveServer(root, "")
	if err != nil || server != defaultServerURL {
		t.Fatalf("default server = %q, %v", server, err)
	}
	if _, err := os.Stat(filepath.Join(root, "selected-server.json")); !os.IsNotExist(err) {
		t.Fatalf("selected server was persisted: %v", err)
	}
}
