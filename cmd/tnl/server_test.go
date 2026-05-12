package main

import (
	"path/filepath"
	"testing"

	"github.com/tnldotdev/tnl/internal/clientstate"
)

func TestResolveServerPrefersExplicitValue(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	state, err := clientstate.Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.SaveServer(t.Context(), "https://saved.example"); err != nil {
		t.Fatal(err)
	}
	state.Close()
	server, resolvedState, err := resolveServer(t.Context(), root, "https://explicit.example")
	if err != nil || server != "https://explicit.example" {
		t.Fatalf("resolved server = %q, %v", server, err)
	}
	resolvedState.Close()
	server, resolvedState, err = resolveServer(t.Context(), root, "")
	if err != nil || server != "https://saved.example" {
		t.Fatalf("saved server = %q, %v", server, err)
	}
	resolvedState.Close()
}

func TestResolveServerDefaultsToHostedWithoutSavingSelection(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	server, state, err := resolveServer(t.Context(), root, "")
	if err != nil || server != defaultServerURL {
		t.Fatalf("default server = %q, %v", server, err)
	}
	defer state.Close()
	if _, found, err := state.SavedServer(t.Context()); err != nil || found {
		t.Fatalf("hosted default was persisted: found=%t, error=%v", found, err)
	}
}
