package clientstate

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"testing"
	"time"
)

func TestSSHHostSetupProtectedScopedAndDurable(t *testing.T) {
	database, err := OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), OpenOptions{Protection: ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store, err := database.Server(t.Context(), "https://control.example.test")
	if err != nil {
		t.Fatal(err)
	}
	const team = "tm_0123456789abcdefghijkl"
	state, err := store.LockSSHHostSetup(t.Context(), team, "host.example.test")
	if err != nil {
		t.Fatal(err)
	}
	value := []byte(`{"key":"host-private-secret","enrollment":"one-use-secret"}`)
	if err := state.Save(t.Context(), value); err != nil {
		t.Fatal(err)
	}
	sealed, err := state.root.ReadFile(state.name)
	if err != nil || bytes.Contains(sealed, []byte("host-private-secret")) || bytes.Contains(sealed, []byte("one-use-secret")) || !bytes.HasPrefix(sealed, sealedValuePrefix) {
		t.Fatalf("setup was not protected: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if _, err := store.LockSSHHostSetup(ctx, team, "host.example.test"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("setup writes were not serialized: %v", err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	root := database.Root()
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	database, err = OpenWithOptions(t.Context(), root, OpenOptions{Protection: ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store, err = database.Server(t.Context(), "https://control.example.test")
	if err != nil {
		t.Fatal(err)
	}
	state, err = store.LockSSHHostSetup(t.Context(), team, "host.example.test")
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	got, found, err := state.Read(t.Context())
	if err != nil || !found || !bytes.Equal(got, value) {
		t.Fatalf("checkpoint changed on reopen: %v", err)
	}
	other, err := store.LockSSHHostSetup(t.Context(), team, "other.example.test")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := other.root.WriteFile(other.name, sealed, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := other.Read(t.Context()); err == nil {
		t.Fatal("encrypted setup accepted under another hostname")
	}
	if err := state.root.Chmod(state.name, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := state.Read(t.Context()); err == nil {
		t.Fatal("insecure setup permissions accepted")
	}
}

func TestSSHHostSetupFailedWriteKeepsOriginalCiphertext(t *testing.T) {
	database, err := OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), OpenOptions{Protection: ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store, err := database.Server(t.Context(), "https://control.example.test")
	if err != nil {
		t.Fatal(err)
	}
	state, err := store.LockSSHHostSetup(t.Context(), "tm_0123456789abcdefghijkl", "host.example.test")
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	if err := state.Save(t.Context(), []byte("original")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := state.Save(ctx, []byte("replacement")); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	value, found, err := state.Read(t.Context())
	if err != nil || !found || string(value) != "original" {
		t.Fatalf("failed save changed setup: %v", err)
	}
	entries, err := fs.ReadDir(state.root.FS(), ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if len(entry.Name()) >= 9 && entry.Name()[:9] == ".pending-" {
			t.Fatal("interrupted write left temporary state")
		}
	}
}
