package state

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLoginTokenLifecycle(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	first, generated, err := EnsureLoginToken(directory)
	if err != nil {
		t.Fatal(err)
	}
	if !generated || first == "" {
		t.Fatalf("generated = %t, token = %q", generated, first)
	}
	assertMode(t, filepath.Join(directory, loginTokenName), 0o600)

	second, generated, err := EnsureLoginToken(directory)
	if err != nil {
		t.Fatal(err)
	}
	if generated || second != first {
		t.Fatalf("second token = %q, generated = %t", second, generated)
	}

	rotated, err := RotateLoginToken(directory)
	if err != nil {
		t.Fatal(err)
	}
	if rotated == first {
		t.Fatal("rotation preserved the previous token")
	}
	if stored, err := ReadLoginToken(directory); err != nil || stored != rotated {
		t.Fatalf("stored token = %q, %v", stored, err)
	}
}

func TestLoginTokenRejectsUnsafeFile(t *testing.T) {
	directory := t.TempDir()
	if _, _, err := EnsureLoginToken(directory); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(directory, loginTokenName), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadLoginToken(directory); err == nil {
		t.Fatal("world-readable login token accepted")
	}
}

func TestDirectoryLock(t *testing.T) {
	directory := t.TempDir()
	first, err := LockDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LockDirectory(directory); !errors.Is(err, ErrLocked) {
		t.Fatalf("second lock error = %v, want %v", err, ErrLocked)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := LockDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}
