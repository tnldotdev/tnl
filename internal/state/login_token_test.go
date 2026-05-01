package state

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestLoginTokenLifecycle(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	db, err := Open(context.Background(), directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	first, generated, err := EnsureLoginToken(t.Context(), db)
	if err != nil {
		t.Fatal(err)
	}
	if !generated || first == "" {
		t.Fatalf("generated = %t, token = %q", generated, first)
	}
	second, generated, err := EnsureLoginToken(t.Context(), db)
	if err != nil {
		t.Fatal(err)
	}
	if generated || second != first {
		t.Fatalf("second token = %q, generated = %t", second, generated)
	}

	rotated, err := RotateLoginToken(t.Context(), db)
	if err != nil {
		t.Fatal(err)
	}
	if rotated == first {
		t.Fatal("rotation preserved the previous token")
	}
	if stored, err := ReadLoginToken(t.Context(), db); err != nil || stored != rotated {
		t.Fatalf("stored token = %q, %v", stored, err)
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
