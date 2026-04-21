package state

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/0xcadams/tnl/internal/credentials"
)

func TestBootstrapTokenLifecycle(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	first, generated, err := EnsureBootstrapToken(directory, "")
	if err != nil {
		t.Fatal(err)
	}
	if !generated || first == "" {
		t.Fatalf("generated = %t, token = %q", generated, first)
	}
	assertMode(t, filepath.Join(directory, bootstrapTokenName), 0o600)

	second, generated, err := EnsureBootstrapToken(directory, "")
	if err != nil {
		t.Fatal(err)
	}
	if generated || second != first {
		t.Fatalf("second token = %q, generated = %t", second, generated)
	}

	rotated, err := RotateBootstrapToken(directory)
	if err != nil {
		t.Fatal(err)
	}
	if rotated == first {
		t.Fatal("rotation preserved the previous token")
	}
	if stored, err := ReadBootstrapToken(directory); err != nil || stored != rotated {
		t.Fatalf("stored token = %q, %v", stored, err)
	}
}

func TestBootstrapTokenRejectsUnsafeFile(t *testing.T) {
	directory := t.TempDir()
	if _, _, err := EnsureBootstrapToken(directory, ""); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(directory, bootstrapTokenName), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadBootstrapToken(directory); err == nil {
		t.Fatal("world-readable bootstrap token accepted")
	}
}

func TestBootstrapTokenImportsLegacyValueOnce(t *testing.T) {
	directory := t.TempDir()
	legacy, err := credentials.NewBootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	stored, generated, err := EnsureBootstrapToken(directory, legacy)
	if err != nil {
		t.Fatal(err)
	}
	if generated || stored != legacy {
		t.Fatalf("stored token = %q, generated = %t", stored, generated)
	}
	different, err := credentials.NewBootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := EnsureBootstrapToken(directory, different); err == nil {
		t.Fatal("different legacy token replaced persisted state")
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
