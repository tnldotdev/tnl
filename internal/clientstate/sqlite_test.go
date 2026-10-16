package clientstate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type failedProtector struct{}

func (failedProtector) Seal(context.Context, string, []byte) ([]byte, error) {
	return nil, errors.New("sealing failed")
}
func (failedProtector) Open(context.Context, string, []byte) ([]byte, error) {
	return nil, errors.New("opening failed")
}

func TestFreshInitializationDoesNotPublishPartialDatabase(t *testing.T) {
	root, err := PrepareRoot(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	if database, err := initializeClientSQLite(t.Context(), DatabasePath(root), ProtectionFile, failedProtector{}); err == nil {
		database.Close()
		t.Fatal("failed secret initialization succeeded")
	}
	if _, err := os.Lstat(DatabasePath(root)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial canonical database was published: %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed initialization left temporary files: %#v, %v", entries, err)
	}
	database := openFileDatabase(t, root)
	if _, err := database.ReadRuntimeSnapshot(t.Context(), t.TempDir()); err != nil {
		t.Fatal(err)
	}
}

func TestSQLiteSettingsSurviveConnectionReplacement(t *testing.T) {
	database := openFileDatabase(t, filepath.Join(t.TempDir(), "state"))
	// discard idle connections so every subsequent operation uses a new one.
	database.db.SetMaxIdleConns(0)
	for _, test := range []struct {
		pragma string
		want   int
	}{{"foreign_keys", 1}, {"busy_timeout", 5000}} {
		var value int
		if err := database.db.QueryRowContext(t.Context(), "PRAGMA "+test.pragma).Scan(&value); err != nil || value != test.want {
			t.Fatalf("%s after replacement: %d, %v", test.pragma, value, err)
		}
	}
	var mode string
	if err := database.db.QueryRowContext(t.Context(), "PRAGMA journal_mode").Scan(&mode); err != nil || mode != "wal" {
		t.Fatalf("journal mode: %q, %v", mode, err)
	}
}
