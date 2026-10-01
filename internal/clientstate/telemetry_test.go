package clientstate

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	tnlsqlite "github.com/tnldotdev/tnl/internal/sqlite"
)

func TestTelemetryPreferenceIsPersistentAndDoesNotCreateStateOnRead(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	read := func(want bool) {
		t.Helper()
		enabled, err := TelemetryEnabledAt(t.Context(), root)
		if err != nil || enabled != want {
			t.Fatalf("telemetry enabled = %t, error = %v; want %t", enabled, err, want)
		}
	}
	read(true)
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("read of absent client state created files: %v", err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	baseline, err := fs.ReadFile(migrationFiles, "migrations/00001_schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := tnlsqlite.Open(t.Context(), DatabasePath(root), fstest.MapFS{
		"00001_schema.sql": &fstest.MapFile{Data: baseline},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}
	read(true)
	state, err := Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.SetTelemetryEnabled(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	read(false)
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	state, err = Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	enabled, err := state.TelemetryEnabled(t.Context())
	if err != nil || enabled {
		t.Fatalf("reopened telemetry preference = %t, error = %v", enabled, err)
	}
	if err := state.SetTelemetryEnabled(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	read(true)
}
