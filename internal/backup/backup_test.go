package backup

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/benbjohnson/litestream/file"
	"github.com/tnldotdev/tnl/internal/state"
)

func TestBackupRestoreRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	replicaPath := filepath.Join(t.TempDir(), "replica")
	sourceDir := filepath.Join(t.TempDir(), "source")
	sourceDB, err := state.Open(ctx, sourceDir)
	if err != nil {
		t.Fatal(err)
	}
	manager := &Manager{databasePath: state.DatabasePath(sourceDir), client: file.NewReplicaClient(replicaPath)}
	if err := manager.Start(ctx); err != nil {
		t.Fatal(err)
	}
	token, _, err := state.EnsureLoginToken(ctx, sourceDB)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.WriteRelayMap(ctx, sourceDB, []byte(`{"Regions":{}}`)); err != nil {
		t.Fatal(err)
	}
	cache := state.ControlTLSCache(sourceDB, "https://acme.example/directory")
	if err := cache.Put(ctx, "account", []byte("account-data")); err != nil {
		t.Fatal(err)
	}
	if err := sourceDB.Close(); err != nil {
		t.Fatal(err)
	}
	if err := manager.Close(ctx); err != nil {
		t.Fatal(err)
	}

	targetDir := filepath.Join(t.TempDir(), "target")
	if err := os.MkdirAll(targetDir, 0o700); err != nil {
		t.Fatal(err)
	}
	restore := &Manager{databasePath: state.DatabasePath(targetDir), client: file.NewReplicaClient(replicaPath)}
	restored, err := restore.Restore(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !restored {
		t.Fatal("backup was not restored")
	}
	targetDB, err := state.Open(ctx, targetDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = targetDB.Close() })
	if got, err := state.ReadLoginToken(ctx, targetDB); err != nil || got != token {
		t.Fatalf("login token = %q, %v", got, err)
	}
	if got, err := state.ReadRelayMap(ctx, targetDB); err != nil || string(got) != `{"Regions":{}}` {
		t.Fatalf("relay map = %q, %v", got, err)
	}
	if got, err := state.ControlTLSCache(targetDB, "https://acme.example/directory").Get(ctx, "account"); err != nil || string(got) != "account-data" {
		t.Fatalf("control TLS cache = %q, %v", got, err)
	}
}

func TestValidateURL(t *testing.T) {
	for _, value := range []string{"", "s3://bucket/path", "s3://bucket/path?endpoint=localhost:9000"} {
		if err := ValidateURL(value); err != nil {
			t.Errorf("ValidateURL(%q): %v", value, err)
		}
	}
	for _, value := range []string{"file:///tmp/backup", "s3://bucket", "s3:///path", "s3://user@bucket/path"} {
		if err := ValidateURL(value); err == nil {
			t.Errorf("ValidateURL(%q) succeeded", value)
		}
	}
}

func TestRestoreWithoutBackup(t *testing.T) {
	targetDir := t.TempDir()
	manager := &Manager{
		databasePath: state.DatabasePath(targetDir),
		client:       file.NewReplicaClient(filepath.Join(t.TempDir(), "empty")),
	}
	if restored, err := manager.Restore(t.Context()); err != nil {
		t.Fatal(err)
	} else if restored {
		t.Fatal("empty replica was restored")
	}
	if _, err := os.Stat(manager.databasePath); !os.IsNotExist(err) {
		t.Fatalf("database stat error = %v, want not exist", err)
	}
}
