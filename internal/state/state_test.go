package state

import (
	"context"
	"database/sql"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"
)

func TestOpen(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	db, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}

	assertMode(t, dir, 0o700)
	assertMode(t, filepath.Join(dir, databaseName), 0o600)
	assertPragma(t, db, "journal_mode", "wal")
	assertPragma(t, db, "foreign_keys", "1")
	assertPragma(t, db, "busy_timeout", "5000")
	if got := db.Stats().MaxOpenConnections; got != 1 {
		t.Fatalf("maximum open connections = %d, want 1", got)
	}

	var version int
	if err := db.QueryRow("SELECT MAX(version_id) FROM goose_db_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 4 {
		t.Fatalf("schema version = %d, want 4", version)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db, err = Open(context.Background(), dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOpenRejectsNewerSchema(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	db, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO goose_db_version (version_id, is_applied) VALUES (5, 1)"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(context.Background(), dir); err == nil {
		t.Fatal("Open succeeded with a newer schema")
	} else if !strings.Contains(err.Error(), "newer than supported") {
		t.Fatalf("Open error = %q", err)
	}
}

func TestOpenMigratesPopulatedV3(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dataSourceName(filepath.Join(dir, databaseName)))
	if err != nil {
		t.Fatal(err)
	}
	migrations, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := goose.NewProvider(
		goose.DialectSQLite3, db, migrations, goose.WithDisableGlobalRegistry(true),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.UpTo(ctx, 3); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO principals (id, display_name, email, created_at)
		VALUES ('owner', 'Owner', '', 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO hostname_claims (id, principal_id, hostname, created_at)
		VALUES ('claim_0123456789abcdef0123456789abcdef', 'owner', 'route.example', 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO routes
		(id, claim_id, principal_id, hostname, display_target, state, generation, created_at)
		VALUES ('route_0123456789abcdef0123456789abcdef', 'claim_0123456789abcdef0123456789abcdef',
		'owner', 'route.example', 'http://127.0.0.1:3000', 'active', 1, 1)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db, err = Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	var irreversible int
	var tombstonedAt sql.NullInt64
	if err := db.QueryRow(`SELECT irreversible, tombstoned_at FROM hostname_claims
		WHERE id = 'claim_0123456789abcdef0123456789abcdef'`).Scan(&irreversible, &tombstonedAt); err != nil {
		t.Fatal(err)
	}
	if irreversible != 1 || tombstonedAt.Valid {
		t.Fatalf("migrated claim = irreversible %d, tombstoned %v", irreversible, tombstonedAt)
	}
	var routes int
	if err := db.QueryRow(`SELECT COUNT(*) FROM routes WHERE state = 'active'`).Scan(&routes); err != nil {
		t.Fatal(err)
	}
	if routes != 1 {
		t.Fatalf("active routes after migration = %d", routes)
	}
}

func TestDatabaseConstraints(t *testing.T) {
	db, err := Open(context.Background(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	if _, err := db.Exec(`INSERT INTO access_credentials
		(id, principal_id, secret_hash, created_at, expires_at)
		VALUES ('credential', 'missing', X'01', 1, 2)`); err == nil {
		t.Fatal("foreign key insert succeeded")
	}
	if _, err := db.Exec(`INSERT INTO principals
		(id, display_name, email, created_at)
		VALUES ('principal', 'Principal', 'principal@example.com', 1)`); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	results := make(chan error, 2)
	for _, id := range []string{"first", "second"} {
		go func() {
			<-start
			_, err := db.Exec(`INSERT INTO access_credentials
				(id, principal_id, secret_hash, created_at, expires_at)
				VALUES (?, 'principal', X'02', 1, 2)`, id)
			results <- err
		}()
	}
	close(start)

	succeeded := 0
	for range 2 {
		if err := <-results; err == nil {
			succeeded++
		}
	}
	if succeeded != 1 {
		t.Fatalf("successful duplicate inserts = %d, want 1", succeeded)
	}
}

func TestIsDatabaseContention(t *testing.T) {
	db, err := sql.Open(
		"sqlite",
		"file:"+filepath.ToSlash(filepath.Join(t.TempDir(), "contention.db"))+"?_busy_timeout=1&_txlock=immediate",
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(2)
	if _, err := db.Exec("CREATE TABLE values_table (value INTEGER)"); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback() })
	if _, err := tx.Exec("INSERT INTO values_table VALUES (1)"); err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO values_table VALUES (2)")
	if !IsDatabaseContention(err) {
		t.Fatalf("IsDatabaseContention(%v) = false", err)
	}
	if IsDatabaseContention(errors.New("storage failed")) {
		t.Fatal("non-SQLite error classified as database contention")
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %o, want %o", path, got, want)
	}
}

func assertPragma(t *testing.T, db *sql.DB, name, want string) {
	t.Helper()
	var got string
	if err := db.QueryRow("PRAGMA " + name).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("PRAGMA %s = %q, want %q", name, got, want)
	}
}
