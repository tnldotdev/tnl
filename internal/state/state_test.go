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
	if version != 3 {
		t.Fatalf("schema version = %d, want 3", version)
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
	if _, err := db.Exec("INSERT INTO goose_db_version (version_id, is_applied) VALUES (4, 1)"); err != nil {
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

func TestOpenMigratesVersionOneClaims(t *testing.T) {
	ctx := context.Background()
	dir, err := prepareDirectory(filepath.Join(t.TempDir(), "state"))
	if err != nil {
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
	provider, err := goose.NewProvider(goose.DialectSQLite3, db, migrations, goose.WithDisableGlobalRegistry(true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.UpTo(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO principals (id, display_name, email, created_at)
		VALUES ('owner', 'Owner', 'owner@example.com', 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO hostname_claims
		(id, principal_id, hostname, created_at, tombstoned_at) VALUES
		('active', 'owner', 'active.example.com', 2, NULL),
		('released', 'owner', 'released.example.com', 3, 4)`); err != nil {
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
	rows, err := db.Query(`SELECT id, kind, state, activated_at, released_at
		FROM hostname_claims ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var id, kind, claimState string
		var activatedAt, releasedAt sql.NullInt64
		if err := rows.Scan(&id, &kind, &claimState, &activatedAt, &releasedAt); err != nil {
			t.Fatal(err)
		}
		count++
		switch id {
		case "active":
			if kind != "persistent_managed" || claimState != "active" || !activatedAt.Valid || activatedAt.Int64 != 2 || releasedAt.Valid {
				t.Fatalf("active claim = %q, %q, %#v, %#v", kind, claimState, activatedAt, releasedAt)
			}
		case "released":
			if kind != "persistent_managed" || claimState != "released_owned" || activatedAt.Valid || !releasedAt.Valid || releasedAt.Int64 != 4 {
				t.Fatalf("released claim = %q, %q, %#v, %#v", kind, claimState, activatedAt, releasedAt)
			}
		default:
			t.Fatalf("unexpected migrated claim %q", id)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("migrated claims = %d, want 2", count)
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
