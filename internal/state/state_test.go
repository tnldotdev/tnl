package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	if version != 1 {
		t.Fatalf("schema version = %d, want 1", version)
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
	if _, err := db.Exec("INSERT INTO goose_db_version (version_id, is_applied) VALUES (2, 1)"); err != nil {
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

func TestDatabaseConstraints(t *testing.T) {
	db, err := Open(context.Background(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	if _, err := db.Exec(`INSERT INTO control_sessions
		(id, identity_id, authentication_method, authentication_source_revision, grants, created_at,
		 refresh_expires_at, access_token_id, access_token_hash, access_expires_at,
		 refresh_token_id, refresh_token_hash)
		VALUES ('control_session_00000000000000000000000000000000', 'missing', 'login_token', 1, 'publish', 1,
		 3, 'access', X'01', 2, 'refresh', X'02')`); err == nil {
		t.Fatal("foreign key insert succeeded")
	}
	if _, err := db.Exec(`INSERT INTO identities
		(id, display_name, email, created_at)
		VALUES ('identity', 'Identity', 'identity@example.com', 1)`); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	results := make(chan error, 2)
	for index, id := range []string{
		"control_session_00000000000000000000000000000001",
		"control_session_00000000000000000000000000000002",
	} {
		go func() {
			<-start
			_, err := db.Exec(`INSERT INTO control_sessions
				(id, identity_id, authentication_method, authentication_source_revision, grants, created_at,
				 refresh_expires_at, access_token_id, access_token_hash, access_expires_at,
				 refresh_token_id, refresh_token_hash)
				VALUES (?, 'identity', 'login_token', 1, 'publish', 1, 3, ?, X'03', 2, ?, ?)`,
				id, fmt.Sprintf("access-%d", index), fmt.Sprintf("refresh-%d", index), []byte{byte(4 + index)})
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
