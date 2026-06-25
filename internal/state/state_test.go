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
	"testing/fstest"

	tnlsqlite "github.com/tnldotdev/tnl/internal/sqlite"
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
	if version != schemaVersion {
		t.Fatalf("schema version = %d, want %d", version, schemaVersion)
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
	if _, err := db.Exec("INSERT INTO goose_db_version (version_id, is_applied) VALUES (?, 1)", schemaVersion+1); err != nil {
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

func TestMigrationTwoDiscardsOnlyCertificateIssuances(t *testing.T) {
	dir := t.TempDir()
	schema, err := migrationFiles.ReadFile("migrations/00001_schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	db, err := tnlsqlite.Open(t.Context(), DatabasePath(dir), fstest.MapFS{
		"00001_schema.sql": &fstest.MapFile{Data: schema},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`INSERT INTO identities (id, display_name, email, created_at)
		 VALUES ('identity', 'Identity', 'identity@example.com', 1)`,
		`INSERT INTO hostnames (id, identity_id, hostname, kind, status, source, created_at, activated_at)
		 VALUES ('hostname', 'identity', 'route.example', 'managed', 'active', 'user', 1, 1)`,
		`INSERT INTO routes (id, hostname_id, identity_id, hostname, local_target, status, route_version, created_at)
		 VALUES ('route', 'hostname', 'identity', 'route.example', 'http://127.0.0.1:3000', 'enabled', 1, 1)`,
		`INSERT INTO certificate_issuances (
			id, route_id, route_version, hostname, acme_profile, status, csr_der, csr_hash, spki_hash, created_at, updated_at
		 ) VALUES ('issuance_old', 'route', 1, 'route.example', 'tlsserver', 'failed', X'01', X'02', X'03', 1, 1)`,
		`INSERT INTO acme_accounts (directory_url, email, key_der, kid, created_at, updated_at)
		 VALUES ('https://acme.test/directory', 'operator@example.com', X'01', 'account', 1, 1)`,
		`INSERT INTO server_values (key, value) VALUES ('preserved', X'0102')`,
	} {
		if _, err := db.ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	beforeSchema := databaseSchemaExceptCertificate(t, db)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db, err = Open(t.Context(), dir)
	if err != nil {
		t.Fatal(err)
	}
	assertDatabaseCount(t, db, "SELECT COUNT(*) FROM certificate_issuances", 0)
	assertDatabaseCount(t, db, "SELECT COUNT(*) FROM identities WHERE id = 'identity'", 1)
	assertDatabaseCount(t, db, "SELECT COUNT(*) FROM hostnames WHERE id = 'hostname'", 1)
	assertDatabaseCount(t, db, "SELECT COUNT(*) FROM routes WHERE id = 'route'", 1)
	assertDatabaseCount(t, db, "SELECT COUNT(*) FROM acme_accounts WHERE kid = 'account'", 1)
	assertDatabaseCount(t, db, "SELECT COUNT(*) FROM server_values WHERE key = 'preserved' AND value = X'0102'", 1)
	afterSchema := databaseSchemaExceptCertificate(t, db)
	if len(afterSchema) != len(beforeSchema) {
		t.Fatalf("non-certificate schema object count = %d, want %d", len(afterSchema), len(beforeSchema))
	}
	for object, definition := range beforeSchema {
		if afterSchema[object] != definition {
			t.Fatalf("non-certificate schema object %q changed", object)
		}
	}
	var version int
	if err := db.QueryRowContext(t.Context(), "SELECT MAX(version_id) FROM goose_db_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != schemaVersion {
		t.Fatalf("schema version = %d, want %d", version, schemaVersion)
	}
	rows, err := db.QueryContext(t.Context(), "PRAGMA table_info(certificate_issuances)")
	if err != nil {
		t.Fatal(err)
	}
	columns := make(map[string]bool)
	for rows.Next() {
		var index, notNull, primaryKey int
		var name, kind string
		var defaultValue any
		if err := rows.Scan(&index, &name, &kind, &notNull, &defaultValue, &primaryKey); err != nil {
			t.Fatal(err)
		}
		columns[name] = true
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	wantColumns := []string{
		"id", "route_id", "route_version", "hostname", "directory_url", "acme_profile", "status",
		"csr_der", "csr_hash", "spki_hash", "order_started_at", "order_url", "order_expires_at", "retry_at",
		"authorization_url", "finalize_url", "challenge_url", "challenge_digest", "challenge_expires_at",
		"certificate_url", "certificate_pem", "not_before", "not_after", "renew_at", "last_error", "created_at", "updated_at",
	}
	if len(columns) != len(wantColumns) {
		t.Fatalf("certificate issuance columns = %v", columns)
	}
	for _, column := range wantColumns {
		if !columns[column] {
			t.Fatalf("certificate issuance column %q is missing", column)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	readOnly, err := OpenReadOnly(t.Context(), dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = readOnly.Close() })
	assertDatabaseCount(t, readOnly, "SELECT COUNT(*) FROM routes WHERE id = 'route'", 1)
	assertDatabaseCount(t, readOnly, "SELECT COUNT(*) FROM certificate_issuances", 0)
}

func assertDatabaseCount(t *testing.T, db *sql.DB, query string, want int) {
	t.Helper()
	var got int
	if err := db.QueryRowContext(t.Context(), query).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("count for %q = %d, want %d", query, got, want)
	}
}

func databaseSchemaExceptCertificate(t *testing.T, db *sql.DB) map[string]string {
	t.Helper()
	rows, err := db.QueryContext(t.Context(), `
		SELECT type, name, tbl_name, COALESCE(sql, '')
		FROM sqlite_schema
		WHERE tbl_name != 'certificate_issuances'
	`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	result := make(map[string]string)
	for rows.Next() {
		var kind, name, table, definition string
		if err := rows.Scan(&kind, &name, &table, &definition); err != nil {
			t.Fatal(err)
		}
		result[kind+":"+name+":"+table] = definition
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
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
