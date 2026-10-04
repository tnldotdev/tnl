// Package sqlite manages client SQLite connections and migrations.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"

	"github.com/pressly/goose/v3"
	modernsqlite "modernc.org/sqlite"
)

// Open creates, configures, and migrates a SQLite database at path.
func Open(ctx context.Context, path string, migrations fs.FS) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dataSourceName(path, false))
	if err != nil {
		return nil, fmt.Errorf("sqlite: open database: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlite: connect database: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlite: secure database: %w", err)
	}
	if err := migrate(ctx, db, migrations); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// OpenReadOnly opens an existing database with a supported migration version.
func OpenReadOnly(ctx context.Context, path string, supportedVersion int64) (*sql.DB, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("sqlite: stat database: %w", err)
	}
	db, err := sql.Open("sqlite", dataSourceName(path, true))
	if err != nil {
		return nil, fmt.Errorf("sqlite: open database read-only: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlite: connect database read-only: %w", err)
	}
	var version int64
	if err := db.QueryRowContext(ctx, "SELECT COALESCE(MAX(version_id), 0) FROM goose_db_version WHERE is_applied = 1").Scan(&version); err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlite: read schema version: %w", err)
	}
	if version < 1 || version > supportedVersion {
		db.Close()
		return nil, fmt.Errorf("sqlite: unsupported database schema version %d", version)
	}
	return db, nil
}

// IsContention reports whether err is a transient SQLite writer conflict.
func IsContention(err error) bool {
	var sqliteErr *modernsqlite.Error
	if !errors.As(err, &sqliteErr) {
		return false
	}
	code := sqliteErr.Code() & 0xff
	return code == 5 || code == 6
}

func dataSourceName(path string, readOnly bool) string {
	u := &url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	query := u.Query()
	query.Set("_busy_timeout", "5000")
	query.Set("_foreign_keys", "on")
	if readOnly {
		query.Set("mode", "ro")
	} else {
		query.Set("_journal_mode", "WAL")
		query.Set("_txlock", "immediate")
	}
	u.RawQuery = query.Encode()
	return u.String()
}

func migrate(ctx context.Context, db *sql.DB, migrations fs.FS) error {
	provider, err := goose.NewProvider(
		goose.DialectSQLite3,
		db,
		migrations,
		goose.WithDisableGlobalRegistry(true),
	)
	if err != nil {
		return fmt.Errorf("sqlite: configure migrations: %w", err)
	}
	current, target, err := provider.GetVersions(ctx)
	if err != nil {
		return fmt.Errorf("sqlite: read schema version: %w", err)
	}
	if current > target {
		return fmt.Errorf("sqlite: database schema version %d is newer than supported version %d", current, target)
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("sqlite: migrate database: %w", err)
	}
	return checkForeignKeys(ctx, db)
}

func checkForeignKeys(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return fmt.Errorf("sqlite: check foreign keys: %w", err)
	}
	defer rows.Close()
	if rows.Next() {
		return errors.New("sqlite: foreign key check failed")
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("sqlite: check foreign keys: %w", err)
	}
	return nil
}
