// Package state opens and migrates the tnld SQLite database.
package state

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite"
)

const databaseName = "tnld.db"

//go:embed migrations/*.sql
var migrationFiles embed.FS

// Open creates, configures, and migrates the database in dir.
func Open(ctx context.Context, dir string) (*sql.DB, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("state: empty directory")
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("state: resolve directory: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("state: create directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("state: secure directory: %w", err)
	}

	path := filepath.Join(dir, databaseName)
	db, err := sql.Open("sqlite", dataSourceName(path))
	if err != nil {
		return nil, fmt.Errorf("state: open database: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("state: connect database: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		db.Close()
		return nil, fmt.Errorf("state: secure database: %w", err)
	}
	if err := migrate(ctx, db); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func dataSourceName(path string) string {
	u := &url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	query := u.Query()
	query.Set("_busy_timeout", "5000")
	query.Set("_foreign_keys", "on")
	query.Set("_journal_mode", "WAL")
	u.RawQuery = query.Encode()
	return u.String()
}

func migrate(ctx context.Context, db *sql.DB) error {
	fsys, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		return fmt.Errorf("state: load migrations: %w", err)
	}
	provider, err := goose.NewProvider(
		goose.DialectSQLite3,
		db,
		fsys,
		goose.WithDisableGlobalRegistry(true),
	)
	if err != nil {
		return fmt.Errorf("state: configure migrations: %w", err)
	}
	current, target, err := provider.GetVersions(ctx)
	if err != nil {
		return fmt.Errorf("state: read schema version: %w", err)
	}
	if current > target {
		return fmt.Errorf("state: database schema version %d is newer than supported version %d", current, target)
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("state: migrate database: %w", err)
	}
	return checkForeignKeys(ctx, db)
}

func checkForeignKeys(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return fmt.Errorf("state: check foreign keys: %w", err)
	}
	defer rows.Close()
	if rows.Next() {
		return errors.New("state: foreign key check failed")
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("state: check foreign keys: %w", err)
	}
	return nil
}
