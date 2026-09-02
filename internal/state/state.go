package state

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	tnlsqlite "github.com/tnldotdev/tnl/internal/sqlite"
)

const databaseName = "tnld.db"

// DatabasePath returns the state database path within dir.
func DatabasePath(dir string) string { return filepath.Join(dir, databaseName) }

//go:embed migrations/*.sql
var migrationFiles embed.FS

// Open creates, configures, and migrates the database in dir.
func Open(ctx context.Context, dir string) (*sql.DB, error) {
	dir, err := prepareDirectory(dir)
	if err != nil {
		return nil, err
	}
	migrations, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		return nil, fmt.Errorf("state: load migrations: %w", err)
	}
	db, err := tnlsqlite.Open(ctx, DatabasePath(dir), migrations)
	if err != nil {
		return nil, fmt.Errorf("state: %w", err)
	}
	return db, nil
}

// OpenReadOnly opens an existing state database without creating or migrating state.
func OpenReadOnly(ctx context.Context, dir string) (*sql.DB, error) {
	if err := RequireDirectoryOwner(dir); err != nil {
		return nil, err
	}
	db, err := tnlsqlite.OpenReadOnly(ctx, DatabasePath(dir), 1)
	if err != nil {
		return nil, fmt.Errorf("state: %w", err)
	}
	return db, nil
}

func prepareDirectory(dir string) (string, error) {
	if strings.TrimSpace(dir) == "" {
		return "", errors.New("state: empty directory")
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("state: resolve directory: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("state: create directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", fmt.Errorf("state: secure directory: %w", err)
	}
	return dir, nil
}

// IsDatabaseContention reports whether err is a transient SQLite writer conflict.
func IsDatabaseContention(err error) bool {
	return tnlsqlite.IsContention(err)
}
