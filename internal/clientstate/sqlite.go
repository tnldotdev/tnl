package clientstate

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
	_ "modernc.org/sqlite"
)

// openClientSQLite configures every connection, including replacements after
// cancellation. only a fresh database applies the single baseline.
func openClientSQLite(ctx context.Context, path string, fresh bool) (_ *sql.DB, retErr error) {
	// the caller has validated the owner-only root and its trusted ancestors.
	// inspect metadata without opening these files: closing any extra descriptor
	// for the database or -shm inode drops this process's posix locks, including
	// locks held by other live sqlite connections. only sqlite may own their
	// descriptors so its vfs can coordinate closes with outstanding locks.
	for _, name := range []string{path, path + "-wal", path + "-shm"} {
		info, err := os.Lstat(name)
		if errors.Is(err, os.ErrNotExist) && name != path {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("clientstate: validate database file: %w", err)
		}
		if err := validatePrivateFile(info, false); err != nil {
			return nil, fmt.Errorf("clientstate: validate database file: %w", err)
		}
	}
	u := &url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	query := u.Query()
	query.Set("mode", "rw")
	query.Set("_txlock", "immediate")
	query.Add("_pragma", "busy_timeout(5000)")
	query.Add("_pragma", "foreign_keys(1)")
	query.Add("_pragma", "journal_mode(WAL)")
	u.RawQuery = query.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	defer func() {
		if retErr != nil {
			db.Close()
		}
	}()
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		return nil, err
	}
	migrations, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		return nil, err
	}
	provider, err := goose.NewProvider(goose.DialectSQLite3, db, migrations, goose.WithDisableGlobalRegistry(true))
	if err != nil {
		return nil, err
	}
	if fresh {
		if _, err := provider.Up(ctx); err != nil {
			return nil, err
		}
	}
	version, target, err := provider.GetVersions(ctx)
	if err != nil {
		return nil, err
	}
	if version != 1 || target != 1 {
		return nil, errors.New("clientstate: unsupported v1 database baseline")
	}
	rows, err := db.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if rows.Next() {
		return nil, errors.New("clientstate: foreign key check failed")
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return db, nil
}

// initializeClientSQLite publishes the database filename only after the fresh
// baseline and wrapping-key check are durable. interruption leaves no partial
// canonical database for a later process to mistake for initialized state.
// the caller holds the initialization lock from key creation through this call.
func initializeClientSQLite(ctx context.Context, path string, mode ProtectionMode, protector secretProtector) (*sql.DB, error) {
	file, err := os.CreateTemp(filepath.Dir(path), ".v1-initializing-*.db")
	if err != nil {
		return nil, err
	}
	staging := file.Name()
	defer os.Remove(staging)
	defer os.Remove(staging + "-wal")
	defer os.Remove(staging + "-shm")
	if err := file.Close(); err != nil {
		return nil, err
	}
	db, err := openClientSQLite(ctx, staging, true)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	check, err := protector.Seal(ctx, "wrapping-key-check", []byte("tnl client state v1"))
	if err != nil {
		return nil, err
	}
	if _, err := db.ExecContext(ctx, "INSERT INTO state_protection (id, protection_mode, key_check_ciphertext) VALUES (1, ?, ?)", string(mode), check); err != nil {
		return nil, err
	}
	if _, err := db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		return nil, err
	}
	if err := db.Close(); err != nil {
		return nil, err
	}
	// link publishes atomically and refuses to overwrite a file that appeared
	// after the initial existence check. the temporary name is then removed.
	if err := os.Link(staging, path); err != nil {
		return nil, err
	}
	if err := os.Remove(staging); err != nil {
		return nil, err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	err = directory.Sync()
	err = errors.Join(err, directory.Close())
	if err != nil {
		return nil, err
	}
	return openClientSQLite(ctx, path, false)
}
