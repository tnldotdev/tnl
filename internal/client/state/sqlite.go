package state

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

const schemaVersion int64 = 2

// openReadOnlySQLite reads existing client state without creating or migrating it.
func openReadOnlySQLite(ctx context.Context, path string) (*sql.DB, error) {
	u := &url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	query := u.Query()
	query.Set("mode", "ro")
	query.Add("_pragma", "busy_timeout(5000)")
	u.RawQuery = query.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		return nil, errors.Join(err, db.Close())
	}
	if err := checkClientSchemaVersion(ctx, db, schemaVersion); err != nil {
		return nil, errors.Join(err, db.Close())
	}
	return db, nil
}

// openClientSQLite configures every connection, including replacements after
// cancellation and applies pending migrations under the caller's migration lock.
func openClientSQLite(ctx context.Context, path string, noWait bool) (_ *sql.DB, retErr error) {
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
	if noWait {
		query.Set("_pragma", "busy_timeout(0)")
	}
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
	if err := migrateClientSQLite(ctx, db, migrations, schemaVersion); err != nil {
		return nil, err
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

func migrateClientSQLite(ctx context.Context, db *sql.DB, migrations fs.FS, supported int64) error {
	provider, err := goose.NewProvider(goose.DialectSQLite3, db, migrations, goose.WithDisableGlobalRegistry(true))
	if err != nil {
		return err
	}
	current, target, err := provider.GetVersions(ctx)
	if err != nil {
		return fmt.Errorf("read client state schema version: %w", err)
	}
	if target != supported {
		return fmt.Errorf("embedded client schema version %d does not match supported version %d", target, supported)
	}
	if current > target {
		return fmt.Errorf("client state schema version %d is newer than supported version %d", current, target)
	}
	// current databases open without a write lock, including optional telemetry.
	if current < target {
		if _, err := provider.Up(ctx); err != nil {
			return fmt.Errorf("migrate client state: %w", err)
		}
	}
	return checkClientSchemaVersion(ctx, db, supported)
}

func checkClientSchemaVersion(ctx context.Context, db *sql.DB, supported int64) error {
	var version int64
	if err := db.QueryRowContext(ctx, "SELECT version_id FROM goose_db_version WHERE is_applied = 1 ORDER BY id DESC LIMIT 1").Scan(&version); err != nil {
		return fmt.Errorf("read client state schema version: %w", err)
	}
	if version != supported {
		return fmt.Errorf("client state schema version %d does not match supported version %d", version, supported)
	}
	return nil
}

// initializeClientSQLite publishes the database filename only after the fresh
// schema and wrapping-key check are durable. interruption leaves no partial
// canonical database for a later process to mistake for initialized state.
// the caller holds the initialization lock from key creation through this call.
func initializeClientSQLite(ctx context.Context, path string, mode ProtectionMode, protector secretProtector, noWait bool) (*sql.DB, error) {
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
	db, err := openClientSQLite(ctx, staging, noWait)
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
	return openClientSQLite(ctx, path, noWait)
}
