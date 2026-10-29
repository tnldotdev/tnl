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

// openClientSQLite configures every connection, including replacements after
// cancellation. only a fresh database applies the single baseline.
func openClientSQLite(ctx context.Context, path string, fresh, noWait bool) (_ *sql.DB, retErr error) {
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
	busyTimeout := "busy_timeout(5000)"
	if noWait {
		busyTimeout = "busy_timeout(0)"
	}
	query.Add("_pragma", busyTimeout)
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
	var baseline string
	if err := db.QueryRowContext(ctx, "SELECT identity FROM baseline_identity WHERE id = 1").Scan(&baseline); err != nil {
		return nil, fmt.Errorf("read client state baseline; select a fresh state directory: %w", err)
	}
	if baseline != "tnl-client-fresh-v1-services" {
		return nil, errors.New("client state baseline does not match; select a fresh state directory")
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

// amendTelemetrySchema keeps this cutover's existing v1.db and saved preference.
// the caller holds migrations.lock and has verified the state protection key.
func amendTelemetrySchema(ctx context.Context, db *sql.DB) error {
	var epoch, metadata, trigger bool
	if err := db.QueryRowContext(ctx, `SELECT
		EXISTS (SELECT 1 FROM pragma_table_info('installation_settings') WHERE name = 'telemetry_epoch'),
		EXISTS (SELECT 1 FROM pragma_table_info('telemetry_outbox') WHERE name = 'client_json'),
		EXISTS (SELECT 1 FROM sqlite_schema WHERE type = 'trigger' AND name = 'telemetry_preference_changed')`).Scan(&epoch, &metadata, &trigger); err != nil {
		return fmt.Errorf("inspect telemetry schema: %w", err)
	}
	if epoch && metadata && trigger {
		return nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin telemetry schema amendment: %w", err)
	}
	defer tx.Rollback()
	if !epoch {
		if _, err := tx.ExecContext(ctx, `ALTER TABLE installation_settings ADD COLUMN telemetry_epoch INTEGER NOT NULL DEFAULT 0 CHECK (telemetry_epoch >= 0)`); err != nil {
			return fmt.Errorf("add telemetry preference epoch: %w", err)
		}
	}
	if !metadata {
		// native70 queued private wire context without captured client metadata.
		// do not translate or upload those rows. other client state stays intact.
		if _, err := tx.ExecContext(ctx, `DELETE FROM telemetry_outbox`); err != nil {
			return fmt.Errorf("discard legacy telemetry outbox: %w", err)
		}
		// the default lets sqlite add the column to the now-empty table. its
		// object constraint also rejects inserts from an old, unfenced sender.
		if _, err := tx.ExecContext(ctx, `ALTER TABLE telemetry_outbox ADD COLUMN client_json TEXT NOT NULL DEFAULT 'null' CHECK (json_valid(client_json) AND json_type(client_json) = 'object')`); err != nil {
			return fmt.Errorf("add captured telemetry metadata: %w", err)
		}
	}
	if !trigger {
		// keep the epoch at the preference's state owner, including when an
		// already-open native70 handle changes only telemetry_enabled.
		if _, err := tx.ExecContext(ctx, `CREATE TRIGGER telemetry_preference_changed AFTER UPDATE OF telemetry_enabled ON installation_settings
			WHEN OLD.telemetry_enabled <> NEW.telemetry_enabled BEGIN
				UPDATE installation_settings SET telemetry_epoch = telemetry_epoch + 1 WHERE id = NEW.id;
			END`); err != nil {
			return fmt.Errorf("fence telemetry preference changes: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit telemetry schema amendment: %w", err)
	}
	return nil
}

// initializeClientSQLite publishes the database filename only after the fresh
// baseline and wrapping-key check are durable. interruption leaves no partial
// canonical database for a later process to mistake for initialized state.
// the caller holds the initialization lock from key creation through this call.
func initializeClientSQLite(ctx context.Context, path string, mode ProtectionMode, protector secretProtector) (*sql.DB, error) {
	return initializeClientSQLiteWithBusyTimeout(ctx, path, mode, protector, false)
}

func initializeClientSQLiteWithBusyTimeout(ctx context.Context, path string, mode ProtectionMode, protector secretProtector, noWait bool) (*sql.DB, error) {
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
	db, err := openClientSQLite(ctx, staging, true, noWait)
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
	return openClientSQLite(ctx, path, false, noWait)
}
