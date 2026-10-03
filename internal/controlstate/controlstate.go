// Package controlstate stores persistent control state in PostgreSQL and changes
// that state in transactions. it also manages schema migrations.
package controlstate

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/tnldotdev/tnl/internal/storagekey"
)

const (
	schemaVersion        int64 = 2
	minimumSchemaVersion int64 = 2
	versionTable               = "control.goose_db_version"
	bootstrapRetryDelay        = 25 * time.Millisecond
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// Database is the PostgreSQL connection pool for control state. its database
// details remain private to this package.
type Database struct {
	pool          *pgxpool.Pool
	storageKey    *storagekey.Keyring
	diagnosticsMu sync.Mutex
	activity      *queryActivity
	connections   *connectionActivity
}

// Migrate applies every embedded control-state migration through a direct
// PostgreSQL URL. A persistent table lock allows only one migration at a time.
func Migrate(ctx context.Context, directURL string) (retErr error) {
	config, err := parseDirectConfig(directURL)
	if err != nil {
		return fmt.Errorf("controlstate: migrate: %w", err)
	}

	db := stdlib.OpenDB(*config)
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(2)
	defer func() {
		retErr = errors.Join(retErr, db.Close())
	}()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("controlstate: migrate: connect database: %w", err)
	}
	if err := ensureMigrationLock(ctx, db); err != nil {
		return fmt.Errorf("controlstate: migrate: bootstrap lock: %w", err)
	}

	lockTx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("controlstate: migrate: begin lock transaction: %w", err)
	}
	defer func() {
		if err := lockTx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			retErr = errors.Join(retErr, fmt.Errorf("controlstate: migrate: release lock: %w", err))
		}
	}()

	var singleton int16
	if err := lockTx.QueryRowContext(ctx, `
		SELECT id
		FROM control.schema_migration_lock
		WHERE id = 1
		FOR UPDATE
	`).Scan(&singleton); err != nil {
		return fmt.Errorf("controlstate: migrate: acquire lock: %w", err)
	}

	migrations, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		return fmt.Errorf("controlstate: migrate: load migrations: %w", err)
	}
	provider, err := goose.NewProvider(
		goose.DialectPostgres,
		db,
		migrations,
		goose.WithTableName(versionTable),
		goose.WithDisableGlobalRegistry(true),
	)
	if err != nil {
		return fmt.Errorf("controlstate: migrate: configure migrations: %w", err)
	}

	current, target, err := provider.GetVersions(ctx)
	if err != nil {
		return fmt.Errorf("controlstate: migrate: read schema version: %w", err)
	}
	if target != schemaVersion {
		return fmt.Errorf("controlstate: migrate: embedded schema version %d does not match supported version %d", target, schemaVersion)
	}
	if current > target {
		return fmt.Errorf("controlstate: migrate: database schema version %d is newer than supported version %d", current, target)
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("controlstate: migrate database: %w", err)
	}
	current, target, err = provider.GetVersions(ctx)
	if err != nil {
		return fmt.Errorf("controlstate: migrate: verify schema version: %w", err)
	}
	if current != target || current != schemaVersion {
		return fmt.Errorf("controlstate: migrate: database schema version %d does not match supported version %d", current, schemaVersion)
	}
	if err := lockTx.Commit(); err != nil {
		return fmt.Errorf("controlstate: migrate: release lock: %w", err)
	}
	return nil
}

// Open connects to already-migrated control state using a pooled PostgreSQL
// URL. Open never creates or migrates schema objects.
func Open(ctx context.Context, pooledURL, currentStorageKey, previousStorageKey string) (*Database, error) {
	keyring, err := storagekey.New(currentStorageKey, previousStorageKey)
	if err != nil {
		return nil, fmt.Errorf("controlstate: open: %w", err)
	}
	config, err := parsePoolConfig(pooledURL)
	if err != nil {
		return nil, fmt.Errorf("controlstate: open: %w", err)
	}
	activity := new(queryActivity)
	connections := new(connectionActivity)
	config.ConnConfig.Tracer = &connectionTracer{connections: connections, purpose: requestPoolConnection, queries: activity}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("controlstate: open database: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("controlstate: connect database: %w", err)
	}

	if err := checkSchemaVersion(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}
	return &Database{pool: pool, storageKey: keyring, activity: activity, connections: connections}, nil
}

// Close closes all runtime database connections. it is safe to call more than
// once.
func (d *Database) Close() {
	if d != nil && d.pool != nil {
		d.pool.Close()
	}
}

// Health verifies that the database can serve a query through the runtime
// pool.
func (d *Database) Health(ctx context.Context) error {
	if d == nil || d.pool == nil {
		return errors.New("controlstate: database is not open")
	}
	if err := d.pool.Ping(ctx); err != nil {
		return fmt.Errorf("controlstate: database health: %w", err)
	}
	return nil
}

// Readiness verifies runtime connectivity and schema compatibility. unlike
// Open, it is safe to call repeatedly from a readiness probe.
func (d *Database) Readiness(ctx context.Context) error {
	if err := d.Health(ctx); err != nil {
		return err
	}
	return checkSchemaVersion(ctx, d.pool)
}

// migrations must remain compatible with processes still serving traffic.
func checkSchemaVersion(ctx context.Context, database schemaVersionQuerier) error {
	version, err := readSchemaVersion(ctx, database)
	if err != nil {
		return err
	}
	if version < minimumSchemaVersion {
		return fmt.Errorf("controlstate: incompatible database schema version %d; minimum supported version is %d", version, minimumSchemaVersion)
	}
	return nil
}

type schemaVersionQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func readSchemaVersion(ctx context.Context, database schemaVersionQuerier) (int64, error) {
	var version int64
	if err := database.QueryRow(ctx, `
		SELECT COALESCE(MAX(version_id) FILTER (WHERE is_applied), 0)
		FROM control.goose_db_version
	`).Scan(&version); err != nil {
		return 0, fmt.Errorf("controlstate: read schema version: %w", err)
	}
	return version, nil
}

func parseDirectConfig(rawURL string) (*pgx.ConnConfig, error) {
	if err := validateDatabaseURL(rawURL); err != nil {
		return nil, err
	}
	config, err := pgx.ParseConfig(rawURL)
	if err != nil {
		return nil, fmt.Errorf("configure PostgreSQL URL: %w", err)
	}
	config.DefaultQueryExecMode = pgx.QueryExecModeExec
	return config, nil
}

func parsePoolConfig(rawURL string) (*pgxpool.Config, error) {
	if err := validateDatabaseURL(rawURL); err != nil {
		return nil, err
	}
	parsed, _ := url.Parse(rawURL) // validated above.
	parameters := parsed.Query()
	if !parameters.Has("pool_max_conns") {
		parameters.Set("pool_max_conns", "8")
		parsed.RawQuery = parameters.Encode()
	}
	config, err := pgxpool.ParseConfig(parsed.String())
	if err != nil {
		return nil, fmt.Errorf("configure PostgreSQL URL: %w", err)
	}
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeExec
	return config, nil
}

func validateDatabaseURL(rawURL string) error {
	if rawURL == "" {
		return errors.New("PostgreSQL URL is empty")
	}
	if rawURL != strings.TrimSpace(rawURL) {
		return errors.New("PostgreSQL URL contains surrounding whitespace")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return errors.New("PostgreSQL URL is invalid")
	}
	if parsed.Scheme != "postgres" && parsed.Scheme != "postgresql" {
		return errors.New("PostgreSQL URL must use the postgres or postgresql scheme")
	}
	if parsed.Opaque != "" || parsed.Fragment != "" {
		return errors.New("PostgreSQL URL is invalid")
	}
	if strings.TrimPrefix(parsed.EscapedPath(), "/") == "" {
		return errors.New("PostgreSQL URL must name a database")
	}
	return nil
}

func ensureMigrationLock(ctx context.Context, db *sql.DB) error {
	for {
		err := createMigrationLock(ctx, db)
		if err == nil {
			return nil
		}
		if !isConcurrentBootstrapError(err) {
			return err
		}

		timer := time.NewTimer(bootstrapRetryDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func createMigrationLock(ctx context.Context, db *sql.DB) error {
	statements := []string{
		`CREATE SCHEMA IF NOT EXISTS control`,
		`CREATE TABLE IF NOT EXISTS control.schema_migration_lock (
			id smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1)
		)`,
		`INSERT INTO control.schema_migration_lock (id) VALUES (1) ON CONFLICT (id) DO NOTHING`,
	}
	for _, statement := range statements {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

func isConcurrentBootstrapError(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	switch pgErr.Code {
	case "23505", "40P01", "40001", "42710", "42P06", "42P07":
		return true
	default:
		return false
	}
}
