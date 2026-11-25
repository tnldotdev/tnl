package state

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
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/tnldotdev/tnl/internal/control/storagekey"
	"github.com/tnldotdev/tnl/internal/naming"
)

const (
	// serving roles require the latest embedded migration or a newer schema.
	minimumSchemaVersion int64 = 4
	versionTable               = "control.goose_db_version"
	bootstrapRetryDelay        = 25 * time.Millisecond
)

const schemaVersionQuery = `
	SELECT COALESCE(MAX(version_id) FILTER (WHERE is_applied), 0)
	FROM control.goose_db_version
`

// check the supported v1 baseline before upgrading. older layouts also
// reported version 1.
const schemaLayoutQuery = `
	SELECT to_regclass('control.connector_peer_watch_versions') IS NOT NULL
		AND to_regclass('control.registered_key_watch_versions') IS NOT NULL
		AND to_regclass('control.visitor_policy_watch_versions') IS NOT NULL
		AND to_regclass('control.publisher_run_policy_bookmarks') IS NOT NULL
		AND to_regclass('control.run_alias_watch_versions') IS NOT NULL
		AND to_regclass('control.operator_nameserver_hostnames') IS NOT NULL
		AND EXISTS (SELECT 1 FROM pg_catalog.pg_attribute
			WHERE attrelid=to_regclass('control.dns_authorities')
				AND attname='claim_proof_verified_at' AND NOT attisdropped)
		AND EXISTS (SELECT 1 FROM pg_catalog.pg_rewrite r JOIN pg_catalog.pg_depend d
			ON d.classid='pg_rewrite'::regclass AND d.objid=r.oid AND d.refclassid='pg_class'::regclass
			WHERE r.ev_class=to_regclass('control.service_policy_watch_bookmarks')
				AND d.refobjid=to_regclass('control.deployment_management_services'))
		AND EXISTS (SELECT 1 FROM pg_catalog.pg_class
			WHERE oid=to_regclass('control.relay_service_reservations') AND relkind='v')
		AND EXISTS (
			SELECT 1 FROM pg_catalog.pg_proc
			WHERE oid = to_regprocedure('control.visitor_identity_permission(text,text,text,text,text,timestamptz)')
				AND 'grant_id' = ANY(proargnames)
		)`

//go:embed migrations/*.sql
var migrationFiles embed.FS

// Database is the PostgreSQL connection pool for control state. its database
// details remain private to this package.
type Database struct {
	controlOutageTolerance  atomic.Int64
	serviceRunLeaseDuration atomic.Int64
	oidcAdmissions          map[string]configuredAdmission
	projectPublisherLimits  map[string]int
	pool                    *pgxpool.Pool
	publisherAuditSlots     chan struct{}
	storageKey              *storagekey.Keyring
	managedURLMode          naming.ManagedURLMode
	diagnosticsMu           sync.Mutex
	watchBookmarks          watchBookmarkCache
	activity                *queryActivity
	connections             *connectionActivity
}

// Migrate initializes or upgrades the control schema through a direct PostgreSQL URL.
// a persistent table lock allows only one migration at a time. a newer schema
// with the supported baseline is left unchanged.
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
	// only an empty control schema needs bootstrap writes. an existing schema
	// missing its migration metadata must not acquire new tables on rejection.
	var versioned, populated bool
	const hasControlTables = `EXISTS (SELECT 1 FROM pg_catalog.pg_class
		WHERE relnamespace=to_regnamespace('control') AND relkind IN ('r','p','v','m','f')
			AND relname NOT IN ('schema_migration_lock','goose_db_version'))`
	if err := db.QueryRowContext(ctx, `SELECT to_regclass('control.goose_db_version') IS NOT NULL, `+hasControlTables).Scan(&versioned, &populated); err != nil {
		return fmt.Errorf("controlstate: migrate: inspect database: %w", err)
	}
	if !versioned {
		if populated {
			return errors.New("controlstate: incompatible unversioned control schema; use a fresh PostgreSQL database")
		}
		if err := ensureMigrationLock(ctx, db); err != nil {
			return fmt.Errorf("controlstate: migrate: bootstrap lock: %w", err)
		}
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
	if target != minimumSchemaVersion {
		return fmt.Errorf("controlstate: migrate: embedded schema version %d does not match required minimum %d", target, minimumSchemaVersion)
	}
	if current == 0 {
		if err := lockTx.QueryRowContext(ctx, `SELECT `+hasControlTables).Scan(&populated); err != nil {
			return fmt.Errorf("controlstate: migrate: inspect uninitialized database: %w", err)
		}
		if populated {
			return errors.New("controlstate: incompatible version 0 control schema; use a fresh PostgreSQL database")
		}
	} else if err := checkSchemaLayout(lockTx.QueryRowContext(ctx, schemaLayoutQuery)); err != nil {
		return err
	}
	if current < target {
		if _, err := provider.Up(ctx); err != nil {
			return fmt.Errorf("controlstate: migrate database: %w", err)
		}
		current = target
		if err := checkSchemaLayout(lockTx.QueryRowContext(ctx, schemaLayoutQuery)); err != nil {
			return err
		}
	}
	// goose reports the highest recorded version. verify it is applied before
	// returning success, including when this binary has no newer SQL to run.
	var applied int64
	if err := lockTx.QueryRowContext(ctx, schemaVersionQuery).Scan(&applied); err != nil {
		return fmt.Errorf("controlstate: migrate: verify schema version: %w", err)
	}
	if applied != current {
		return fmt.Errorf("controlstate: migrate: expected applied schema version %d, found %d", current, applied)
	}
	if err := lockTx.Commit(); err != nil {
		return fmt.Errorf("controlstate: migrate: release lock: %w", err)
	}
	return nil
}

type PoolConfig struct {
	URL                       string
	DisablePreparedStatements bool
}

// Open uses the default serving pool with prepared statements.
func Open(ctx context.Context, pooledURL, currentStorageKey, previousStorageKey string, mode naming.ManagedURLMode) (*Database, error) {
	return PoolConfig{URL: pooledURL}.Open(ctx, currentStorageKey, previousStorageKey, mode)
}

// Open connects to already-migrated control state. it never creates or migrates schema objects.
func (p PoolConfig) Open(ctx context.Context, currentStorageKey, previousStorageKey string, mode naming.ManagedURLMode) (*Database, error) {
	if mode != naming.ManagedURLModeSimple && mode != naming.ManagedURLModeGenerated {
		return nil, errors.New("controlstate: invalid managed URL mode")
	}
	keyring, err := storagekey.New(currentStorageKey, previousStorageKey)
	if err != nil {
		return nil, fmt.Errorf("controlstate: open: %w", err)
	}
	config, err := p.pgxConfig()
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
	database := &Database{
		pool: pool, storageKey: keyring, managedURLMode: mode, activity: activity, connections: connections,
		// leave room for watch comparisons and run updates when one team's
		// audit writers are queued on its commit-order lock.
		publisherAuditSlots: make(chan struct{}, max(1, config.MaxConns-2)),
	}
	var missingGuestKey bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.guest_trials
		WHERE expires_at > now() AND source_ip_key_id <> $1 AND source_ip_key_id <> $2)`,
		keyring.CurrentID(), keyring.PreviousID()).Scan(&missingGuestKey); err != nil || missingGuestKey {
		pool.Close()
		if err != nil {
			return nil, fmt.Errorf("controlstate: check guest verifier keys: %w", err)
		}
		return nil, errors.New("controlstate: previous storage key is still needed by active guest trials")
	}
	return database, nil
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

// newer migrations must keep queries and row shapes used by older binaries valid.
func checkSchemaVersion(ctx context.Context, database schemaVersionQuerier) error {
	version, err := readSchemaVersion(ctx, database)
	if err != nil {
		return err
	}
	if version < minimumSchemaVersion {
		return fmt.Errorf("controlstate: incompatible database schema version %d; required minimum is %d", version, minimumSchemaVersion)
	}
	return checkSchemaLayout(database.QueryRow(ctx, schemaLayoutQuery))
}

func checkSchemaLayout(row interface{ Scan(...any) error }) error {
	var current bool
	if err := row.Scan(&current); err != nil {
		return fmt.Errorf("controlstate: check schema layout: %w", err)
	}
	if !current {
		return errors.New("controlstate: incompatible version 1 database schema; use a fresh PostgreSQL database")
	}
	return nil
}

type schemaVersionQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func readSchemaVersion(ctx context.Context, database schemaVersionQuerier) (int64, error) {
	var version int64
	if err := database.QueryRow(ctx, schemaVersionQuery).Scan(&version); err != nil {
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

func (p PoolConfig) pgxConfig() (*pgxpool.Config, error) {
	if err := validateDatabaseURL(p.URL); err != nil {
		return nil, err
	}
	parsed, _ := url.Parse(p.URL) // validated above.
	parameters := parsed.Query()
	if !parameters.Has("pool_max_conns") {
		parameters.Set("pool_max_conns", "8")
		parsed.RawQuery = parameters.Encode()
	}
	config, err := pgxpool.ParseConfig(parsed.String())
	if err != nil {
		return nil, fmt.Errorf("configure PostgreSQL URL: %w", err)
	}
	if p.DisablePreparedStatements {
		config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeExec
	} else {
		if config.ConnConfig.StatementCacheCapacity < 1 {
			return nil, errors.New("prepared statements require a positive statement_cache_capacity; set --disable-prepared-statements to use ordinary execution")
		}
		config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeCacheStatement
	}
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
