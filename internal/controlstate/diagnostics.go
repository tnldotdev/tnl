package controlstate

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tnldotdev/tnl/internal/failure"
)

// private diagnostic limits are shared with collectors. eight blocker PIDs per
// session keep a maximum-shaped snapshot within 64 KiB, leaving room for eight
// snapshots alongside the benchmark's periodic and failure metrics windows.
const (
	MaxDatabaseDiagnosticSessions   = 64
	MaxDatabaseDiagnosticBlockers   = 8
	MaxDatabaseDiagnosticOperations = 64
	MaxDatabaseDiagnosticBytes      = 64 << 10
)

// PoolStats returns an in-memory snapshot without acquiring a connection.
func (d *Database) PoolStats() *pgxpool.Stat { return d.pool.Stat() }

// DatabaseMetrics contains process-local state that is safe to collect on every
// metrics scrape. it never acquires a database connection.
type DatabaseMetrics struct {
	Pool              *pgxpool.Stat
	ActiveOperations  []DatabaseOperation
	OperationsOmitted int
	Connections       map[string]DatabaseConnectionCounts
}

// Metrics returns one process-local database metrics snapshot.
func (d *Database) Metrics(now time.Time) DatabaseMetrics {
	if d == nil {
		return DatabaseMetrics{}
	}
	result := DatabaseMetrics{}
	if d.pool != nil {
		result.Pool = d.pool.Stat()
	}
	result.ActiveOperations, result.OperationsOmitted = d.activity.snapshotWithOmitted(now)
	result.Connections = d.connections.snapshot()
	return result
}

// DatabaseDiagnostics contains bounded, parameter-free PostgreSQL activity.
type DatabaseDiagnostics struct {
	CapturedAt          time.Time                           `json:"captured_at"`
	Sessions            []DatabaseSession                   `json:"sessions"`
	Truncated           bool                                `json:"truncated"`
	ActiveOperations    []DatabaseOperation                 `json:"active_operations"`
	OperationsTruncated bool                                `json:"operations_truncated"`
	Connections         map[string]DatabaseConnectionCounts `json:"connections,omitempty"`
	Pooler              *DatabasePoolerDiagnostics          `json:"pooler,omitempty"`
	Error               string                              `json:"error,omitempty"`
}

type DatabaseSession struct {
	PID                   int32    `json:"pid"`
	Operation             string   `json:"operation,omitempty"`
	State                 string   `json:"state"`
	WaitType              string   `json:"wait_type"`
	WaitEvent             string   `json:"wait_event"`
	TransactionAgeSeconds *float64 `json:"transaction_age_seconds"`
	QueryAgeSeconds       *float64 `json:"query_age_seconds"`
	QueryID               *int64   `json:"query_id,omitempty"`
	BlockingPIDs          []int32  `json:"blocking_pids"`
	BlockingPIDsTruncated bool     `json:"blocking_pids_truncated"`
}

// Diagnostics uses a separate connection through the configured pooled URL.
// It cannot be starved by the local pgx pool; pooler/database unavailability is
// still bounded by the timeout. it never returns query text or connection data.
func (d *Database) Diagnostics(parent context.Context) (result DatabaseDiagnostics, retErr error) {
	result = DatabaseDiagnostics{CapturedAt: time.Now().UTC(), Sessions: []DatabaseSession{}}
	local := d.Metrics(result.CapturedAt)
	result.ActiveOperations = local.ActiveOperations
	result.OperationsTruncated = local.OperationsOmitted > 0
	result.Connections = local.Connections
	defer func() {
		if retErr != nil {
			result.Error = databaseDiagnosticsMessage(retErr)
		}
	}()
	if err := d.requireOpen(); err != nil {
		return result, databaseDiagnosticsError(parent, err)
	}
	if !d.diagnosticsMu.TryLock() {
		return result, failure.Wrap("collect database diagnostics", failure.ServerDiagnosticsBusy, errors.New("database diagnostics already in progress"))
	}
	defer d.diagnosticsMu.Unlock()
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	// the admin console may remain accessible when regular clients are rejected.
	// its own timeout consumes at most one second of the shared snapshot budget.
	result.Pooler = d.poolerDiagnostics(ctx)
	config := d.dedicatedConnectionConfig(diagnosticConnection)
	connection, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		return result, databaseDiagnosticsError(ctx, err)
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = connection.Close(closeCtx)
	}()
	rows, err := connection.Query(ctx, `
		SELECT pid, COALESCE(state, 'unavailable'), COALESCE(wait_event_type, ''), COALESCE(wait_event, ''),
		       EXTRACT(EPOCH FROM clock_timestamp() - xact_start)::float8,
		       EXTRACT(EPOCH FROM clock_timestamp() - query_start)::float8,
		       query_id, (pg_blocking_pids(pid))[1:$1], COALESCE(substring(query FROM '^-- name: ([A-Za-z0-9_]{1,128})'), '')
		FROM pg_stat_activity
		WHERE datname = current_database() AND pid <> pg_backend_pid() AND state IS DISTINCT FROM 'idle'
		ORDER BY (wait_event_type = 'Lock') DESC NULLS LAST, xact_start NULLS LAST, pid
		LIMIT $2
	`, MaxDatabaseDiagnosticBlockers+1, MaxDatabaseDiagnosticSessions+1)
	if err != nil {
		return result, databaseDiagnosticsError(ctx, err)
	}
	defer rows.Close()
	for rows.Next() {
		var session DatabaseSession
		if err := rows.Scan(&session.PID, &session.State, &session.WaitType, &session.WaitEvent,
			&session.TransactionAgeSeconds, &session.QueryAgeSeconds, &session.QueryID, &session.BlockingPIDs, &session.Operation); err != nil {
			return result, databaseDiagnosticsError(ctx, err)
		}
		if len(result.Sessions) == MaxDatabaseDiagnosticSessions {
			result.Truncated = true
			break
		}
		if _, known := diagnosticQueryNames[session.Operation]; !known {
			session.Operation = "unknown"
		}
		if len(session.BlockingPIDs) > MaxDatabaseDiagnosticBlockers {
			session.BlockingPIDsTruncated = true
			session.BlockingPIDs = session.BlockingPIDs[:MaxDatabaseDiagnosticBlockers]
		}
		result.Sessions = append(result.Sessions, session)
	}
	if err := rows.Err(); err != nil {
		return result, databaseDiagnosticsError(ctx, err)
	}
	return result, nil
}

func databaseDiagnosticsError(ctx context.Context, err error) error {
	if cause := context.Cause(ctx); cause != nil {
		err = errors.Join(err, cause)
	}
	return failure.Wrap("collect database diagnostics", failure.ServerDatabaseDiagnosticsUnavailable, err)
}

var diagnosticSQLState = regexp.MustCompile(`^[0-9A-Z]{5}$`)

func databaseDiagnosticsMessage(err error) string {
	message := failure.SafeMessage(err, failure.ServerDatabaseDiagnosticsUnavailable)
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) && diagnosticSQLState.MatchString(postgresError.Code) {
		message += fmt.Sprintf("; PostgreSQL error %s", postgresError.Code)
	}
	return message
}
