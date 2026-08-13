package controlstate

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PoolStats returns an in-memory snapshot without acquiring a connection.
func (d *Database) PoolStats() *pgxpool.Stat { return d.pool.Stat() }

// DatabaseDiagnostics contains bounded, parameter-free PostgreSQL activity.
type DatabaseDiagnostics struct {
	CapturedAt time.Time         `json:"captured_at"`
	Sessions   []DatabaseSession `json:"sessions"`
	Truncated  bool              `json:"truncated"`
}

type DatabaseSession struct {
	PID                   int32   `json:"pid"`
	Operation             string  `json:"operation,omitempty"`
	State                 string  `json:"state"`
	WaitType              string  `json:"wait_type"`
	WaitEvent             string  `json:"wait_event"`
	TransactionAgeSeconds float64 `json:"transaction_age_seconds"`
	QueryAgeSeconds       float64 `json:"query_age_seconds"`
	QueryID               *int64  `json:"query_id,omitempty"`
	BlockingPIDs          []int32 `json:"blocking_pids"`
}

// Diagnostics uses a separate connection through the configured pooled URL.
// It cannot be starved by the local pgx pool; pooler/database unavailability is
// still bounded by the timeout. It never returns query text or connection data.
func (d *Database) Diagnostics(parent context.Context) (DatabaseDiagnostics, error) {
	if err := d.requireOpen(); err != nil {
		return DatabaseDiagnostics{}, err
	}
	if !d.diagnosticsMu.TryLock() {
		return DatabaseDiagnostics{}, errors.New("database diagnostics already in progress")
	}
	defer d.diagnosticsMu.Unlock()
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	connection, err := pgx.ConnectConfig(ctx, d.pool.Config().ConnConfig.Copy())
	if err != nil {
		return DatabaseDiagnostics{}, databaseDiagnosticsError(ctx, err)
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = connection.Close(closeCtx)
	}()
	rows, err := connection.Query(ctx, `
		SELECT pid, COALESCE(state, 'unavailable'), COALESCE(wait_event_type, ''), COALESCE(wait_event, ''),
		       COALESCE(EXTRACT(EPOCH FROM clock_timestamp() - xact_start), 0)::float8,
		       COALESCE(EXTRACT(EPOCH FROM clock_timestamp() - query_start), 0)::float8,
		       query_id, pg_blocking_pids(pid), COALESCE(substring(query FROM '^-- name: ([A-Za-z0-9_]{1,128})'), '')
		FROM pg_stat_activity
		WHERE datname = current_database() AND pid <> pg_backend_pid() AND state IS DISTINCT FROM 'idle'
		ORDER BY (wait_event_type = 'Lock') DESC NULLS LAST, xact_start NULLS LAST, pid
		LIMIT 65
	`)
	if err != nil {
		return DatabaseDiagnostics{}, databaseDiagnosticsError(ctx, err)
	}
	defer rows.Close()
	result := DatabaseDiagnostics{CapturedAt: time.Now().UTC(), Sessions: []DatabaseSession{}}
	for rows.Next() {
		var session DatabaseSession
		if err := rows.Scan(&session.PID, &session.State, &session.WaitType, &session.WaitEvent,
			&session.TransactionAgeSeconds, &session.QueryAgeSeconds, &session.QueryID, &session.BlockingPIDs, &session.Operation); err != nil {
			return DatabaseDiagnostics{}, databaseDiagnosticsError(ctx, err)
		}
		if len(result.Sessions) == 64 {
			result.Truncated = true
			break
		}
		result.Sessions = append(result.Sessions, session)
	}
	if err := rows.Err(); err != nil {
		return DatabaseDiagnostics{}, databaseDiagnosticsError(ctx, err)
	}
	return result, nil
}

func databaseDiagnosticsError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return fmt.Errorf("database diagnostics: %w", ctx.Err())
	}
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		return fmt.Errorf("database diagnostics: PostgreSQL error %s", postgresError.Code)
	}
	return errors.New("database diagnostics: connection or query unavailable")
}
