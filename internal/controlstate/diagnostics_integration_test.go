package controlstate

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tnldotdev/tnl/internal/observability"
)

func TestIntegrationDatabaseMetricsDuringPoolExhaustion(t *testing.T) {
	_, databaseURL, _ := newControlStateIntegrationDatabaseWithURL(t, "pool_diagnostics")
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.MaxConns = 1
	activity := new(queryActivity)
	connections := new(connectionActivity)
	config.ConnConfig.Tracer = &connectionTracer{connections: connections, purpose: requestPoolConnection, queries: activity}
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	database := &Database{pool: pool, activity: activity, connections: connections}
	held, err := pool.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()
	waitCtx, cancel := context.WithTimeout(t.Context(), 25*time.Millisecond)
	defer cancel()
	if _, err := pool.Acquire(waitCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("exhausted acquire: %v", err)
	}
	metrics := observability.New("control")
	metrics.RegisterDatabase(func(now time.Time) observability.DatabaseSnapshot {
		local := database.Metrics(now)
		result := observability.DatabaseSnapshot{
			Pool: local.Pool, OperationsOmitted: local.OperationsOmitted,
			Connections:      make(map[string]observability.DatabaseConnectionSnapshot, len(local.Connections)),
			ActiveOperations: make([]observability.DatabaseOperationSnapshot, len(local.ActiveOperations)),
		}
		for purpose, counts := range local.Connections {
			result.Connections[purpose] = observability.DatabaseConnectionSnapshot{
				Open: counts.Open, Connecting: counts.Connecting, Opened: counts.Opened,
				Closed: counts.Closed, Failed: counts.Failed,
			}
		}
		for index, operation := range local.ActiveOperations {
			result.ActiveOperations[index] = observability.DatabaseOperationSnapshot{
				Operation: operation.Operation, ElapsedSeconds: operation.ElapsedSeconds,
			}
		}
		return result
	})
	response := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
	for _, want := range []string{
		"tnl_database_pool_acquired_connections 1", "tnl_database_pool_max_connections 1",
		"tnl_database_pool_idle_connections 0", "tnl_database_pool_canceled_acquires_total 1",
	} {
		if !strings.Contains(response.Body.String(), want) {
			t.Errorf("metrics missing %q", want)
		}
	}
	for _, purpose := range []string{"diagnostics", "pooler_diagnostics"} {
		if counts := database.Metrics(time.Now()).Connections[purpose]; counts != (DatabaseConnectionCounts{}) {
			t.Fatalf("metrics scrape opened %s connection: %+v", purpose, counts)
		}
	}
	ctx, stop := context.WithTimeout(t.Context(), time.Second)
	defer stop()
	if _, err := database.Diagnostics(ctx); err != nil {
		t.Fatalf("snapshot was starved by local pool: %v", err)
	}
}

func TestIntegrationDatabaseDiagnosticsMarksOmittedBlockers(t *testing.T) {
	database, databaseURL, _ := newControlStateIntegrationDatabaseWithURL(t, "diagnostic_blocker_limit")
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	var blockers []pgx.Tx
	for range MaxDatabaseDiagnosticBlockers + 1 {
		// Separate connections keep this independent of the test machine's pool
		// size. They model concurrent shared lock holders, not request activity.
		connection, err := pgx.Connect(ctx, databaseURL)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close(context.Background())
		blocker, err := connection.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer rollbackTestTransaction(t, blocker)
		if _, err := blocker.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(987654321)`); err != nil {
			t.Fatal(err)
		}
		blockers = append(blockers, blocker)
	}
	waitCtx, cancelWait := context.WithCancel(ctx)
	defer cancelWait()
	done := make(chan error, 1)
	workers := newIntegrationWorkers(t, cancelWait)
	defer workers.stop()
	workers.Go(func() { _, err := database.pool.Exec(waitCtx, `SELECT pg_advisory_xact_lock(987654321)`); done <- err })
	waiterPID := waitForPostgresBlock(t, ctx, database, int32(blockers[0].Conn().PgConn().PID()), done)
	for _, omitted := range []bool{true, false} {
		if !omitted {
			if err := blockers[len(blockers)-1].Rollback(ctx); err != nil {
				t.Fatal(err)
			}
		}
		snapshot, err := database.Diagnostics(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if snapshot.Truncated {
			t.Fatal("blocker truncation incorrectly marked session list truncated")
		}
		found := false
		for _, session := range snapshot.Sessions {
			if session.PID != waiterPID {
				continue
			}
			found = true
			if len(session.BlockingPIDs) != MaxDatabaseDiagnosticBlockers || session.BlockingPIDsTruncated != omitted {
				t.Fatalf("blocker boundary omitted=%t: %+v", omitted, session)
			}
		}
		if !found {
			t.Fatal("snapshot omitted the blocked query")
		}
	}
	cancelWait()
	if err := awaitIntegrationResult(t, ctx, done); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel waiter: %v", err)
	}
}

func TestIntegrationDatabaseDiagnosticsIdentifyBlockingTransaction(t *testing.T) {
	database, _ := newControlStateIntegrationDatabase(t, "blocking_diagnostics")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if _, err := database.pool.Exec(ctx, "CREATE TABLE diagnostic_lock (id integer PRIMARY KEY, secret text); INSERT INTO diagnostic_lock VALUES (1, 'do-not-export')"); err != nil {
		t.Fatal(err)
	}
	blocker, err := database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(context.Background())
	if _, err := blocker.Exec(ctx, "UPDATE diagnostic_lock SET secret = 'do-not-export' WHERE id = 1"); err != nil {
		t.Fatal(err)
	}
	blockerPID := int32(blocker.Conn().PgConn().PID())
	done := make(chan error, 1)
	workers := newIntegrationWorkers(t, cancel)
	workers.Go(func() {
		_, err := database.pool.Exec(ctx, "-- name: BlockedDiagnostic :exec\nUPDATE diagnostic_lock SET secret = 'do-not-export-either' WHERE id = 1")
		done <- err
	})
	waiterPID := waitForPostgresBlock(t, ctx, database, blockerPID, done)
	snapshot, err := database.Diagnostics(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, session := range snapshot.Sessions {
		if session.PID == waiterPID && session.WaitType == "Lock" && session.Operation == "unknown" && slices.Contains(session.BlockingPIDs, blockerPID) {
			found = true
		}
	}
	if !found {
		t.Fatalf("blocking relationship missing: %+v", snapshot)
	}
	data, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "do-not-export") || strings.Contains(string(data), "UPDATE") {
		t.Fatalf("snapshot exposed query text: %s", data)
	}
	if err := blocker.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, done); err != nil {
		t.Fatal(err)
	}
}
