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
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	database := &Database{pool: pool}
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
	metrics.RegisterDatabasePool(database.PoolStats)
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
	ctx, stop := context.WithTimeout(t.Context(), time.Second)
	defer stop()
	if _, err := database.Diagnostics(ctx); err != nil {
		t.Fatalf("snapshot was starved by local pool: %v", err)
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
		if session.PID == waiterPID && session.WaitType == "Lock" && session.Operation == "BlockedDiagnostic" && slices.Contains(session.BlockingPIDs, blockerPID) {
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
