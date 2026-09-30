package controlstate

import (
	"context"
	"encoding/pem"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/testutil"
)

const testStorageKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func newDisposableControlStateDatabaseURL(t *testing.T, suffix string) string {
	t.Helper()
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	return testutil.NewDisposablePostgresDatabaseURL(t, "controlstate_"+suffix)
}

// Register after opening the database so workers are joined before the pool is
// closed. Tests that hand a transaction to a worker also defer stop after its
// rollback defer: cancel and join the worker before reusing its pgx connection
// for rollback. All waits and transaction cleanup have independent bounds.
type integrationWorkers struct {
	sync.WaitGroup
	t        *testing.T
	cancel   context.CancelFunc
	joinOnce sync.Once
	done     chan struct{}
}

func newIntegrationWorkers(t *testing.T, cancel context.CancelFunc) *integrationWorkers {
	t.Helper()
	workers := &integrationWorkers{t: t, cancel: cancel, done: make(chan struct{})}
	t.Cleanup(workers.stop)
	return workers
}

func (workers *integrationWorkers) stop() {
	workers.t.Helper()
	workers.cancel()
	workers.joinOnce.Do(func() { go func() { workers.Wait(); close(workers.done) }() })
	select {
	case <-workers.done:
	case <-time.After(5 * time.Second):
		workers.t.Error("integration workers did not stop within five seconds of cancellation")
	}
}

func rollbackTestTransaction(t *testing.T, tx pgx.Tx) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		t.Errorf("rollback test transaction: %v", err)
	}
}

func awaitIntegrationResult[T any](t *testing.T, ctx context.Context, done <-chan T) T {
	t.Helper()
	select {
	case result := <-done:
		return result
	case <-ctx.Done():
		t.Fatalf("waiting for integration worker: %v", ctx.Err())
		var zero T
		return zero
	}
}

func decodeTestPEM(t *testing.T, data []byte, kind string) (*pem.Block, []byte) {
	t.Helper()
	block, rest := pem.Decode(data)
	if block == nil || block.Type != kind {
		t.Fatalf("expected %s PEM block", kind)
	}
	return block, rest
}

func newControlStateIntegrationDatabase(t *testing.T, suffix string) (*Database, time.Time) {
	t.Helper()
	database, _, now := newControlStateIntegrationDatabaseWithURL(t, suffix)
	return database, now
}

func newControlStateIntegrationDatabaseWithURL(t *testing.T, suffix string) (*Database, string, time.Time) {
	t.Helper()
	databaseURL := newDisposableControlStateDatabaseURL(t, suffix)
	if err := Migrate(t.Context(), databaseURL); err != nil {
		t.Fatal(err)
	}
	database, err := Open(t.Context(), databaseURL, testStorageKey, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(database.Close)
	return database, databaseURL, time.Now().UTC().Truncate(time.Second)
}

// Poll PostgreSQL's actual wait graph, rather than assuming a goroutine has
// reached a lock after an arbitrary scheduling delay.
func waitForPostgresBlock(t *testing.T, ctx context.Context, database *Database, blocker int32, done <-chan error, otherBlockers ...int32) int32 {
	t.Helper()
	blockers := append([]int32{blocker}, otherBlockers...)
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		var pid int32
		err := database.pool.QueryRow(ctx, `
			SELECT pid FROM pg_stat_activity
			WHERE datname = current_database() AND pg_blocking_pids(pid) && $1::integer[]
		`, blockers).Scan(&pid)
		if err == nil {
			return pid
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			t.Fatalf("operation ended before blocking on backends %v: %v", blockers, err)
		case <-ctx.Done():
			t.Fatalf("operation did not block on backends %v: %v", blockers, ctx.Err())
		case <-tick.C:
		}
	}
}
