package controlstate

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

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
func waitForPostgresBlock(t *testing.T, ctx context.Context, database *Database, blocker int32, done <-chan error) int32 {
	t.Helper()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		var pid int32
		err := database.pool.QueryRow(ctx, `
			SELECT pid FROM pg_stat_activity
			WHERE datname = current_database() AND $1::integer = ANY(pg_blocking_pids(pid))
		`, blocker).Scan(&pid)
		if err == nil {
			return pid
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			t.Fatalf("operation ended before blocking on backend %d: %v", blocker, err)
		case <-ctx.Done():
			t.Fatalf("operation did not block on backend %d: %v", blocker, ctx.Err())
		case <-tick.C:
		}
	}
}
