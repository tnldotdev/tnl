package controlstate

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

func TestIntegrationDNSDedicatedWaitExcludedFromPoolActivity(t *testing.T) {
	database, databaseURL, _ := newControlStateIntegrationDatabaseWithURL(t, "dns_activity")
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	observer, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close(context.Background())
	clock, err := observer.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, clock)
	if _, err := controlstatedb.New(clock).LockIngressRoutingTableClock(ctx); err != nil {
		t.Fatal(err)
	}
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	entered, release := make(chan struct{}), make(chan struct{})
	firstDone, secondDone := make(chan error, 1), make(chan error, 1)
	var callbacks atomic.Int32
	const recordName = "_acme-challenge.activity.example.test"
	workers.Go(func() {
		firstDone <- database.WithDNSChallengeLock(ctx, recordName, func() error {
			callbacks.Add(1)
			close(entered)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	})
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	var holderPID int32
	if err := observer.QueryRow(ctx, `SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND granted AND database = (SELECT oid FROM pg_database WHERE datname = current_database())`).Scan(&holderPID); err != nil {
		t.Fatal(err)
	}
	workers.Go(func() {
		secondDone <- database.WithDNSChallengeLock(ctx, recordName, func() error {
			callbacks.Add(1)
			return database.Health(ctx)
		})
	})
	waitForPostgresBlock(t, ctx, database, holderPID, secondDone)
	poolDone := make(chan error, 1)
	workers.Go(func() { _, err := controlstatedb.New(database.pool).LockIngressRoutingTableClock(ctx); poolDone <- err })
	waitForPostgresBlock(t, ctx, database, int32(observer.PgConn().PID()), poolDone)
	active, truncated := database.activity.snapshot(time.Now())
	if truncated || len(active) != 1 || active[0].Operation != "LockIngressRoutingTableClock" {
		t.Fatalf("request-pool activity includes dedicated DNS wait: %+v, truncated=%t", active, truncated)
	}
	if callbacks.Load() != 1 {
		t.Fatal("DNS waiter bypassed advisory lock")
	}
	if err := clock.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, poolDone); err != nil {
		t.Fatal(err)
	}
	if active, _ := database.activity.snapshot(time.Now()); len(active) != 0 {
		t.Fatalf("dedicated wait remains in pool activity: %+v", active)
	}
	close(release)
	for _, done := range []chan error{firstDone, secondDone} {
		if err := awaitIntegrationResult(t, ctx, done); err != nil {
			t.Fatal(err)
		}
	}
	if callbacks.Load() != 2 {
		t.Fatal("DNS callback did not resume")
	}
	var remaining int
	if err := observer.QueryRow(ctx, `SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND database = (SELECT oid FROM pg_database WHERE datname = current_database())`).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("leaked DNS locks = %d, %v", remaining, err)
	}
}
