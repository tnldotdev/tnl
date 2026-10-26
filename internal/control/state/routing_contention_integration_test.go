package state

import (
	"context"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationReadyHeartbeatPublishesRoutingAtCommit(t *testing.T) {
	f := newPublishRunFixture(t)
	readyTestSession(t, f)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	workers := newIntegrationWorkers(t, cancel)
	gate, err := f.database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	defer workers.stop()
	if _, err := controlstatedb.New(gate).LockIngressRoutingTableClock(ctx); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	workers.Go(func() {
		_, err := f.database.HeartbeatPublishRun(ctx, f.authentication(), f.now.Add(time.Second), time.Hour, time.Minute)
		done <- err
	})
	waitForPostgresBlock(t, ctx, f.database, int32(gate.Conn().PgConn().PID()), done)
	operations, _ := f.database.activity.snapshot(time.Now())
	if len(operations) != 1 || operations[0].Operation != "InsertFinalIngressRoutingTableEvent" {
		t.Fatalf("heartbeat clock wait = %+v", operations)
	}
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, done); err != nil {
		t.Fatal(err)
	}
}
