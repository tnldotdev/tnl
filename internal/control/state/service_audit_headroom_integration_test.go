package state

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
)

func TestIntegrationBlockedPublisherAuditLeavesWatchPoolHeadroom(t *testing.T) {
	f := newServicePublicationFixture(t)
	db, run, now := f.database, f.run, f.now
	installPrivateTestCertificate(t, db, f.prepared, run, now)
	f.readyConnections(t, now)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if _, err := db.HeartbeatServiceRun(ctx, run.ServiceID, run.RunID, run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(db.pool.Config().ConnString())
	if err != nil {
		t.Fatal(err)
	}
	params := u.Query()
	params.Set("pool_max_conns", "3")
	u.RawQuery = params.Encode()
	caller, err := Open(ctx, u.String(), testStorageKey, "", naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	defer caller.Close()
	if err := caller.AuthorizeConnectorPeerWatch(ctx, run.ServiceID, run.RunID, run.RunNumber, run.Token, now); err != nil {
		t.Fatal(err)
	}
	blocker, err := db.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, blocker)
	if err := controlstatedb.New(blocker).LockServiceAuditClock(ctx, controlstatedb.LockServiceAuditClockParams{TeamID: text(f.service.TeamID)}); err != nil {
		t.Fatal(err)
	}
	event := serviceaudit.Observation{EventID: serviceaudit.NewID(), RunID: run.RunID, RunNumber: run.RunNumber,
		ServiceID: run.ServiceID, ServiceKind: "service", VisitorConnectionID: mustOpaqueID(t, opaqueid.VisitorConnectionPrefix),
		EventType: "http.decision", OccurredAt: now, SourceIP: "192.0.2.10", Outcome: "allowed"}
	send := func(ctx context.Context, e serviceaudit.Observation) error {
		_, err := caller.IngestServiceRunObservations(ctx, run.ServiceID, run.RunID, run.Token, run.RunNumber, serviceaudit.Batch{Events: []serviceaudit.Observation{e}}, now)
		return err
	}
	done := make(chan error, 1)
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	workers.Go(func() { done <- send(ctx, event) })
	waitForPostgresBlock(t, ctx, db, int32(blocker.Conn().PgConn().PID()), done)
	before := caller.pool.Stat().AcquireCount()
	next := event
	next.EventID = serviceaudit.NewID()
	budget, stop := context.WithTimeout(ctx, 50*time.Millisecond)
	err = send(budget, next)
	stop()
	if !errors.Is(err, context.DeadlineExceeded) || caller.pool.Stat().AcquireCount() != before {
		t.Fatal("queued report acquired a database connection or escaped its deadline", err)
	}
	if _, err = caller.CompareConnectorPeerWatchVersions(ctx, []ConnectorPeerWatchVersion{{RunID: run.RunID, Revision: -1}}); err != nil {
		t.Fatal("blocked publisher reports stalled an authorized watch", err)
	}
	if err = blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = awaitIntegrationResult(t, ctx, done); err != nil {
		t.Fatal(err)
	}
	var stored bool
	if err = db.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.service_audit_events WHERE id=$1)`, next.EventID).Scan(&stored); err != nil || stored {
		t.Fatal("expired report appeared in the audit log", err)
	}
	if err = send(ctx, next); err != nil {
		t.Fatal("report could not use the released slot", err)
	}
}
