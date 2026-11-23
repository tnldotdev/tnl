package state

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
)

func TestIntegrationPublisherAuditCommitOrderWithoutPreparedStatements(t *testing.T) {
	f := newServicePublicationFixture(t)
	run, db, now := f.run, f.database, f.now
	installPrivateTestCertificate(t, db, f.prepared, run, now)
	f.readyConnections(t, now)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if _, err := db.HeartbeatServiceRun(ctx, run.ServiceID, run.RunID, run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil {
		t.Fatal(err)
	}
	client, err := (PoolConfig{URL: db.pool.Config().ConnString(), DisablePreparedStatements: true}).Open(ctx, testStorageKey, "", naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	gate, err := db.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if err = controlstatedb.New(gate).LockServiceAuditClock(ctx, controlstatedb.LockServiceAuditClockParams{TeamID: text(f.service.TeamID)}); err != nil {
		t.Fatal(err)
	}
	first := serviceaudit.Event{ID: serviceaudit.NewID(), TeamID: f.service.TeamID, ServiceID: run.ServiceID, ServiceKind: "service", EventType: "apply", OccurredAt: now}
	next := serviceaudit.Observation{EventID: serviceaudit.NewID(), ServiceID: run.ServiceID, ServiceKind: "service",
		RunID: run.RunID, RunNumber: run.RunNumber, VisitorConnectionID: mustOpaqueID(t, opaqueid.VisitorConnectionPrefix),
		SourceIP: "192.0.2.1", EventType: "http.decision", Outcome: "allowed", OccurredAt: now}
	send := func(events ...serviceaudit.Observation) (ServiceObservationResult, error) {
		return client.IngestServiceRunObservations(ctx, run.ServiceID, run.RunID, run.Token, run.RunNumber, serviceaudit.Batch{Events: events}, now)
	}
	done := make(chan error, 1)
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	workers.Go(func() { _, err := send(next); done <- err })
	waitForPostgresBlock(t, ctx, db, int32(gate.Conn().PgConn().PID()), done)
	if err = insertServiceAudit(ctx, gate, first, now); err != nil {
		t.Fatal(err)
	}
	if err = gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = awaitIntegrationResult(t, ctx, done); err != nil {
		t.Fatal(err)
	}
	var ordered bool
	if err = db.pool.QueryRow(ctx, `SELECT a.cursor<b.cursor FROM control.service_audit_events a,control.service_audit_events b WHERE a.id=$1 AND b.id=$2`, first.ID, next.EventID).Scan(&ordered); err != nil || !ordered {
		t.Fatal("publisher cursor preceded the transaction that held the clock", err)
	}
	fresh := next
	fresh.EventID = serviceaudit.NewID()
	conflict := next
	conflict.Outcome = "denied"
	if result, err := send(fresh, conflict); !errors.Is(err, ErrServiceAuditAccess) || result != (ServiceObservationResult{}) {
		t.Fatal("conflicting report was acknowledged", result, err)
	}
	if result, err := send(next, fresh, fresh); err != nil || result.Accepted != 1 || result.Duplicates != 2 {
		t.Fatal("conflict left a fresh neighbor or retry changed its count", result, err)
	}
}
