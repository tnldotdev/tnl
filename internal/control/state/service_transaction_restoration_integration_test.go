package state

import (
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationServiceRestoredTargetClosureAndAuditRollback(t *testing.T) {
	f := newServicePublicationFixture(t)
	prepareServingPublisher(t, f)
	ctx := t.Context()
	q := controlstatedb.New(f.database.pool)
	beforeService, err := q.GetService(ctx, f.service.ID)
	if err != nil {
		t.Fatal(err)
	}
	beforeRun, err := q.LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: f.run.RunID, ServiceID: f.service.ID})
	if err != nil {
		t.Fatal(err)
	}
	before, digest, err := f.database.GetServiceConfiguration(ctx, f.service.ID, f.actor(t))
	if err != nil || before == nil {
		t.Fatal(err)
	}
	var beforeAudit int
	if err := f.database.pool.QueryRow(ctx, `SELECT count(*) FROM control.service_audit_events WHERE service_id=$1`,
		f.service.ID).Scan(&beforeAudit); err != nil {
		t.Fatal(err)
	}
	tx, err := f.database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, tx)
	queries := controlstatedb.New(tx)
	if _, err := queries.LockService(ctx, f.service.ID); err != nil {
		t.Fatal(err)
	}
	replacement := *before
	replacement.Target = "rollback-target.internal:4999"
	if err := f.database.saveServiceConfiguration(ctx, tx, f.service.ID, replacement); err != nil {
		t.Fatal(err)
	}
	run, err := queries.LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: f.run.RunID, ServiceID: f.service.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := closeServiceRun(ctx, queries, run, f.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var attempted bool
	if err := tx.QueryRow(ctx, `SELECT run.closed_at IS NOT NULL AND NOT run.assignments_open
		AND EXISTS(SELECT 1 FROM control.service_audit_events event WHERE event.service_id=run.service_id AND event.event_type='run.close')
		FROM control.service_runs run WHERE run.id=$1`, run.ID).Scan(&attempted); err != nil || !attempted {
		t.Fatal("rollback fixture did not actually stage closure and its audit", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	afterService, err := q.GetService(ctx, f.service.ID)
	if err != nil || !reflect.DeepEqual(afterService, beforeService) {
		t.Fatal("rollback retained changed service storage", err)
	}
	afterRun, err := q.LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: f.run.RunID, ServiceID: f.service.ID})
	if err != nil || !reflect.DeepEqual(afterRun, beforeRun) {
		t.Fatal("rollback retained a changed run or closure", err)
	}
	after, nextDigest, err := f.database.GetServiceConfiguration(ctx, f.service.ID, f.actor(t))
	if err != nil || nextDigest != digest || !reflect.DeepEqual(after, before) {
		t.Fatal("rollback retained the changed target or digest", err)
	}
	var audit int
	if err := f.database.pool.QueryRow(ctx, `SELECT count(*) FROM control.service_audit_events WHERE service_id=$1`,
		f.service.ID).Scan(&audit); err != nil || audit != beforeAudit {
		t.Fatal("run closure audit escaped its caller transaction", audit, err)
	}
	assertAssignmentTotals(t, f.database.pool, 2)
}

func TestIntegrationServiceRestoredHeartbeatActivityCleanup(t *testing.T) {
	f := newServicePublicationFixture(t)
	prepareServingPublisher(t, f)
	for _, at := range []time.Time{f.now.Add(time.Second), f.run.ExpiresAt.Add(-time.Second)} {
		state, err := f.database.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, at,
			ServiceRunHealth{Healthy: true, StreamCapacity: 64})
		if err != nil || state.State != "ready" || len(state.Connections) != 2 {
			t.Fatal("heartbeat lost its current ready run or connections", err)
		}
		if operations, truncated := f.database.activity.snapshot(time.Now()); truncated || len(operations) != 0 {
			t.Fatalf("completed heartbeat retained active database operations: %+v", operations)
		}
	}
}
