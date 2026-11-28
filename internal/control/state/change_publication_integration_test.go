package state

import (
	"context"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
)

func TestIntegrationChangePublicationDoesNotHoldAnotherOperation(t *testing.T) {
	f := newServicePublicationFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	var initial int64
	if err := f.database.pool.QueryRow(ctx, `SELECT COALESCE((SELECT revision FROM control.read_dependency_versions WHERE topic='ingress' AND bucket=-1),0)`).Scan(&initial); err != nil {
		t.Fatal(err)
	}
	slow, err := f.database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, slow)
	event := serviceaudit.Event{ID: serviceaudit.NewID(), TeamID: f.service.TeamID, ServiceID: f.service.ID,
		ServiceKind: "service", EventType: "apply", OccurredAt: f.now}
	if err := insertServiceAudit(ctx, slow, event, f.now); err != nil {
		t.Fatal(err)
	}
	// these represent the shared rows touched by different publishers on a team.
	// queue both before pausing this operation, then commit another operation.
	if _, err := slow.Exec(ctx, `SELECT control.queue_change_publication('registered_key',ARRAY[$1,'','']),
	    control.queue_change_publication('read_dependency',ARRAY['ingress','-1'])`, f.service.TeamID); err != nil {
		t.Fatal(err)
	}
	progress, stop := context.WithTimeout(ctx, 2*time.Second)
	defer stop()
	fast, err := f.database.pool.Begin(progress)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, fast)
	next := event
	next.ID = serviceaudit.NewID()
	if err := insertServiceAudit(progress, fast, next, f.now); err != nil {
		t.Fatal("a slow operation held the audit cursor during insertion", err)
	}
	if _, err := fast.Exec(progress, `SELECT control.queue_change_publication('registered_key',ARRAY[$1,'','']),
	    control.queue_change_publication('read_dependency',ARRAY['ingress','-1'])`, f.service.TeamID); err != nil {
		t.Fatal("a slow operation held shared counters", err)
	}
	if err := controlstatedb.New(fast).FlushChangePublications(progress); err != nil {
		t.Fatal("final authorization could not flush pending projections", err)
	}
	if err := fast.Commit(progress); err != nil {
		t.Fatal("a slow operation blocked another commit", err)
	}
	var before int64
	if err := f.database.pool.QueryRow(ctx, `SELECT revision FROM control.read_dependency_versions WHERE topic='ingress' AND bucket=-1`).Scan(&before); err != nil || before != initial+1 {
		t.Fatal("immediate constraints published a change more than once", initial, before, err)
	}
	if err := slow.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var ordered bool
	var after int64
	if err := f.database.pool.QueryRow(ctx, `SELECT earlier.cursor<later.cursor
	    FROM control.service_audit_events earlier,control.service_audit_events later
	    WHERE earlier.id=$1 AND later.id=$2`, next.ID, event.ID).Scan(&ordered); err != nil || !ordered {
		t.Fatal("cursor pagination would skip the late commit", err)
	}
	if err := f.database.pool.QueryRow(ctx, `SELECT revision FROM control.read_dependency_versions WHERE topic='ingress' AND bucket=-1`).Scan(&after); err != nil || after != before+1 {
		t.Fatal("the late commit lost its cache invalidation", before, after, err)
	}
	var pending int
	if err := f.database.pool.QueryRow(ctx, `SELECT count(*) FROM control.pending_change_publications`).Scan(&pending); err != nil || pending != 0 {
		t.Fatal("commits left a durable change backlog", pending, err)
	}
}
