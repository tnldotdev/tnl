package state

import (
	"context"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationPolicyMutationRestoredAccessRollbackAndContiguousHistory(t *testing.T) {
	f := newServicePublicationFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	d, q := f.database, controlstatedb.New(f.database.pool)
	configuration := ProjectServiceConfiguration{Target: "http://127.0.0.1:3000", HTTP: &config.HTTPService{
		Access: &config.Access{Mode: "restricted", IP: []string{"192.0.2.0/24"}},
	}}
	if _, err := d.ConfigureService(ctx, f.service.ID, f.publisher.CreatorID, f.service.ServiceMetadata,
		&configuration, ServiceUpdateConditions{UnconditionalConfiguration: true}, f.now); err != nil {
		t.Fatal(err)
	}
	before, err := q.ReadVisitorPolicyRevision(ctx, f.service.ID)
	if err != nil {
		t.Fatal(err)
	}
	beforeStorage, err := q.GetServiceConfiguration(ctx, f.service.ID)
	if err != nil {
		t.Fatal(err)
	}
	beforeEvents, err := q.ReadVisitorPolicyEvents(ctx,
		controlstatedb.ReadVisitorPolicyEventsParams{ResourceID: f.service.ID, AfterRevision: 0})
	if err != nil {
		t.Fatal(err)
	}
	readMode := func(queries *controlstatedb.Queries, want VisitorAccessMode) {
		t.Helper()
		mode, err := d.serviceHTTPSourcePolicy(ctx, queries, f.service.ID, netip.MustParseAddr("192.0.2.8"))
		if err != nil || mode != want {
			t.Fatal("real saved access settings produced the wrong source policy", mode, want, err)
		}
	}
	lock := func(tx pgx.Tx) {
		t.Helper()
		queries := controlstatedb.New(tx)
		if _, err := queries.LockLocalTeamForMutation(ctx, f.service.TeamID); err != nil {
			t.Fatal(err)
		}
		if _, err := queries.LockService(ctx, f.service.ID); err != nil {
			t.Fatal(err)
		}
	}
	mutate := func(tx pgx.Tx, mode string) {
		t.Helper()
		actual := configuration
		actual.HTTP = &config.HTTPService{Access: &config.Access{Mode: mode, IP: []string{"192.0.2.0/24"}}}
		if err := d.saveServiceConfiguration(ctx, tx, f.service.ID, actual); err != nil {
			t.Fatal(err)
		}
	}
	checkHistory := func(queries *controlstatedb.Queries, count int) {
		t.Helper()
		revision, err := queries.ReadVisitorPolicyRevision(ctx, f.service.ID)
		if err != nil || revision != before+int64(count) {
			t.Fatal("real access mutation advanced the wrong exact revision", revision, count, err)
		}
		events, err := queries.ReadVisitorPolicyEvents(ctx,
			controlstatedb.ReadVisitorPolicyEventsParams{ResourceID: f.service.ID, AfterRevision: before})
		if err != nil || len(events) != count {
			t.Fatal("access revision does not cover exactly its committed history", len(events), count, err)
		}
		for index, event := range events {
			if event.Revision != before+int64(index)+1 || !event.ChangedAt.Valid {
				t.Fatal("actual access-mutation history has a gap or lacks its change time")
			}
		}
	}
	readMode(q, VisitorAccessRestricted)
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, tx)
	lock(tx)
	mutate(tx, "anonymous")
	readMode(controlstatedb.New(tx), VisitorAccessAnonymous)
	checkHistory(controlstatedb.New(tx), 1)
	// the same real mutation is invisible outside its transaction.
	readMode(q, VisitorAccessRestricted)
	checkHistory(q, 0)
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	readMode(q, VisitorAccessRestricted)
	checkHistory(q, 0)
	afterStorage, err := q.GetServiceConfiguration(ctx, f.service.ID)
	if err != nil || !reflect.DeepEqual(afterStorage, beforeStorage) {
		t.Fatal("rolled-back access mutation changed encrypted settings", err)
	}
	afterEvents, err := q.ReadVisitorPolicyEvents(ctx,
		controlstatedb.ReadVisitorPolicyEventsParams{ResourceID: f.service.ID, AfterRevision: 0})
	if err != nil || !reflect.DeepEqual(afterEvents, beforeEvents) {
		t.Fatal("rolled-back actual access mutation changed existing history", err)
	}
	committed, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, committed)
	lock(committed)
	for index, mode := range []string{"anonymous", "restricted", "anonymous"} {
		mutate(committed, mode)
		readMode(controlstatedb.New(committed), VisitorAccessMode(mode))
		checkHistory(controlstatedb.New(committed), index+1)
	}
	readMode(q, VisitorAccessRestricted)
	checkHistory(q, 0)
	if err := committed.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	readMode(q, VisitorAccessAnonymous)
	checkHistory(q, 3)
	committedEvents, err := q.ReadVisitorPolicyEvents(ctx,
		controlstatedb.ReadVisitorPolicyEventsParams{ResourceID: f.service.ID, AfterRevision: 0})
	if err != nil || len(committedEvents) != len(beforeEvents)+3 ||
		!reflect.DeepEqual(committedEvents[:len(beforeEvents)], beforeEvents) {
		t.Fatal("committed access mutations changed the existing history prefix or appended the wrong count", err)
	}
	afterStorage, err = q.GetServiceConfiguration(ctx, f.service.ID)
	if err != nil || reflect.DeepEqual(afterStorage, beforeStorage) {
		t.Fatal("committed real access change did not replace saved configuration", err)
	}
}
