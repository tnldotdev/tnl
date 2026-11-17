package state

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/failure"
)

func TestIntegrationPartialRecoveryRestoredStartupRequiresTwoLogicalServices(t *testing.T) {
	f := newServicePublicationFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	d, now := f.database, f.now
	if err := d.CloseServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, now); err != nil {
		t.Fatal(err)
	}
	first, second := f.run.Connections[0], f.run.Connections[1]
	if _, err := d.BeginRelayDrain(ctx, f.leases[first.RelayServiceID].RelayLeaseIdentity,
		now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	probe, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, probe)
	available, _, err := availableRelayServicePlacements(ctx, controlstatedb.New(probe), now)
	if err != nil || len(available) != 1 || available[0].relayServiceID != second.RelayServiceID ||
		available[0].capacity < 2 || available[0].assignments != 0 {
		t.Fatal("startup contrast needs one logical service with room for both slots", err)
	}
	if err := probe.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	prepared, err := d.PrepareServiceRun(ctx, f.service.ID, f.publisher, "one-service-startup", now,
		ServiceRunRequest{Metadata: f.service.ServiceMetadata})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.StartServiceRun(ctx, f.service.ID, prepared.RunID, prepared.RunNumber,
		f.publisher, now); !failure.Only(err, ErrInsufficientRelayServices) {
		t.Fatal("new publication did not require two distinct logical relay services", err)
	}
	var unchanged bool
	if err := d.pool.QueryRow(ctx, `SELECT state='prepared' AND started_at IS NULL AND
		NOT EXISTS(SELECT 1 FROM control.service_connection_slots slot WHERE slot.service_run_id=run.id)
		FROM control.service_runs run WHERE run.id=$1`, prepared.RunID).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("denied one-service startup left a partially started publication", err)
	}
	assertRestoredAssignmentState(t, ctx, d.pool, 0)
}

func TestIntegrationPartialRecoveryRestoredEstablishedRunUsesOneReturningRelay(t *testing.T) {
	d, now := newRelayLifecycleDatabase(t)
	f, registrations := newRelayLifecycleServiceFixture(t, d, now)
	installPrivateTestCertificate(t, d, f.prepared, f.run, now)
	f.readyConnections(t, now)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	health := ServiceRunHealth{Healthy: true, StreamCapacity: 64}
	heartbeat := func(at time.Time) ServiceRunState {
		t.Helper()
		run, err := d.HeartbeatServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, at, health)
		if err != nil || run.ServiceID != f.service.ID || run.RunID != f.run.RunID ||
			run.RunNumber != f.run.RunNumber || len(run.Connections) != 2 {
			t.Fatal("established recovery changed the exact publication or assignment count", err)
		}
		return run
	}
	initial := heartbeat(now)
	if initial.State != "ready" || initial.Connections[0].State != "ready" || initial.Connections[1].State != "ready" {
		t.Fatal("partial recovery fixture never established the certified two-relay run")
	}
	first, second := initial.Connections[0], initial.Connections[1]
	if first.RelayServiceID == second.RelayServiceID || first.ConnectionSlot == second.ConnectionSlot {
		t.Fatal("established run did not start with distinct relay services and slots")
	}
	slotFor := func(run ServiceRunState, slot int16) ServiceRunAssignment {
		t.Helper()
		var result ServiceRunAssignment
		found := false
		for _, connection := range run.Connections {
			if connection.ConnectionSlot == slot {
				if found {
					t.Fatal("recovery returned the same slot twice")
				}
				result, found = connection, true
			}
		}
		if !found {
			t.Fatal("recovery omitted an established connection slot")
		}
		return result
	}
	at := now.Add(2 * time.Minute)
	// expire only these two actual process leases at the recovery boundary.
	// the publisher keeps renewing its original run before that boundary.
	expired, err := d.pool.Exec(ctx, `UPDATE control.relay_leases SET lease_expires_at=$1
		WHERE relay_id=ANY($2::text[])`, at, []string{
		f.leases[first.RelayServiceID].RelayID, f.leases[second.RelayServiceID].RelayID,
	})
	if err != nil || expired.RowsAffected() != 2 {
		t.Fatal("fixture did not select exactly the two original relay leases", err)
	}
	for _, elapsed := range []time.Duration{30 * time.Second, time.Minute, 90 * time.Second} {
		kept := heartbeat(now.Add(elapsed))
		a, b := slotFor(kept, first.ConnectionSlot), slotFor(kept, second.ConnectionSlot)
		if kept.State != "ready" || a.PublisherConnectionID != first.PublisherConnectionID ||
			a.Revision != first.Revision || a.State != "ready" ||
			b.PublisherConnectionID != second.PublisherConnectionID || b.Revision != second.Revision || b.State != "ready" {
			t.Fatal("live lease renewal changed the established pair before the outage")
		}
	}
	returnRelay := func(service string, returnedAt time.Time) RelayLease {
		t.Helper()
		for _, original := range registrations {
			if original.RelayServiceID != service {
				continue
			}
			original.RelayRunID += "-partial-return"
			lease, err := d.RegisterRelay(ctx, original, returnedAt, time.Hour)
			if err != nil || lease.RelayLeaseRevision != f.leases[service].RelayLeaseRevision+1 {
				t.Fatal("actual returning relay did not receive its next process lease", err)
			}
			f.leases[service] = lease
			return lease
		}
		t.Fatal("returning relay was not one of the actual original services")
		return RelayLease{}
	}
	secondLease := returnRelay(second.RelayServiceID, at)
	recovered := heartbeat(at)
	unavailable, replacement := slotFor(recovered, first.ConnectionSlot), slotFor(recovered, second.ConnectionSlot)
	if unavailable.PublisherConnectionID != first.PublisherConnectionID || unavailable.Revision != first.Revision ||
		unavailable.RelayServiceID != first.RelayServiceID || unavailable.State != "closed" {
		t.Fatal("unavailable first slot lost its retired identity or borrowed the returning service")
	}
	// an established run must make safe incremental progress; do not replace
	// this expectation with both old slots unchanged until the other relay returns.
	if replacement.PublisherConnectionID == second.PublisherConnectionID || replacement.Revision != second.Revision+1 ||
		replacement.RelayServiceID != second.RelayServiceID || replacement.State != "assigned" {
		t.Fatal("one returning relay did not receive its fresh assigned replacement")
	}
	assertRestoredAssignmentState(t, ctx, d.pool, 1)
	ready := func(connection ServiceRunAssignment, lease RelayLease, readyAt time.Time) {
		t.Helper()
		expected := ServicePublisherConnection{ServiceID: f.service.ID, RunID: f.run.RunID, RunNumber: f.run.RunNumber,
			ConnectionID: connection.PublisherConnectionID, Revision: connection.Revision, RelayServiceID: connection.RelayServiceID}
		claimed, err := d.ClaimServicePublisherConnection(ctx, connection.PublisherConnectionID, f.service.ID,
			f.run.RunID, f.run.RunNumber, connection.Revision, connection.Credential, netip.MustParseAddr("127.0.0.1"),
			lease.RelayLeaseIdentity, readyAt)
		if err != nil || claimed != expected {
			t.Fatal("incremental replacement could not claim its exact current assignment", err)
		}
		connected, err := d.ReadyServicePublisherConnection(ctx, connection.PublisherConnectionID, f.run.RunID,
			f.run.RunNumber, connection.Revision, lease.RelayLeaseIdentity, readyAt)
		if err != nil || connected != expected {
			t.Fatal("incremental replacement could not make its exact connection ready", err)
		}
	}
	ready(replacement, secondLease, at.Add(time.Second))
	usable := heartbeat(at.Add(time.Second))
	survivor := slotFor(usable, second.ConnectionSlot)
	if usable.State != "ready" || survivor.PublisherConnectionID != replacement.PublisherConnectionID ||
		survivor.Revision != replacement.Revision || survivor.RelayServiceID != replacement.RelayServiceID || survivor.State != "ready" ||
		slotFor(usable, first.ConnectionSlot).State != "closed" {
		t.Fatal("one connected returning relay did not restore the established run")
	}
	selection, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, selection)
	if err := lockServiceAdmission(ctx, selection, f.service.ID); err != nil {
		t.Fatal(err)
	}
	count, err := countReadyServiceConnections(ctx, selection, f.run.RunID, at.Add(time.Second))
	if err != nil || count != 1 {
		t.Fatal("one-relay usability contrast did not have exactly one current ready connection", err)
	}
	id, number, until, err := selectRoutableServiceRun(ctx, selection, f.service.ID, "", at.Add(time.Second))
	if err != nil || id != f.run.RunID || number != f.run.RunNumber || !until.After(at.Add(time.Second)) {
		t.Fatal("current visitor selection could not use the established one-relay run", err)
	}
	if err := selection.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	assertRestoredAssignmentState(t, ctx, d.pool, 1)
	firstLease := returnRelay(first.RelayServiceID, at.Add(2*time.Second))
	completed := heartbeat(at.Add(2 * time.Second))
	restored, kept := slotFor(completed, first.ConnectionSlot), slotFor(completed, second.ConnectionSlot)
	if restored.PublisherConnectionID == first.PublisherConnectionID || restored.Revision != first.Revision+1 ||
		restored.RelayServiceID != first.RelayServiceID || restored.State != "assigned" {
		t.Fatal("later first-relay return did not replenish its own retired slot")
	}
	if kept.PublisherConnectionID != survivor.PublisherConnectionID || kept.Revision != survivor.Revision ||
		kept.RelayServiceID != survivor.RelayServiceID || kept.State != "ready" {
		t.Fatal("later recovery replaced the already usable ready survivor")
	}
	assertRestoredAssignmentState(t, ctx, d.pool, 2)
	ready(restored, firstLease, at.Add(3*time.Second))
	final := heartbeat(at.Add(3 * time.Second))
	if final.State != "ready" || slotFor(final, first.ConnectionSlot).State != "ready" ||
		slotFor(final, second.ConnectionSlot).PublisherConnectionID != survivor.PublisherConnectionID ||
		slotFor(final, second.ConnectionSlot).State != "ready" {
		t.Fatal("complete recovery lost its original run or the ready survivor")
	}
	assertRestoredAssignmentState(t, ctx, d.pool, 2)
}
