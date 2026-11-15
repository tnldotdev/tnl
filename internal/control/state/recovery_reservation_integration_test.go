package state

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationRecoveryReusesReservationDuringPlacement(t *testing.T) {
	f := newServicePublicationFixture(t)
	installPrivateTestCertificate(t, f.database, f.prepared, f.run, f.now)
	f.readyConnections(t, f.now)
	ready, err := f.database.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.now, ServiceRunHealth{Healthy: true, StreamCapacity: 64})
	if err != nil || ready.State != "ready" {
		t.Fatal("service did not become ready", ready, err)
	}
	ready.Token = f.run.Token
	f.run = ready
	previous := f.run.Connections[0]
	surviving := f.run.Connections[1]

	// restart the relay process for the reserved service while leaving the stale ready
	// slot reservation intact, so recovery must reuse that reservation.
	oldRelayID, oldRelayRunID, oldRevision := "", "", int64(0)
	if err := f.database.pool.QueryRow(t.Context(), `SELECT relay_id, relay_run_id, relay_lease_revision FROM control.service_connection_slots WHERE publisher_connection_id=$1`, previous.PublisherConnectionID).Scan(&oldRelayID, &oldRelayRunID, &oldRevision); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.relay_leases SET lease_expires_at=$2, connection_capacity=1 WHERE relay_service_id=$1`, previous.RelayServiceID, f.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.relay_leases SET connection_capacity=0 WHERE relay_service_id<>$1`, previous.RelayServiceID); err != nil {
		t.Fatal(err)
	}
	reg := relayLifecycleRegistration(previous.RelayServiceID)
	reg.RelayID = oldRelayID
	reg.RelayRunID = oldRelayRunID + "-restart"
	reg.ConnectionCapacity = 1
	reg.StreamCapacity = 64
	restarted, err := f.database.RegisterRelay(t.Context(), reg, f.now.Add(2*time.Second), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f.leases[restarted.RelayServiceID] = restarted

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	gate, err := f.database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, _, err := availableRelayServicePlacements(ctx, controlstatedb.New(gate), f.run.ExpiresAt.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	type hbResult struct {
		run ServiceRunState
		err error
	}
	done := make(chan hbResult, 1)
	workers.Go(func() {
		run, err := f.database.HeartbeatServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, f.run.ExpiresAt.Add(-time.Second), ServiceRunHealth{Healthy: true, StreamCapacity: 64})
		done <- hbResult{run: run, err: err}
	})
	var res hbResult
	select {
	case <-time.After(2 * time.Second):
		t.Fatal("same-service recovery waited for placement gate")
	case res = <-done:
		// recovery reusing the reserved slot must not wait on placement/allocation gate.
	}
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if res.err != nil {
		t.Fatal(res.err)
	}
	recovered := res.run
	var replaced, unchanged *ServiceRunAssignment
	for i := range recovered.Connections {
		s := &recovered.Connections[i]
		switch s.ConnectionSlot {
		case previous.ConnectionSlot:
			replaced = s
		case surviving.ConnectionSlot:
			unchanged = s
		}
	}
	if replaced == nil || unchanged == nil {
		t.Fatalf("recovered slots not found: %+v", recovered.Connections)
	}
	if replaced.RelayServiceID != previous.RelayServiceID || replaced.PublisherConnectionID == previous.PublisherConnectionID || replaced.Revision != previous.Revision+1 {
		t.Fatalf("recovery did not reuse reserved service: replaced=%+v previous=%+v", *replaced, previous)
	}
	if unchanged.PublisherConnectionID != surviving.PublisherConnectionID || unchanged.Revision != surviving.Revision || unchanged.RelayServiceID != surviving.RelayServiceID {
		t.Fatalf("surviving connection changed: unchanged=%+v surviving=%+v", *unchanged, surviving)
	}
	assertAssignmentTotals(t, f.database.pool, 2)
	if _, err := f.database.ReadyServicePublisherConnection(t.Context(), previous.PublisherConnectionID, f.run.RunID, f.run.RunNumber, previous.Revision, RelayLeaseIdentity{RelayServiceID: previous.RelayServiceID, RelayID: oldRelayID, RelayRunID: oldRelayRunID, RelayLeaseRevision: uint64(oldRevision)}, f.run.ExpiresAt.Add(-time.Second)); !errors.Is(err, ErrServiceAccess) {
		t.Fatalf("old readiness after recovery replacement = %v", err)
	}
	if _, err := f.database.ClaimServicePublisherConnection(t.Context(), replaced.PublisherConnectionID, f.service.ID, f.run.RunID, f.run.RunNumber, replaced.Revision, replaced.Credential, netip.MustParseAddr("127.0.0.1"), restarted.RelayLeaseIdentity, f.run.ExpiresAt.Add(-time.Second)); err != nil {
		t.Fatalf("claim recovered assignment: %v", err)
	}
	assertAssignmentTotals(t, f.database.pool, 2)
}

func TestIntegrationClaimProgressesDuringReadinessPublication(t *testing.T) {
	f := newServicePublicationFixture(t)
	installPrivateTestCertificate(t, f.database, f.prepared, f.run, f.now)
	f.readyConnections(t, f.now)
	ready, err := f.database.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.now, ServiceRunHealth{Healthy: true, StreamCapacity: 64})
	if err != nil || ready.State != "ready" {
		t.Fatal(err)
	}
	ready.Token = f.run.Token
	f.run = ready
	// independent claim on a slot needing reconnect must progress (no fake clock/retired routing-table clock gate).
	slot := f.run.Connections[0]
	lease := connectedRelayLease(t, f.database, slot.PublisherConnectionID, slot.RelayServiceID)
	if _, err := f.database.DisconnectServicePublisherConnection(t.Context(), slot.PublisherConnectionID, f.run.RunID, f.run.RunNumber, slot.Revision, lease, f.now, true); err != nil {
		t.Fatal(err)
	}
	recovered, err := f.database.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.now, ServiceRunHealth{Healthy: true, StreamCapacity: 64})
	if err != nil {
		t.Fatal(err)
	}
	var replacement *ServiceRunAssignment
	for i := range recovered.Connections {
		if recovered.Connections[i].ConnectionSlot == slot.ConnectionSlot {
			replacement = &recovered.Connections[i]
			break
		}
	}
	if replacement == nil {
		t.Fatalf("recovered slot not found: %+v", recovered.Connections)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	claimLease, ok := f.leases[replacement.RelayServiceID]
	if !ok {
		t.Fatalf("missing lease for replacement service %q", replacement.RelayServiceID)
	}
	done := make(chan error, 1)
	workers.Go(func() {
		_, err := f.database.ClaimServicePublisherConnection(t.Context(), replacement.PublisherConnectionID, f.service.ID, f.run.RunID, f.run.RunNumber, replacement.Revision, replacement.Credential, netip.MustParseAddr("127.0.0.1"), claimLease.RelayLeaseIdentity, f.now)
		done <- err
	})
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("independent claim did not progress: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("independent claim did not progress")
	}
}

func TestIntegrationRecoveryReservationFallback(t *testing.T) {
	for _, reason := range []string{"disabled", "draining", "capacity_reduced", "mixed_closed_slot"} {
		t.Run(reason, func(t *testing.T) {
			f := newServicePublicationFixture(t)
			installPrivateTestCertificate(t, f.database, f.prepared, f.run, f.now)
			f.readyConnections(t, f.now)
			ready, err := f.database.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.now, ServiceRunHealth{Healthy: true, StreamCapacity: 64})
			if err != nil || ready.State != "ready" {
				t.Fatal(err)
			}
			ready.Token = f.run.Token
			f.run = ready
			slot := f.run.Connections[0]
			survivor := f.run.Connections[1]
			lease := f.leases[slot.RelayServiceID]

			spareReg := relayLifecycleRegistration("spare-" + reason)
			spareReg.ConnectionCapacity = 10
			if _, err := f.database.RegisterRelay(t.Context(), spareReg, f.now, time.Hour); err != nil {
				t.Fatal(err)
			}

			if reason == "mixed_closed_slot" {
				survLease := connectedRelayLease(t, f.database, survivor.PublisherConnectionID, survivor.RelayServiceID)
				if _, err := f.database.DisconnectServicePublisherConnection(t.Context(), survivor.PublisherConnectionID, f.run.RunID, f.run.RunNumber, survivor.Revision, survLease, f.now, true); err != nil {
					t.Fatal(err)
				}
				// close the disconnected slot while the run remains open (session_open must match assignments_open).
				if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.service_connection_slots SET state='closed', session_open=true, relay_id=NULL, relay_run_id=NULL, relay_lease_revision=NULL WHERE publisher_connection_id=$1`, survivor.PublisherConnectionID); err != nil {
					t.Fatal(err)
				}
			}

			slotLease := connectedRelayLease(t, f.database, slot.PublisherConnectionID, slot.RelayServiceID)
			if _, err := f.database.DisconnectServicePublisherConnection(t.Context(), slot.PublisherConnectionID, f.run.RunID, f.run.RunNumber, slot.Revision, slotLease, f.now, true); err != nil {
				t.Fatal(err)
			}

			switch reason {
			case "disabled":
				if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.relay_services SET enabled=false WHERE relay_service_id=$1`, lease.RelayServiceID); err != nil {
					t.Fatal(err)
				}
			case "draining":
				if _, err := f.database.BeginRelayDrain(t.Context(), lease.RelayLeaseIdentity, f.now, f.now.Add(time.Minute)); err != nil {
					t.Fatal(err)
				}
			case "capacity_reduced", "mixed_closed_slot":
				// preserve original mixed-case reservation reuse + new allocation invariants;
				// source must handle replacement allocation without uniqueness conflicts.
				if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.relay_leases SET connection_capacity=0 WHERE relay_service_id=$1`, lease.RelayServiceID); err != nil {
					t.Fatal(err)
				}
			}

			recovered, err := f.database.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.run.ExpiresAt.Add(-time.Second), ServiceRunHealth{Healthy: true, StreamCapacity: 64})
			if err != nil {
				t.Fatal(err)
			}
			var replaced, kept *ServiceRunAssignment
			for i := range recovered.Connections {
				c := &recovered.Connections[i]
				switch c.ConnectionSlot {
				case slot.ConnectionSlot:
					replaced = c
				case survivor.ConnectionSlot:
					kept = c
				}
			}
			if replaced == nil || kept == nil {
				t.Fatalf("expected both slots in recovered run: %+v", recovered.Connections)
			}
			if replaced.RelayServiceID == slot.RelayServiceID {
				t.Fatalf("expected fallback placement away from unavailable service, got %+v", *replaced)
			}
			if replaced.Revision != slot.Revision+1 {
				t.Fatalf("expected replacement revision increment: replaced=%+v old=%+v", *replaced, slot)
			}
			if reason != "mixed_closed_slot" {
				if kept.Revision != survivor.Revision || kept.RelayServiceID != survivor.RelayServiceID {
					t.Fatalf("surviving connection changed: kept=%+v old=%+v", *kept, survivor)
				}
			}
			assertAssignmentTotals(t, f.database.pool, 2)
		})
	}
}

func TestIntegrationRecoveryReservationRollback(t *testing.T) {
	f := newServicePublicationFixture(t)
	installPrivateTestCertificate(t, f.database, f.prepared, f.run, f.now)
	f.readyConnections(t, f.now)
	ready, err := f.database.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.now, ServiceRunHealth{Healthy: true, StreamCapacity: 64})
	if err != nil || ready.State != "ready" {
		t.Fatal(err)
	}
	ready.Token = f.run.Token
	f.run = ready
	slot := f.run.Connections[0]
	survivor := f.run.Connections[1]

	// real stale READY reservation setup (restart), preserving reservation/totals.
	oldRelayID, oldRelayRunID, oldRevision := "", "", int64(0)
	if err := f.database.pool.QueryRow(t.Context(), `SELECT relay_id, relay_run_id, relay_lease_revision FROM control.service_connection_slots WHERE publisher_connection_id=$1`, slot.PublisherConnectionID).Scan(&oldRelayID, &oldRelayRunID, &oldRevision); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.relay_leases SET lease_expires_at=$2 WHERE relay_service_id=$1`, slot.RelayServiceID, f.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	reg := relayLifecycleRegistration(slot.RelayServiceID)
	reg.RelayID = oldRelayID
	reg.RelayRunID = oldRelayRunID + "-restart"
	reg.ConnectionCapacity = 2
	reg.StreamCapacity = 64
	if _, err := f.database.RegisterRelay(t.Context(), reg, f.now.Add(2*time.Second), time.Hour); err != nil {
		t.Fatal(err)
	}

	// inject an actual failure boundary: reject any replacement write for this slot.
	constraint := fmt.Sprintf(`ALTER TABLE control.service_connection_slots ADD CONSTRAINT reject_recovery_replacement CHECK (connection_slot <> %d OR connection_assignment_revision = %d)`, slot.ConnectionSlot, slot.Revision)
	if _, err := f.database.pool.Exec(t.Context(), constraint); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.run.ExpiresAt.Add(-time.Second), ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err == nil {
		t.Fatal("heartbeat unexpectedly committed replacement past failure boundary")
	}
	slots, err := controlstatedb.New(f.database.pool).ListServiceConnectionSlots(t.Context(), f.run.RunID)
	if err != nil || len(slots) != 2 {
		t.Fatalf("read rolled-back assignments: len=%d err=%v", len(slots), err)
	}
	for _, row := range slots {
		switch row.ConnectionSlot {
		case slot.ConnectionSlot:
			if row.PublisherConnectionID != slot.PublisherConnectionID || row.ConnectionAssignmentRevision != slot.Revision || row.State != "ready" {
				t.Fatalf("failed replacement slot committed change: id=%q old=%q state=%q revision=%d old=%d", row.PublisherConnectionID, slot.PublisherConnectionID, row.State, row.ConnectionAssignmentRevision, slot.Revision)
			}
		case survivor.ConnectionSlot:
			if row.PublisherConnectionID != survivor.PublisherConnectionID || row.ConnectionAssignmentRevision != survivor.Revision || row.State != "ready" {
				t.Fatalf("surviving slot changed on rollback: id=%q old=%q state=%q revision=%d old=%d", row.PublisherConnectionID, survivor.PublisherConnectionID, row.State, row.ConnectionAssignmentRevision, survivor.Revision)
			}
		}
	}
	assertAssignmentTotals(t, f.database.pool, 2)
	if _, err := f.database.pool.Exec(t.Context(), `ALTER TABLE control.service_connection_slots DROP CONSTRAINT reject_recovery_replacement`); err != nil {
		t.Fatal(err)
	}
	retry, err := f.database.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.run.ExpiresAt.Add(-time.Second), ServiceRunHealth{Healthy: true, StreamCapacity: 64})
	if err != nil {
		t.Fatal(err)
	}
	var retried *ServiceRunAssignment
	for i := range retry.Connections {
		if retry.Connections[i].ConnectionSlot == slot.ConnectionSlot {
			retried = &retry.Connections[i]
			break
		}
	}
	if retried == nil || retried.PublisherConnectionID == slot.PublisherConnectionID || retried.Revision != slot.Revision+1 {
		t.Fatalf("retry did not replace slot after boundary removal: retried=%+v old=%+v", retry.Connections, slot)
	}
	assertAssignmentTotals(t, f.database.pool, 2)
}

func connectedRelayLease(t *testing.T, database *Database, connectionID, relayServiceID string) RelayLeaseIdentity {
	t.Helper()
	var relayID, relayRunID string
	var revision int64
	err := database.pool.QueryRow(t.Context(), `SELECT relay_id, relay_run_id, relay_lease_revision FROM control.service_connection_slots WHERE publisher_connection_id=$1`, connectionID).Scan(&relayID, &relayRunID, &revision)
	if err != nil {
		t.Fatal(err)
	}
	return RelayLeaseIdentity{RelayServiceID: relayServiceID, RelayID: relayID, RelayRunID: relayRunID, RelayLeaseRevision: uint64(revision)}
}
