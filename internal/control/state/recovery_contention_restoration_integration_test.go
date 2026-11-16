package state

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
)

func TestIntegrationRecoveryContentionRestoredReadinessClaimAndDrain(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	d, now := newStateBRecoveryDatabase(t, ctx)
	fixtures := newStateBRecoveryRuns(t, ctx, d, now, 5)
	f, independent := fixtures[0], fixtures[1]
	slot := f.run.Connections[0]
	lease := f.leases[slot.RelayServiceID].RelayLeaseIdentity
	if _, err := d.ClaimServicePublisherConnection(ctx, slot.PublisherConnectionID, f.service.ID,
		f.run.RunID, f.run.RunNumber, slot.Revision, slot.Credential, netip.MustParseAddr("127.0.0.1"), lease, now); err != nil {
		t.Fatal(err)
	}
	var claimSlot *ServiceRunAssignment
	for index := range independent.run.Connections {
		candidate := &independent.run.Connections[index]
		if candidate.RelayServiceID == slot.RelayServiceID {
			claimSlot = candidate
		}
	}
	if claimSlot == nil || claimSlot.State != "assigned" {
		t.Fatal("independent claim lacks a fresh slot on the readiness relay")
	}
	assertRestoredAssignmentState(t, ctx, d.pool, 10)
	gate, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	var locked string
	if err := gate.QueryRow(ctx, `SELECT publisher_connection_id FROM control.service_connection_slots
		WHERE publisher_connection_id=$1 FOR UPDATE`, slot.PublisherConnectionID).Scan(&locked); err != nil {
		t.Fatal(err)
	}
	type claimResult struct {
		connection ServicePublisherConnection
		err        error
	}
	readyDone, claimDone := make(chan error, 1), make(chan claimResult, 1)
	ready := func() {
		_, err := d.ReadyServicePublisherConnection(ctx, slot.PublisherConnectionID, f.run.RunID,
			f.run.RunNumber, slot.Revision, lease, now)
		readyDone <- err
	}
	claim := func() {
		connection, err := d.ClaimServicePublisherConnection(ctx, claimSlot.PublisherConnectionID,
			independent.service.ID, independent.run.RunID, independent.run.RunNumber, claimSlot.Revision,
			claimSlot.Credential, netip.MustParseAddr("127.0.0.1"), lease, now)
		claimDone <- claimResult{connection: connection, err: err}
	}
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	workers.Go(ready)
	pid := waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), readyDone)
	var statement string
	if err := d.pool.QueryRow(ctx, `SELECT query FROM pg_stat_activity WHERE pid=$1`, pid).Scan(&statement); err != nil ||
		!strings.Contains(statement, "-- name: ReadyServiceConnectionSlot") {
		t.Fatal("gate did not block the actual readiness transition", err)
	}
	workers.Go(claim)
	claimed := awaitIntegrationResult(t, ctx, claimDone)
	if claimed.err != nil || claimed.connection.ConnectionID != claimSlot.PublisherConnectionID ||
		claimed.connection.RunID != independent.run.RunID || claimed.connection.Revision != claimSlot.Revision {
		t.Fatal("independent claim did not progress while readiness was blocked", claimed.err)
	}
	drained, err := d.BeginRelayDrain(ctx, lease, now, now.Add(time.Minute))
	if err != nil || !drained.Draining || drained.RelayLeaseIdentity != lease {
		t.Fatal("drain did not progress while readiness was blocked", err)
	}
	var draining bool
	var deadline time.Time
	if err := d.pool.QueryRow(ctx, `SELECT draining,drain_deadline FROM control.relay_leases
		WHERE relay_id=$1 AND relay_run_id=$2 AND relay_lease_revision=$3`,
		lease.RelayID, lease.RelayRunID, int64(lease.RelayLeaseRevision)).Scan(&draining, &deadline); err != nil ||
		!draining || !deadline.Equal(now.Add(time.Minute)) {
		t.Fatal("drain did not commit its exact relay deadline before readiness release", err)
	}
	// this is a connected slot on the drained relay, not an already-ready
	// retry whose state could independently mask the drain predicate.
	_, denied := d.ReadyServicePublisherConnection(ctx, claimSlot.PublisherConnectionID, independent.run.RunID,
		independent.run.RunNumber, claimSlot.Revision, lease, now)
	if !failure.Only(denied, ErrServiceAccess) {
		t.Error("post-drain readiness did not reject only current relay authority", denied)
	}
	var state string
	if err := d.pool.QueryRow(ctx, `SELECT state FROM control.service_connection_slots
		WHERE publisher_connection_id=$1`, claimSlot.PublisherConnectionID).Scan(&state); err != nil || state != "connected" {
		t.Error("post-drain denial changed the independent connected slot", state, err)
	}
	assertRestoredAssignmentState(t, ctx, d.pool, 10)
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, readyDone); err != nil {
		t.Fatal("previously admitted readiness failed after its child gate released", err)
	}
	if err := d.pool.QueryRow(ctx, `SELECT state FROM control.service_connection_slots
		WHERE publisher_connection_id=$1`, slot.PublisherConnectionID).Scan(&state); err != nil || state != "ready" {
		t.Fatal("joined readiness did not commit its exact slot", state, err)
	}
	assertRestoredAssignmentState(t, ctx, d.pool, 10)
}

func TestIntegrationRecoveryContentionRestoredMixedAndFallbackAssignments(t *testing.T) {
	for _, reason := range []string{"disabled", "draining", "capacity_reduced", "mixed_closed_slot"} {
		t.Run(reason, func(t *testing.T) {
			f := newServicePublicationFixture(t)
			installPrivateTestCertificate(t, f.database, f.prepared, f.run, f.now)
			f.readyConnections(t, f.now)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			d, at := f.database, f.now.Add(2*time.Second)
			health := ServiceRunHealth{Healthy: true, StreamCapacity: 64}
			ready, err := d.HeartbeatServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, f.now, health)
			if err != nil || ready.State != "ready" || len(ready.Connections) != 2 {
				t.Fatal("recovery fixture did not start with two ready slots", err)
			}
			first, second := ready.Connections[0], ready.Connections[1]
			if first.Revision != 1 || second.Revision != 1 || first.State != "ready" || second.State != "ready" {
				t.Fatal("recovery fixture lacks the initial ready revision-one pair")
			}
			previousLease := f.leases[first.RelayServiceID]
			if _, err := d.pool.Exec(ctx, `UPDATE control.relay_leases SET lease_expires_at=$2
				WHERE relay_id=$1`, previousLease.RelayID, f.now.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			registration := relayLifecycleRegistration(first.RelayServiceID)
			registration.RelayID = previousLease.RelayID
			registration.RelayRunID = previousLease.RelayRunID + "-state-b-restart"
			registration.ConnectionCapacity = 100
			restarted, err := d.RegisterRelay(ctx, registration, at, time.Hour)
			if err != nil || restarted.RelayLeaseRevision != previousLease.RelayLeaseRevision+1 {
				t.Fatal("real relay restart did not invalidate the old ready claim", err)
			}
			spare := relayLifecycleRegistration("state-b-spare")
			spare.ConnectionCapacity = 100
			if _, err := d.RegisterRelay(ctx, spare, at, time.Hour); err != nil {
				t.Fatal(err)
			}
			switch reason {
			case "disabled":
				if _, err := d.pool.Exec(ctx, `UPDATE control.relay_services SET enabled=false WHERE relay_service_id=$1`,
					first.RelayServiceID); err != nil {
					t.Fatal(err)
				}
			case "draining":
				if _, err := d.BeginRelayDrain(ctx, restarted.RelayLeaseIdentity, at, at.Add(time.Minute)); err != nil {
					t.Fatal(err)
				}
			case "capacity_reduced":
				if _, err := d.pool.Exec(ctx, `UPDATE control.relay_leases SET connection_capacity=0 WHERE relay_id=$1`,
					restarted.RelayID); err != nil {
					t.Fatal(err)
				}
			case "mixed_closed_slot":
				if _, err := d.DisconnectServicePublisherConnection(ctx, second.PublisherConnectionID, f.run.RunID,
					f.run.RunNumber, second.Revision, f.leases[second.RelayServiceID].RelayLeaseIdentity, at, true); err != nil {
					t.Fatal(err)
				}
				// retain the first stale ready reservation; only the other
				// slot is closed, and no relay capacity is disabled.
				assertRestoredAssignmentState(t, ctx, d.pool, 1)
			}
			recovered, err := d.HeartbeatServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, at, health)
			if err != nil || len(recovered.Connections) != 2 {
				t.Fatal("recovery did not return exactly two assignments", err)
			}
			var replacement, other *ServiceRunAssignment
			for index := range recovered.Connections {
				connection := &recovered.Connections[index]
				switch connection.ConnectionSlot {
				case first.ConnectionSlot:
					replacement = connection
				case second.ConnectionSlot:
					other = connection
				}
			}
			if replacement == nil || other == nil || replacement.PublisherConnectionID == first.PublisherConnectionID ||
				replacement.Revision != 2 || replacement.State != "assigned" {
				t.Fatal("stale reservation did not receive a fresh assigned revision-two identity")
			}
			if reason == "mixed_closed_slot" {
				if replacement.RelayServiceID != first.RelayServiceID || other.PublisherConnectionID == second.PublisherConnectionID ||
					other.Revision != 2 || other.State != "assigned" {
					t.Fatal("mixed recovery did not reuse the reserved relay and allocate the closed slot")
				}
			} else if replacement.RelayServiceID != spare.RelayServiceID || other.PublisherConnectionID != second.PublisherConnectionID ||
				other.RelayServiceID != second.RelayServiceID || other.Revision != second.Revision || other.State != "ready" {
				t.Fatal("fallback did not select the spare while preserving the exact ready survivor")
			}
			stored, err := controlstatedb.New(d.pool).ListServiceConnectionSlots(ctx, f.run.RunID)
			if err != nil || len(stored) != 2 {
				t.Fatal("recovered assignments were not both stored", err)
			}
			for _, row := range stored {
				expected := replacement
				if row.ConnectionSlot == second.ConnectionSlot {
					expected = other
				}
				if row.PublisherConnectionID != expected.PublisherConnectionID || row.ConnectionAssignmentRevision != expected.Revision ||
					row.State != expected.State || row.RelayServiceID != expected.RelayServiceID || !row.SessionOpen {
					t.Fatal("durable recovery tuple differs from the returned assignment")
				}
			}
			assertRestoredAssignmentState(t, ctx, d.pool, 2)
		})
	}
}

func TestIntegrationRecoveryContentionRestoredHealthyHeartbeatAtHeldPlacement(t *testing.T) {
	f := newServicePublicationFixture(t)
	installPrivateTestCertificate(t, f.database, f.prepared, f.run, f.now)
	f.readyConnections(t, f.now)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	d := f.database
	health := ServiceRunHealth{Healthy: true, StreamCapacity: 64}
	ready, err := d.HeartbeatServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, f.now, health)
	if err != nil || ready.State != "ready" || len(ready.Connections) != 2 {
		t.Fatal("healthy fixture lacks two ready connections", err)
	}
	if _, err := d.RegisterRelay(ctx, relayLifecycleRegistration("state-b-held-placement"), f.now, time.Hour); err != nil {
		t.Fatal(err)
	}
	gate, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	var locked string
	if err := gate.QueryRow(ctx, `SELECT relay_service_id FROM control.relay_services
		WHERE relay_service_id='state-b-held-placement' FOR UPDATE`).Scan(&locked); err != nil {
		t.Fatal(err)
	}
	type result struct {
		run ServiceRunState
		err error
	}
	done := make(chan result, 1)
	call, stop := context.WithTimeout(ctx, time.Second)
	defer stop()
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	workers.Go(func() {
		run, err := d.HeartbeatServiceRun(call, f.service.ID, f.run.RunID, f.run.Token, f.now.Add(time.Second), health)
		done <- result{run: run, err: err}
	})
	observed := awaitIntegrationResult(t, call, done)
	if observed.err != nil || observed.run.State != "ready" || len(observed.run.Connections) != 2 {
		t.Fatal("healthy heartbeat did not return two ready slots within one second of the held lock", observed.err)
	}
	for index, connection := range observed.run.Connections {
		previous := ready.Connections[index]
		if connection.State != "ready" || connection.PublisherConnectionID != previous.PublisherConnectionID ||
			connection.Revision != previous.Revision || connection.RelayServiceID != previous.RelayServiceID {
			t.Fatal("healthy heartbeat changed or omitted a ready connection while placement was held")
		}
	}
	assertRestoredAssignmentState(t, ctx, d.pool, 2)
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func newStateBRecoveryDatabase(t *testing.T, ctx context.Context) (*Database, time.Time) {
	t.Helper()
	// disposable database allocation keeps the existing harness tier gate;
	// migration, open, and every workload call use the caller's fixed budget.
	url := newDisposableControlStateDatabaseURL(t, "state_b_recovery_contention")
	if err := Migrate(ctx, url); err != nil {
		t.Fatal(err)
	}
	d, err := Open(ctx, url, testStorageKey, "", naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	return d, time.Now().UTC().Truncate(time.Second)
}

func newStateBRecoveryRuns(t *testing.T, ctx context.Context, d *Database, now time.Time, count int) []servicePublicationFixture {
	t.Helper()
	session, err := createTestControlSession(ctx, d, "tunnels.example.test", time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	member, actor := session.Identity.Memberships[0], session.Identity.Identity.ID
	leases := make(map[string]RelayLease)
	for index := range 2 {
		registration := relayLifecycleRegistration(fmt.Sprintf("state-b-relay-%d", index))
		registration.ConnectionCapacity = 100
		lease, err := d.RegisterRelay(ctx, registration, now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		leases[lease.RelayServiceID] = lease
	}
	fixtures := make([]servicePublicationFixture, 0, count)
	for index := range count {
		name := fmt.Sprintf("state-b-run-%d", index)
		service, err := d.CreateServiceAt(ctx, member.TeamID, actor, name, name, ServicePlacement{}, now,
			ServiceMetadata{}, &ProjectServiceConfiguration{Target: "localhost:3000"})
		if err != nil {
			t.Fatal(err)
		}
		authority, err := controlstatedb.New(d.pool).GetTeamActorContext(ctx,
			controlstatedb.GetTeamActorContextParams{TeamID: member.TeamID, IdentityID: actor})
		if err != nil {
			t.Fatal(err)
		}
		enrollment, err := d.IssuePublisherEnrollment(ctx, CreatePublisherEnrollmentRequest{
			Scope: PublisherScope{TeamID: member.TeamID, Kind: "service", ServiceID: service.ID},
			Name:  name, Kind: "installed", EditorID: actor, EditorMembershipID: authority.ActorMembershipID,
			PolicyRevision: uint64(authority.PolicyRevision), Now: now,
		})
		if err != nil {
			t.Fatal(err)
		}
		public, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		publisher, err := d.RedeemPublisherEnrollment(ctx, enrollment.Key, public, now)
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := d.PrepareServiceRun(ctx, service.ID, publisher, "initial", now,
			ServiceRunRequest{Metadata: service.ServiceMetadata})
		if err != nil {
			t.Fatal(err)
		}
		run, err := d.StartServiceRun(ctx, service.ID, prepared.RunID, prepared.RunNumber, publisher, now)
		if err != nil {
			t.Fatal(err)
		}
		fixtures = append(fixtures, servicePublicationFixture{
			database: d, now: now, service: service, publisher: publisher, prepared: prepared, run: run, leases: leases,
		})
	}
	return fixtures
}
