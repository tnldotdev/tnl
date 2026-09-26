package controlstate

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

func TestIntegrationRecoveryReusesReservationDuringPlacement(t *testing.T) {
	f := newPublishRunFixture(t)
	oldClaims := readyTestSession(t, f)
	database, now := f.database, f.now
	previous := f.setup.PublisherConnections[0]
	registration := relayLifecycleRegistration(previous.RelayServiceID)
	registration.ConnectionCapacity = 1 // The existing reservation fills this service.
	registration.RelayRunID += "-restart"
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.relay_leases SET lease_expires_at = $1 WHERE relay_id = $2`, now.Add(time.Second), registration.RelayID); err != nil {
		t.Fatal(err)
	}
	lease, err := database.RegisterRelay(t.Context(), registration, now.Add(2*time.Second), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f.leases[lease.RelayServiceID] = lease
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	gate, err := database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	// An unrelated allocator holds the reservation, service, and lease guards.
	// Replacing an already-reserved slot must not join that queue or write totals.
	if _, _, err := availableRelayServicePlacements(ctx, controlstatedb.New(gate), now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	callCtx, stop := context.WithTimeout(ctx, time.Second)
	defer stop()
	recovered, err := database.HeartbeatPublishRun(callCtx, f.authentication(), now.Add(3*time.Second), time.Hour, time.Minute)
	if err != nil {
		t.Fatalf("same-service recovery waited for placement: %v", err)
	}
	connection := recovered.PublisherConnections[0]
	if connection.RelayServiceID != previous.RelayServiceID || connection.PublisherConnectionID == previous.PublisherConnectionID || connection.ConnectionAssignmentRevision != previous.ConnectionAssignmentRevision+1 || connection.State != PublisherConnectionAssigned {
		t.Fatal("recovery did not replace the failed connection in its reserved service")
	}
	if recovered.PublisherConnections[1].ConnectionAssignmentIdentity != f.setup.PublisherConnections[1].ConnectionAssignmentIdentity || recovered.PublisherConnections[1].State != PublisherConnectionReady {
		t.Fatal("recovery changed the surviving connection")
	}
	assertAssignmentTotals(t, database.pool, 2)
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := database.MarkPublisherConnectionReady(ctx, oldClaims[0], now.Add(4*time.Second)); !errors.Is(err, ErrPublisherConnectionUnavailable) && !errors.Is(err, ErrConnectionAssignmentStale) {
		t.Fatalf("old connection readiness was not rejected: %v", err)
	}
	f.setup = recovered
	claimTestConnection(t, f, 0, now.Add(4*time.Second))
	assertAssignmentTotals(t, database.pool, 2)
}

func TestIntegrationClaimProgressesDuringReadinessPublication(t *testing.T) {
	fixtures, _ := relayServiceProgressSessions(t)
	f := fixtures[0]
	claims := readyTestSession(t, f)
	// Model an already-routable session with a claimed replacement awaiting
	// readiness. Its publisher connection already consumes process capacity.
	if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.publish_run_connections SET state = 'connected' WHERE publisher_connection_id = $1`, claims[0].PublisherConnectionID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	gate, err := f.database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := controlstatedb.New(gate).LockIngressRoutingTableClock(ctx); err != nil {
		t.Fatal(err)
	}
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	ready := make(chan error, 1)
	workers.Go(func() {
		_, err := f.database.MarkPublisherConnectionReady(ctx, claims[0], f.now)
		ready <- err
	})
	waitForPostgresBlock(t, ctx, f.database, int32(gate.Conn().PgConn().PID()), ready)
	callCtx, stop := context.WithTimeout(ctx, time.Second)
	defer stop()
	if _, err := f.database.ClaimPublisherConnection(callCtx, sessionClaim(t, fixtures[1]), f.now); err != nil {
		t.Fatalf("independent claim waited for readiness publication: %v", err)
	}
	// Drain can overlap readiness that already validated this lease; a later
	// readiness request must observe the drain rather than reuse that decision.
	if _, err := f.database.BeginRelayDrain(callCtx, claims[0].RelayLeaseIdentity, f.now, f.now.Add(time.Minute)); err != nil {
		t.Fatalf("drain waited for readiness publication: %v", err)
	}
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, ready); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.MarkPublisherConnectionReady(ctx, claims[0], f.now); !errors.Is(err, ErrRelayDraining) {
		t.Fatalf("readiness after committed drain = %v", err)
	}
	assertAssignmentTotals(t, f.database.pool, 10)
}

func TestIntegrationRecoveryReservationFallback(t *testing.T) {
	for _, reason := range []string{"disabled", "draining", "capacity_reduced", "mixed_closed_slot"} {
		t.Run(reason, func(t *testing.T) {
			fixtures, registration := relayServiceProgressSessions(t)
			f := fixtures[0]
			claims := readyTestSession(t, f)
			ctx := t.Context()
			at := f.now.Add(time.Second)
			if _, err := f.database.RegisterRelay(ctx, relayLifecycleRegistration("spare"), at, time.Hour); err != nil {
				t.Fatal(err)
			}
			// A stale ready assignment still contributes to its service total.
			if _, err := f.database.pool.Exec(ctx, `UPDATE control.publish_run_connections SET connected_relay_run_id = 'stale-run' WHERE publisher_connection_id = $1`, claims[0].PublisherConnectionID); err != nil {
				t.Fatal(err)
			}
			var err error
			switch reason {
			case "disabled":
				_, err = f.database.pool.Exec(ctx, `UPDATE control.relay_services SET enabled = false WHERE relay_service_id = $1`, registration.RelayServiceID)
			case "draining":
				_, err = f.database.BeginRelayDrain(ctx, claims[0].RelayLeaseIdentity, at, at.Add(time.Minute))
			case "capacity_reduced":
				registration.ConnectionCapacity = 4 // Five reservations no longer fit.
				_, err = f.database.RegisterRelay(ctx, registration, at, time.Hour)
			case "mixed_closed_slot":
				_, err = f.database.DisconnectPublisherConnection(ctx, claims[1], at, true)
			}
			if err != nil {
				t.Fatal(err)
			}
			recovered, err := f.database.HeartbeatPublishRun(ctx, f.authentication(), at, time.Hour, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			wantService := "spare"
			if reason == "mixed_closed_slot" {
				wantService = registration.RelayServiceID
				if recovered.PublisherConnections[1].State != PublisherConnectionAssigned || recovered.PublisherConnections[1].ConnectionAssignmentRevision != 2 {
					t.Fatal("closed slot was not allocated alongside reservation reuse")
				}
			} else if recovered.PublisherConnections[1].State != PublisherConnectionReady {
				t.Fatal("fallback changed the surviving connection")
			}
			first := recovered.PublisherConnections[0]
			if first.RelayServiceID != wantService || first.State != PublisherConnectionAssigned || first.ConnectionAssignmentRevision != 2 || first.PublisherConnectionID == claims[0].PublisherConnectionID {
				t.Fatalf("fallback did not produce the expected assignment: %+v", first.ConnectionAssignmentIdentity)
			}
			assertAssignmentTotals(t, f.database.pool, 10)
		})
	}
}

func TestIntegrationRecoveryReservationRollback(t *testing.T) {
	f := newPublishRunFixture(t)
	readyTestSession(t, f)
	ctx := t.Context()
	if _, err := f.database.pool.Exec(ctx, `UPDATE control.publish_run_connections SET connected_relay_run_id = 'stale-run' WHERE connection_slot = 0`); err != nil {
		t.Fatal(err)
	}
	queries := controlstatedb.New(f.database.pool)
	before, err := queries.ReadIngressRoutingTableClock(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.pool.Exec(ctx, fmt.Sprintf(`ALTER TABLE control.ingress_routing_table_events ADD CONSTRAINT reject_recovery_event CHECK (routing_table_revision <= %d)`, before.CurrentRevision)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.HeartbeatPublishRun(ctx, f.authentication(), f.now.Add(time.Second), time.Hour, time.Minute); err == nil {
		t.Fatal("heartbeat unexpectedly committed without its routing event")
	}
	rows, err := queries.ListPublishRunConnections(ctx, f.setup.PublishRunID)
	if err != nil || len(rows) != 2 {
		t.Fatalf("read rolled-back assignments: %v", err)
	}
	for _, row := range rows {
		if row.State != "ready" || row.PublisherConnectionID != f.setup.PublisherConnections[row.ConnectionSlot].PublisherConnectionID || row.ConnectionAssignmentRevision != 1 {
			t.Fatal("failed publication retained a replacement assignment")
		}
	}
	after, err := queries.ReadIngressRoutingTableClock(ctx)
	if err != nil || after.CurrentRevision != before.CurrentRevision {
		t.Fatalf("failed publication advanced the clock: %v", err)
	}
	assertAssignmentTotals(t, f.database.pool, 2)
	if _, err := f.database.pool.Exec(ctx, `ALTER TABLE control.ingress_routing_table_events DROP CONSTRAINT reject_recovery_event`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.HeartbeatPublishRun(ctx, f.authentication(), f.now.Add(time.Second), time.Hour, time.Minute); err != nil {
		t.Fatal(err)
	}
	assertAssignmentTotals(t, f.database.pool, 2)
}
