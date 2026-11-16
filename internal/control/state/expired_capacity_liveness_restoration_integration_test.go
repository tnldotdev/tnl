package state

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"
)

func TestIntegrationExpirationRestorationProgressPastBusyOwner(t *testing.T) {
	busy := newServicePublicationFixture(t)
	other := newRestorationOtherTeamPublication(t, busy, "expiration", busy.now)
	other.start(t, "first", busy.now.Add(time.Second))
	d, at := busy.database, other.run.ExpiresAt
	if busy.service.TeamID == other.service.TeamID || !busy.run.ExpiresAt.Before(at) {
		t.Fatal("busy expired candidate must precede a different team's expired run")
	}
	assertAssignmentTotals(t, d.pool, 4)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	gate, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	// the gate follows the owner's lock order, rather than taking a service
	// first and asking expiration to invert its authority locks.
	if err := lockServiceOwner(ctx, gate, busy.service.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := gate.Exec(ctx, `SELECT id FROM control.services WHERE id=$1 FOR UPDATE`, busy.service.ID); err != nil {
		t.Fatal(err)
	}
	workers := newIntegrationWorkers(t, cancel)
	done := make(chan error, 1)
	var count int
	received := false
	defer func() {
		// release even on a failed liveness assertion, then join. cleanup gets
		// its own bound, never more time for the five-second progress claim.
		rollbackTestTransaction(t, gate)
		workers.stop()
		if !received {
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("expiration worker after gate release: %v", err)
				}
			default:
				t.Error("expiration worker did not return a result after joining")
			}
		}
	}()
	workers.Go(func() {
		var err error
		count, err = d.ExpireServiceRuns(ctx, at)
		done <- err
	})
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		var busyOpen, otherClosed bool
		if err := d.pool.QueryRow(ctx, `SELECT
			(SELECT closed_at IS NULL AND assignments_open FROM control.service_runs WHERE id=$1),
			(SELECT state='closed' AND closed_at>=publisher_expires_at AND NOT assignments_open
			 FROM control.service_runs WHERE id=$2)`, busy.run.RunID, other.run.RunID).Scan(&busyOpen, &otherClosed); err != nil {
			t.Fatal("observe unrelated expiration progress within the original five-second caller", err)
		}
		if !busyOpen {
			t.Fatal("expiration changed the busy run while its owner/service gate stayed held")
		}
		if otherClosed {
			break
		}
		if received {
			t.Fatal("expiration returned without closing the unrelated expired run", count)
		}
		select {
		case err := <-done:
			received = true
			if err != nil {
				t.Fatal("expiration failed while another owner was busy", err)
			}
		case <-ctx.Done():
			t.Fatal("busy expired owner prevented unrelated progress within the original five-second caller", ctx.Err())
		case <-tick.C:
		}
	}
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if !received {
		if err := awaitIntegrationResult(t, ctx, done); err != nil {
			received = true
			t.Fatal("expiration failed after the busy owner was released", err)
		}
		received = true
	}
	if count < 1 || count > 2 {
		t.Fatal("expiration did not report its exact completed candidates", count)
	}
	// a worker may skip the busy candidate or finish it after release. neither
	// choice may prevent the unrelated durable progress already observed above.
	if remaining, err := d.ExpireServiceRuns(ctx, at); err != nil || remaining != 2-count {
		t.Fatal("released owner did not finish within the same five-second caller", remaining, count, err)
	}
	var closed bool
	if err := d.pool.QueryRow(ctx, `SELECT state='closed' AND closed_at>=publisher_expires_at AND NOT assignments_open
		FROM control.service_runs WHERE id=$1`, busy.run.RunID).Scan(&closed); err != nil || !closed {
		t.Fatal("released busy run retained publication authority", err)
	}
	assertAssignmentTotals(t, d.pool, 0)
}

func TestIntegrationCapacityRestorationUnrelatedStartReclaimsExpiredReservations(t *testing.T) {
	f := newServicePublicationFixture(t)
	d, now := f.database, f.now
	other := newRestorationOtherTeamPublication(t, f, "capacity", now)
	if other.service.TeamID == f.service.TeamID {
		t.Fatal("capacity contrast requires different teams")
	}
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.relay_leases SET connection_capacity=1`); err != nil {
		t.Fatal(err)
	}
	prepared, err := d.PrepareServiceRun(t.Context(), other.service.ID, other.publisher, "first", now,
		ServiceRunRequest{Metadata: other.service.ServiceMetadata})
	if err != nil {
		t.Fatal(err)
	}
	assertAssignmentTotals(t, d.pool, 2)
	onlyCapacityDenial := func(err error) bool {
		var insufficient, capacity int
		var inspect func(error) bool
		inspect = func(cause error) bool {
			switch cause {
			case ErrInsufficientRelayServices:
				insufficient++
				return true
			case errRelayPlacementCapacity:
				capacity++
				return true
			case nil:
				return false
			}
			if joined, ok := cause.(interface{ Unwrap() []error }); ok {
				children := joined.Unwrap()
				if len(children) == 0 {
					return false
				}
				for _, child := range children {
					if !inspect(child) {
						return false
					}
				}
				return true
			}
			if wrapped, ok := cause.(interface{ Unwrap() error }); ok {
				return inspect(wrapped.Unwrap())
			}
			return false
		}
		return inspect(err) && insufficient == 1 && capacity == 1
	}
	if _, err := d.StartServiceRun(t.Context(), other.service.ID, prepared.RunID, prepared.RunNumber, other.publisher,
		now.Add(time.Second)); !onlyCapacityDenial(err) {
		t.Fatal("live first run did not retain both capacity-one reservations", err)
	}
	assertAssignmentTotals(t, d.pool, 2)
	// this retains admission-triggered reclamation, not cleanup followed by
	// admission. do not run a sweep or start a background cleanup worker here.
	later := f.run.ExpiresAt
	started, err := d.StartServiceRun(t.Context(), other.service.ID, prepared.RunID, prepared.RunNumber, other.publisher, later)
	if err != nil {
		t.Fatal("unrelated start alone did not reclaim the expired first run's reservations", err)
	}
	if started.RunID != prepared.RunID || started.RunNumber != prepared.RunNumber || len(started.Connections) != 2 {
		t.Fatal("unrelated prepared run did not start with its own two assignments")
	}
	assertAssignmentTotals(t, d.pool, 2)
	var closed bool
	if err := d.pool.QueryRow(t.Context(), `SELECT state='closed' AND closed_at>=publisher_expires_at AND NOT assignments_open
		AND (SELECT count(*)=2 FROM control.service_connection_slots WHERE service_run_id=$1 AND NOT session_open)
		FROM control.service_runs WHERE id=$1`, f.run.RunID).Scan(&closed); err != nil || !closed {
		t.Fatal("expired first run retained publication or reservation authority", err)
	}
}

func newRestorationOtherTeamPublication(t *testing.T, f servicePublicationFixture, name string, now time.Time) servicePublicationFixture {
	t.Helper()
	d, actor := f.database, f.actor(t)
	team, err := d.CreateTeam(t.Context(), CreateTeamRequest{
		IdentityID: actor, DisplayName: name + "-team", MemberSlug: "owner",
		IdempotencyKey: name + "-team", RequestDigest: sha256.Sum256([]byte(name + "-team")),
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	service, err := d.CreateServiceAt(t.Context(), team.ID, actor, name, name, ServicePlacement{}, now,
		ServiceMetadata{Protocol: "http"}, &ProjectServiceConfiguration{Target: "localhost:3000"})
	if err != nil {
		t.Fatal(err)
	}
	enrollment := publisherEnrollment(t, d, serviceTestAuthority{TeamID: team.ID, ActingIdentityID: actor},
		PublisherScope{TeamID: team.ID, Kind: "service", ServiceID: service.ID}, now)
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := d.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, now)
	if err != nil {
		t.Fatal(err)
	}
	return servicePublicationFixture{database: d, now: now, service: service, publisher: publisher, leases: f.leases}
}
