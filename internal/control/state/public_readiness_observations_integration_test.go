package state

import (
	"context"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func observationReadinessFixture(t *testing.T) (publishRunFixture, StreamCapacityAllocation) {
	t.Helper()
	f := newServingReadinessFixture(t)
	prepareServingPublisher(t, f)
	servingPreparationPending(t, f, f.now)
	if err := f.database.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, f.now); err != nil {
		t.Fatal(err)
	}
	owner := registerServingIngress(t, f, f.now)
	a := servingAllocation(t, f, owner, f.now)
	acknowledgeServingRouting(t, f, owner, f.now)
	return f, a
}

func TestIntegrationPublicReadinessPublisherObservationExpiresAcrossRenewal(t *testing.T) {
	f, original := observationReadinessFixture(t)
	observeServingPublisher(t, f, original, f.now)
	renewed := servingAllocation(t, f, original.Owner, f.now.Add(9*time.Second))
	if !renewed.PublisherObserved || !renewed.PublisherObservedUntil.Equal(original.ValidUntil) || !renewed.ValidUntil.After(original.ValidUntil) {
		t.Fatal("renewal did not retain the original installed publisher deadline")
	}
	observeServingIngress(t, f, renewed, f.now.Add(9*time.Second))
	later := f.now.Add(11 * time.Second)
	servingPreparationPending(t, f, later)
	current := servingAllocation(t, f, original.Owner, later)
	if current.PublisherObserved || current.ID != original.ID || current.ProofKey != original.ProofKey {
		t.Fatal("renewal resurrected expired publisher evidence or replaced the existing proof")
	}
	observeServingPublisher(t, f, current, later)
	if ready, err := f.database.MarkPublishRunReady(t.Context(), f.authentication(), later); err != nil || ready.ReadyAt == nil || !ready.ReadyAt.Equal(later) {
		t.Fatalf("fresh independent publisher observation did not restore readiness: %+v %v", ready, err)
	}
}

func TestIntegrationPublicReadinessIngressObservationRetainsInstalledDeadline(t *testing.T) {
	f, original := observationReadinessFixture(t)
	observeServingPublisher(t, f, original, f.now)
	wire, err := f.database.ReadIngressVisitorPolicy(t.Context(), original.Owner, original.Scope, 0, f.now.Add(8*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	installed := installServingTestPolicy(t, original.Scope, wire, f.now.Add(8*time.Second))
	renewed := servingAllocation(t, f, original.Owner, f.now.Add(9*time.Second))
	observeServingPublisher(t, f, renewed, f.now.Add(9*time.Second))
	observed := installed.BoundedAllocations(original.RunID)
	if len(observed) != 1 || !observed[0].ValidUntil.Equal(original.ValidUntil) {
		t.Fatal("installed ingress allocation was extended by a later database renewal")
	}
	// leave the response uninstalled, as on a stalled/lost background response.
	_, err = f.database.ReadIngressVisitorPolicy(t.Context(), original.Owner, original.Scope, wire.Policy.VisitorPolicyRevision, f.now.Add(9*time.Second),
		IngressStreamAllocationObservation{AllocationID: original.ID, RunID: original.RunID, RunNumber: original.RunNumber, ValidUntil: observed[0].ValidUntil})
	if err != nil {
		t.Fatal(err)
	}
	later := f.now.Add(11 * time.Second)
	servingPreparationPending(t, f, later)
	observeServingIngress(t, f, renewed, later)
	if ready, err := f.database.MarkPublishRunReady(t.Context(), f.authentication(), later); err != nil || ready.ReadyAt == nil {
		t.Fatalf("fresh installed ingress observation did not restore readiness: %+v %v", ready, err)
	}
}

func TestIntegrationPublicReadinessSerializesRegistrationWithFinalVisibility(t *testing.T) {
	f, allocation := observationReadinessFixture(t)
	d, now := f.database, f.now
	observeServingPublisher(t, f, allocation, now)
	observeServingIngress(t, f, allocation, now)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	gate, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := controlstatedb.New(gate).LockIngressRoutingTableClock(ctx); err != nil {
		t.Fatal(err)
	}
	final := make(chan error, 1)
	workers.Go(func() {
		_, err := d.MarkPublishRunReady(ctx, f.authentication(), now)
		final <- err
	})
	// the final mutation has selected the receivers and updated ready_at, but
	// cannot commit its final projection while this clock gate is held.
	finalPID := waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), final)
	joined := make(chan error, 1)
	var snapshot IngressRoutingTableSnapshot
	workers.Go(func() {
		lease, err := d.RegisterIngress(ctx, IngressRegistration{IngressID: "joining-during-final", IngressRunID: "new-process", IngressPoolID: PrimaryIngressPoolID, ProtocolVersion: 1, ConnectionCapacity: 8}, now, time.Minute)
		if err == nil {
			snapshot, err = d.ReadIngressRoutingTableSnapshot(ctx, lease.IngressLeaseIdentity, now)
		}
		joined <- err
	})
	waitForPostgresBlock(t, ctx, d, finalPID, joined)
	// normal renewal is not a membership writer and must remain independent.
	if _, err := d.RenewIngress(ctx, IngressRenewal{IngressLeaseIdentity: allocation.Owner}, now, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, final); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, joined); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Entries) != 1 || snapshot.Entries[0].Projection.PublishRunReadyAt == nil || !snapshot.Entries[0].Projection.PublishRunReadyAt.Equal(now) {
		t.Fatal("joining receiver could obtain the old starting snapshot after final receiver selection")
	}
}
