package ingress

import (
	"crypto/ed25519"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func observationProducerFixture(t *testing.T, clock func() time.Time) (*publicVisitorRun, ingressv1.IngressRoutingTableEntry, ingressv1.IngressLease, streamAllocation, visitorlease.Update) {
	t.Helper()
	now := clock()
	a := reservationAllocation(now)
	a.ResourceKind, a.ResourceID, a.RunID = "public_url", "url_"+strings.Repeat("B", 22), "pr_"+strings.Repeat("C", 22)
	pool := newStreamReservations(clock)
	t.Cleanup(pool.Close)
	if err := pool.apply(a, now); err != nil {
		t.Fatal(err)
	}
	scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: a.ResourceID}
	policy, err := visitorlease.New(scope, clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(policy.Close)
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("k", 32)))
	update := visitorlease.Update{View: visitortoken.View{Scope: scope, Issuer: "https://control.example.test", Hostname: "preview.example.test", Port: 443,
		VisitorPolicyRevision: 1, ObservedAt: now, ValidUntil: now.Add(10 * time.Second)}.WithVerificationKeys(map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}),
		Enabled: true, Snapshot: true, KeyRevision: 1, Allocations: map[string]controlv1.StreamCapacityAllocation{a.ID: {
			Id: a.ID, Resource: controlv1.VisitorResourceScope{Kind: "public_url", Id: a.ResourceID}, RunId: a.RunID, RunNumber: int64(a.RunNumber), IngressId: a.IngressID, IngressRunId: a.IngressRunID, IngressLeaseRevision: int64(a.IngressLeaseRevision),
			ObservedAt: now, ValidUntil: a.ValidUntil, Capacity: a.Capacity, ReservationKey: a.ProofKey[:],
		}}}
	if err := policy.Apply(policy.Begin(), update); err != nil {
		t.Fatal(err)
	}
	process := ingressv1.IngressLease{IngressId: a.IngressID, IngressRunId: a.IngressRunID, IngressLeaseRevision: int64(a.IngressLeaseRevision), LeaseExpiresAt: now.Add(time.Minute)}
	run := &publicVisitorRun{capacity: &streamCapacity{owner: process, pool: pool, id: a.ID, ready: true, publisherUntil: now.Add(30 * time.Second)}, policy: &visitorPolicy{lease: policy}}
	entry := ingressv1.IngressRoutingTableEntry{PublicUrlId: a.ResourceID, PublishRunId: a.RunID, PublishRunNumber: int64(a.RunNumber), CanonicalHostname: update.View.Hostname}
	return run, entry, process, a, update
}

func TestPublicReadinessObservationClipsInstalledAllocationDeadline(t *testing.T) {
	start := time.Now()
	now := start
	run, entry, process, a, update := observationProducerFixture(t, func() time.Time { return now })
	now = start.Add(8 * time.Second)
	update.View.ObservedAt, update.View.ValidUntil = now, now.Add(10*time.Second)
	if err := run.policy.lease.Apply(run.policy.lease.Begin(), update); err != nil {
		t.Fatal(err)
	}
	now = start.Add(9 * time.Second)
	a.ObservedAt, a.ValidUntil = now, now.Add(10*time.Second)
	if err := run.capacity.pool.apply(a, now); err != nil {
		t.Fatal(err)
	}
	observed := run.observationsFor(entry, process, now)
	if len(observed) != 1 || !observed[0].ValidUntil.Equal(start.Add(10*time.Second)) {
		t.Fatal("renewed local setup extended the allocation in the installed policy", observed)
	}
	shortProcess := process
	shortProcess.LeaseExpiresAt = now.Add(500 * time.Millisecond)
	if observation := run.observationsFor(entry, shortProcess, now); len(observation) != 1 || !observation[0].ValidUntil.Equal(shortProcess.LeaseExpiresAt) {
		t.Fatal("observation exceeded the current process deadline")
	}
	// the response carrying the renewed allocation was never installed.
	now = start.Add(11 * time.Second)
	if len(run.observationsFor(entry, process, now)) != 0 {
		t.Fatal("withheld policy response left expired allocation evidence usable")
	}
}

func TestPublicReadinessObservationKeepsOneIdentityAcrossRollover(t *testing.T) {
	now := time.Now()
	var armed atomic.Bool
	entered, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	run, entry, process, a, _ := observationProducerFixture(t, func() time.Time {
		if armed.CompareAndSwap(true, false) {
			close(entered)
			<-release
		}
		return now
	})
	armed.Store(true)
	observed := make(chan []ingressv1.IngressStreamAllocationObservation, 1)
	worker := ingressWorker(t, func() {}, func() error { observed <- run.observationsFor(entry, process, now); return nil })
	ingressAwait(t, entered)
	if run.capacity.mu.TryLock() {
		run.capacity.mu.Unlock()
		t.Fatal("observation released capacity identity before policy membership was checked")
	}
	rolled := make(chan struct{})
	rollover := ingressWorker(t, func() {}, func() error {
		run.capacity.mu.Lock()
		defer run.capacity.mu.Unlock()
		b := a
		b.ID, b.ProofKey = "salloc_"+strings.Repeat("D", 22), [32]byte{2}
		if err := run.capacity.pool.apply(b, now); err != nil {
			return err
		}
		run.capacity.id, run.capacity.ready = b.ID, false
		close(rolled)
		return nil
	})
	// releasing the existing policy's read lets A finish; only then may B publish.
	release <- struct{}{}
	got := ingressAwait(t, observed)
	if len(got) != 1 || got[0].AllocationId != a.ID {
		t.Fatal("rollover emitted an unchecked allocation identity", got)
	}
	ingressAwait(t, rolled)
	if err := ingressAwait(t, worker); err != nil {
		t.Fatal(err)
	}
	if err := ingressAwait(t, rollover); err != nil {
		t.Fatal(err)
	}
	if len(run.observationsFor(entry, process, now)) != 0 {
		t.Fatal("unready B inherited A's observation")
	}
	run.capacity.ready = true
	if len(run.observationsFor(entry, process, now)) != 0 {
		t.Fatal("B missing from installed policy inherited A's observation")
	}
}
