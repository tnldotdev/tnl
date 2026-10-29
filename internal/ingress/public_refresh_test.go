package ingress

import (
	"context"
	"crypto/ed25519"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// a publisher reports its previously installed allocation, not the response it
// is about to install. keep the six-second process bound used by runtime tests.
type shortLeasePreparation struct {
	mu        sync.Mutex
	latest    controlv1.StreamCapacityAllocation
	installed controlv1.StreamCapacityAllocation
	publisher time.Time
	observed  int
	retired   atomic.Int64
	first     chan struct{}
}

func (c *shortLeasePreparation) AllocateStreamCapacity(_ context.Context, ingress string, body ingressv1.StreamCapacityRequest) (controlv1.StreamCapacityAllocation, error) {
	now := time.Now()
	c.mu.Lock()
	until := c.publisher
	c.mu.Unlock()
	// policy can run while this ordinary control request is in flight.
	time.Sleep(20 * time.Millisecond)
	c.mu.Lock()
	defer c.mu.Unlock()
	a := controlv1.StreamCapacityAllocation{Id: "salloc_" + strings.Repeat("A", 22), Resource: body.Resource, RunId: body.RunId, RunNumber: body.RunNumber,
		IngressId: ingress, IngressRunId: body.IngressRunId, IngressLeaseRevision: body.IngressLeaseRevision, Capacity: body.Capacity,
		ObservedAt: now, ValidUntil: now.Add(6 * time.Second), ReservationKey: []byte(strings.Repeat("k", 32))}
	if !until.IsZero() {
		a.PublisherObservedUntil, a.PublisherObserved = &until, until.After(now)
	}
	c.latest = a
	if c.first != nil {
		close(c.first)
		c.first = nil
	}
	return a, nil
}

func (c *shortLeasePreparation) ReadIngressVisitorPolicy(_ context.Context, _ string, body ingressv1.IngressVisitorPolicyRequest) (controlv1.VisitorPolicyUpdate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if body.ObservedAllocations != nil {
		for _, observation := range *body.ObservedAllocations {
			if observation.ValidUntil.After(now) && c.publisher.After(now) {
				c.observed++
			}
		}
	}
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("i", 32)))
	a := c.latest
	a.ObservedAt = now
	time.Sleep(time.Millisecond)
	return controlv1.VisitorPolicyUpdate{AfterRevision: body.AfterRevision, SnapshotRequired: body.AfterRevision == 0, Revisions: []int64{},
		Policy: controlv1.VisitorPolicySnapshot{Resource: body.Resource, Hostname: "preview.example.test", Port: 443, Issuer: "https://control.example.test",
			VisitorPolicyRevision: 1, KeyRevision: 1, ObservedAt: now, ValidUntil: now.Add(10 * time.Second), Enabled: true, Anonymous: true,
			VerificationKeys: []controlv1.VisitorVerificationKey{{Id: "key", PublicKey: key.Public().(ed25519.PublicKey)}}, StreamAllocations: []controlv1.StreamCapacityAllocation{a}}}, nil
}

func (c *shortLeasePreparation) RetireStreamCapacity(context.Context, string, string, ingressv1.StreamCapacityRetirement) error {
	c.retired.Add(1)
	return nil
}

func TestPublicReadinessRefreshProgressesWithShortProcessLeases(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		client := &shortLeasePreparation{first: make(chan struct{})}
		first := client.first
		process := testIngressLease(time.Now())
		process.LeaseExpiresAt = time.Now().Add(6 * time.Second)
		entry := ingressv1.IngressRoutingTableEntry{PublicUrlId: "url_" + strings.Repeat("B", 22), PublishRunId: "pr_" + strings.Repeat("C", 22), PublishRunNumber: 1,
			CanonicalHostname: "preview.example.test", PublicUrlExpiresAt: time.Now().Add(time.Hour)}
		c := &Controller{lease: process, now: time.Now, visitorControl: client, publicVisitors: make(map[string]*publicVisitorRun),
			routingTable: &RoutingTable{initialized: true, revision: 1, routes: map[string]routingTableEntry{"starting": {entry: entry}}}}
		var workers sync.WaitGroup
		workers.Go(func() { _ = c.runPublicVisitors(ctx) })
		workers.Go(func() {
			select {
			case <-first:
			case <-ctx.Done():
				return
			}
			time.Sleep(2 * time.Millisecond)
			ticker := time.NewTicker(2 * time.Second)
			defer ticker.Stop()
			for {
				client.mu.Lock()
				client.publisher, client.installed = client.installed.ValidUntil, client.latest
				client.mu.Unlock()
				c.mu.Lock()
				c.lease.RenewedAt, c.lease.LeaseExpiresAt = time.Now(), time.Now().Add(6*time.Second)
				c.mu.Unlock()
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
			}
		})
		defer func() { cancel(); workers.Wait() }()
		time.Sleep(10 * time.Second)
		synctest.Wait()
		client.mu.Lock()
		observed := client.observed
		client.mu.Unlock()
		if observed == 0 {
			t.Fatal("live background preparation never reported an ingress installation")
		}
		c.mu.RLock()
		original := c.publicVisitors[entry.PublishRunId]
		c.mu.RUnlock()
		// both publisher connections can disappear without closing the run.
		// even an idle preparation must keep its identity through this tombstone.
		c.routingTable.mu.Lock()
		c.routingTable.routes["starting"] = routingTableEntry{tombstone: true, entry: entry}
		c.routingTable.mu.Unlock()
		time.Sleep(4 * time.Second)
		synctest.Wait()
		c.mu.RLock()
		during := c.publicVisitors[entry.PublishRunId]
		c.mu.RUnlock()
		if during != original || client.retired.Load() != 0 {
			t.Fatal("temporary routing loss retired the live run's prepared allocation")
		}
		c.routingTable.mu.Lock()
		c.routingTable.routes["starting"] = routingTableEntry{entry: entry}
		c.routingTable.mu.Unlock()
		time.Sleep(time.Second)
		synctest.Wait()
		c.mu.RLock()
		recovered := c.publicVisitors[entry.PublishRunId]
		c.mu.RUnlock()
		if recovered != original {
			t.Fatal("recovery replaced a live run's preparation owner")
		}
		entry.PublishRunClosed = new(true)
		c.routingTable.mu.Lock()
		c.routingTable.routes["starting"] = routingTableEntry{tombstone: true, entry: entry}
		c.routingTable.mu.Unlock()
		time.Sleep(time.Second)
		synctest.Wait()
		c.mu.RLock()
		remaining := len(c.publicVisitors)
		c.mu.RUnlock()
		if remaining != 0 || client.retired.Load() != 1 {
			t.Fatal("confirmed closure did not retire the retained preparation exactly once")
		}
	})
}

func TestPublicReadinessUsesRenewedProcessDeadline(t *testing.T) {
	now := time.Now()
	run, entry, process, _, _ := observationProducerFixture(t, func() time.Time { return now })
	entry.PublicUrlExpiresAt = now.Add(time.Minute)
	run.capacity.owner.LeaseExpiresAt = now.Add(-time.Second)
	c := &Controller{lease: process, now: func() time.Time { return now }, publicVisitors: map[string]*publicVisitorRun{entry.PublishRunId: run},
		routingTable: &RoutingTable{initialized: true, revision: 1, routes: map[string]routingTableEntry{"ready": {entry: entry}}}}
	entry.PublishRunReadyAt = &now
	c.routingTable.routes["ready"] = routingTableEntry{entry: entry}
	if !c.publicRoutingPrepared(1, now) {
		t.Fatal("initial process deadline overrode the renewed current process")
	}
	process.LeaseExpiresAt = now
	c.lease = process
	if c.publicRoutingPrepared(1, now) {
		t.Fatal("expired current process retained prepared authority")
	}
}

type heldPublicPolicy struct {
	capacityClientFixture
	armed            atomic.Bool
	entered, release chan struct{}
}

func (c *heldPublicPolicy) ReadIngressVisitorPolicy(ctx context.Context, id string, body ingressv1.IngressVisitorPolicyRequest) (controlv1.VisitorPolicyUpdate, error) {
	if c.armed.CompareAndSwap(true, false) {
		close(c.entered)
		<-c.release
	}
	return c.capacityClientFixture.ReadIngressVisitorPolicy(ctx, id, body)
}

func TestPublicReadinessRetirementJoinsEnteredRefresh(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client := &heldPublicPolicy{entered: make(chan struct{}), release: make(chan struct{})}
		release := sync.OnceFunc(func() { close(client.release) })
		process := testIngressLease(time.Now())
		run, err := preparePublicVisitorRun(t.Context(), client, func() ingressv1.IngressLease { return process }, ingressv1.IngressRoutingTableEntry{
			PublicUrlId: "url_" + strings.Repeat("B", 22), PublishRunId: "pr_" + strings.Repeat("C", 22), PublishRunNumber: 1,
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { release(); run.close(context.Background()) }()
		client.armed.Store(true)
		time.Sleep(2 * time.Second)
		synctest.Wait()
		<-client.entered
		closed := make(chan struct{})
		go func() { run.close(context.Background()); close(closed) }()
		synctest.Wait()
		select {
		case <-closed:
			t.Fatal("retirement returned before the entered refresh joined")
		default:
		}
		run.capacity.pool.mu.Lock()
		poolClosed := run.capacity.pool.closed
		run.capacity.pool.mu.Unlock()
		if poolClosed {
			t.Fatal("retirement closed child state while refresh still owned it")
		}
		release()
		<-closed
		run.capacity.pool.mu.Lock()
		poolClosed = run.capacity.pool.closed
		run.capacity.pool.mu.Unlock()
		_, enabled, _ := run.policy.lease.Current()
		if !poolClosed || enabled || client.retired.Load() != 1 {
			t.Fatal("retirement did not close and retire the joined children exactly once")
		}
	})
}
