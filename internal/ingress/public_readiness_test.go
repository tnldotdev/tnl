package ingress

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
)

func readinessEvent(now time.Time, revision, run int64, hostname string, ready bool) ingressv1.IngressRoutingTableEvent {
	entry := forwardingTestEntry(now, "relay.example:443")
	entry.CanonicalHostname = hostname
	entry.PolicyRevision = 1
	entry.IpPolicy = ingressv1.AllowAll
	entry.PublishRunNumber = run
	entry.PublishRunId = fmt.Sprintf("run-%d", run)
	if ready {
		entry.PublishRunReadyAt = &now
	}
	return ingressv1.IngressRoutingTableEvent{RoutingTableRevision: revision, Kind: ingressv1.PublicUrlUpsert,
		PublicUrlId: entry.PublicUrlId, PublishRunNumber: run, CanonicalHostname: hostname, EntryRevision: revision,
		Entry: entry, PublicUrlExpiresAt: &entry.PublicUrlExpiresAt, CreatedAt: now}
}

func TestPublicReadinessJoinAndPublisherIsolation(t *testing.T) {
	now := time.Now().UTC()
	c := testLeaseController(t, leaseTestClient{})
	lease := testIngressLease(now)
	if err := c.setLease(lease); err != nil {
		t.Fatal(err)
	}
	first := readinessEvent(now, 1, 1, "pool.example", true)
	sibling := readinessEvent(now, 2, 2, "pool.example", false)
	unrelated := readinessEvent(now, 3, 3, "other.example", false)
	if err := c.routingTable.ApplySnapshot(ingressv1.IngressRoutingTableSnapshot{ThroughRevision: 3, Entries: []ingressv1.IngressRoutingTableEvent{first, sibling, unrelated}}); err != nil {
		t.Fatal(err)
	}
	c.markRoutingTableCurrent(true)
	installed := map[string]bool{}
	until := now.Add(10 * time.Second)
	c.publicRunPrepared = func(entry ingressv1.IngressRoutingTableEntry, owner ingressv1.IngressLease, at time.Time) (time.Time, bool) {
		return until, installed[entry.PublishRunId] && owner.IngressRunId == lease.IngressRunId && owner.IngressLeaseRevision == lease.IngressLeaseRevision && at.Before(until)
	}
	if c.Ready(now) {
		t.Fatal("new ingress joined before installing existing ready run")
	}
	installed[first.Entry.PublishRunId] = true
	if !c.Ready(now) {
		t.Fatal("starting runs blocked the existing ready run's health")
	}
	entries, reason := c.LookupAllWithReason("pool.example", now)
	if reason != LookupCurrent || len(entries) != 1 || entries[0].PublishRunId != first.Entry.PublishRunId {
		t.Fatal("starting publisher blocked or joined its healthy sibling", entries, reason)
	}
	if _, reason := c.LookupAllWithReason("other.example", now); reason != LookupNoBackends {
		t.Fatal(reason)
	}
	observations := c.publicRunObservations(lease, now)
	if len(observations) != 1 || observations[0].EntryRevision != 1 || !observations[0].ValidUntil.Equal(until) {
		t.Fatal(observations)
	}
	installed[sibling.Entry.PublishRunId] = true
	if entries, reason := c.LookupAllWithReason("pool.example", now); reason != LookupCurrent || len(entries) != 2 {
		t.Fatal(entries, reason)
	}
	observations = c.publicRunObservations(lease, now)
	if len(observations) != 2 || observations[1].EntryRevision != 2 || !observations[1].ValidUntil.Equal(until) {
		t.Fatal(observations)
	}
	// a joined ingress fences an expired run individually, including a first
	// visitor lookup at the exact deadline; lease renewal does not install policy.
	if !c.Ready(until) {
		t.Fatal("run expiry became a global health barrier")
	}
	if _, reason := c.LookupAllWithReason("pool.example", until); reason != LookupNoBackends {
		t.Fatal("expired policy selected", reason)
	}
	if observations := c.publicRunObservations(lease, until); len(observations) != 0 {
		t.Fatal("expired policy observed", observations)
	}
}

func TestPublicReadinessProcessDrainAndDeadlineFences(t *testing.T) {
	now := time.Now().UTC()
	c := testLeaseController(t, leaseTestClient{})
	lease := testIngressLease(now)
	lease.LeaseExpiresAt = now.Add(5 * time.Second)
	entry := readinessEvent(now, 1, 1, "ready.example", false).Entry
	c.publicRunPrepared = func(_ ingressv1.IngressRoutingTableEntry, owner ingressv1.IngressLease, _ time.Time) (time.Time, bool) {
		return now.Add(time.Minute), owner.IngressRunId == lease.IngressRunId && owner.IngressLeaseRevision == lease.IngressLeaseRevision
	}
	if until, ok := c.publicRunInstalled(entry, lease, now); !ok || !until.Equal(lease.LeaseExpiresAt) {
		t.Fatal("observation escaped process deadline", until, ok)
	}
	for _, change := range []func(*ingressv1.IngressLease){
		func(l *ingressv1.IngressLease) { l.IngressRunId = "different" },
		func(l *ingressv1.IngressLease) { l.IngressLeaseRevision++ },
		func(l *ingressv1.IngressLease) { l.Draining = true },
		func(l *ingressv1.IngressLease) { l.LeaseExpiresAt = now },
	} {
		changed := lease
		change(&changed)
		if _, ok := c.publicRunInstalled(entry, changed, now); ok {
			t.Fatal("stale process prepared a run")
		}
	}
	entry.PublicUrlExpiresAt = now.Add(time.Second)
	if until, ok := c.publicRunInstalled(entry, lease, now); !ok || !until.Equal(entry.PublicUrlExpiresAt) {
		t.Fatal("observation escaped run deadline", until, ok)
	}
	if _, ok := c.publicRunInstalled(entry, lease, entry.PublicUrlExpiresAt); ok {
		t.Fatal("expired run prepared")
	}
}

type readinessRenewClient struct {
	ControlClient
	lease    ingressv1.IngressLease
	requests chan ingressv1.IngressRenewal
}

func (client readinessRenewClient) RenewIngress(ctx context.Context, _ ingressv1.IngressID, request ingressv1.IngressRenewal) (ingressv1.IngressLease, error) {
	select {
	case client.requests <- request:
	case <-ctx.Done():
		return ingressv1.IngressLease{}, ctx.Err()
	}
	return client.lease, nil
}

func TestPublicReadinessAcknowledgesInstallationWithoutWaitingForPeriodicRenewal(t *testing.T) {
	now := time.Now().UTC()
	lease := testIngressLease(now)
	client := readinessRenewClient{lease: lease, requests: make(chan ingressv1.IngressRenewal, 2)}
	c := testLeaseController(t, client)
	c.renewalInterval = time.Hour
	if err := c.setLease(lease); err != nil {
		t.Fatal(err)
	}
	event := readinessEvent(now, 1, 1, "ready.example", false)
	if err := c.routingTable.ApplySnapshot(ingressv1.IngressRoutingTableSnapshot{ThroughRevision: 1, Entries: []ingressv1.IngressRoutingTableEvent{event}}); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	installed := false
	c.publicRunPrepared = func(ingressv1.IngressRoutingTableEntry, ingressv1.IngressLease, time.Time) (time.Time, bool) {
		mu.Lock()
		defer mu.Unlock()
		return now.Add(time.Minute), installed
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- c.renewLoop(ctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	wait := func() ingressv1.IngressRenewal {
		select {
		case request := <-client.requests:
			return request
		case <-time.After(time.Second):
			t.Fatal("installed state waited for periodic renewal")
			return ingressv1.IngressRenewal{}
		}
	}
	c.ServingStateChanged()
	if request := wait(); request.PreparedPublicRuns == nil || len(*request.PreparedPublicRuns) != 0 {
		t.Fatal("fetch start acknowledged future policy", request)
	}
	mu.Lock()
	installed = true
	mu.Unlock()
	c.ServingStateChanged()
	request := wait()
	if request.PreparedPublicRuns == nil || len(*request.PreparedPublicRuns) != 1 || (*request.PreparedPublicRuns)[0].PublishRunId != event.Entry.PublishRunId {
		t.Fatal(request)
	}
}

func TestPublicReadinessReportsAllInstalledPagesBeforeExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now().UTC()
		lease := testIngressLease(now)
		client := readinessRenewClient{lease: lease, requests: make(chan ingressv1.IngressRenewal, 16)}
		c := testLeaseController(t, client)
		c.renewalInterval = 10 * time.Second
		if err := c.setLease(lease); err != nil {
			t.Fatal(err)
		}
		const count = 2001
		events := make([]ingressv1.IngressRoutingTableEvent, count)
		for i := range events {
			events[i] = readinessEvent(now, int64(i+1), int64(i+1), "ready.example", false)
		}
		if err := c.routingTable.ApplySnapshot(ingressv1.IngressRoutingTableSnapshot{ThroughRevision: count, Entries: events}); err != nil {
			t.Fatal(err)
		}
		until := now.Add(20 * time.Second)
		c.publicRunPrepared = func(_ ingressv1.IngressRoutingTableEntry, _ ingressv1.IngressLease, at time.Time) (time.Time, bool) {
			return until, at.Before(until)
		}
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- c.renewLoop(ctx) }()
		defer func() {
			cancel()
			if err := <-done; err != nil {
				t.Error(err)
			}
		}()
		c.ServingStateChanged()
		synctest.Wait()
		time.Sleep(20 * time.Second)
		synctest.Wait()
		observed := make(map[string]bool)
		for len(client.requests) > 0 {
			request := <-client.requests
			if request.PreparedPublicRuns == nil || len(*request.PreparedPublicRuns) > 1000 {
				t.Fatal("unbounded observation request")
			}
			for _, observation := range *request.PreparedPublicRuns {
				observed[observation.PublishRunId] = true
			}
		}
		if len(observed) != count {
			t.Fatalf("reported %d of %d installed runs before their policy expired", len(observed), count)
		}
	})
}

type gatedReadinessRenewClient struct {
	ControlClient
	lease    ingressv1.IngressLease
	requests chan ingressv1.IngressRenewal
	resume   chan struct{}
}

func (client gatedReadinessRenewClient) RenewIngress(ctx context.Context, _ ingressv1.IngressID, request ingressv1.IngressRenewal) (ingressv1.IngressLease, error) {
	select {
	case client.requests <- request:
	case <-ctx.Done():
		return ingressv1.IngressLease{}, ctx.Err()
	}
	select {
	case <-client.resume:
		lease := client.lease
		lease.RenewedAt = time.Now()
		lease.LeaseExpiresAt = lease.RenewedAt.Add(time.Minute)
		return lease, nil
	case <-ctx.Done():
		return ingressv1.IngressLease{}, ctx.Err()
	}
}

func TestPublicReadinessPagesRevalidateChurnBeforeNewSnapshot(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now().UTC()
		lease := testIngressLease(now)
		client := gatedReadinessRenewClient{lease: lease, requests: make(chan ingressv1.IngressRenewal, 1), resume: make(chan struct{})}
		c := testLeaseController(t, client)
		c.renewalInterval = 10 * time.Second
		if err := c.setLease(lease); err != nil {
			t.Fatal(err)
		}
		const count = 2001
		events := make([]ingressv1.IngressRoutingTableEvent, count)
		deadlines := make(map[string]time.Time)
		until := now.Add(20 * time.Second)
		for i := range events {
			events[i] = readinessEvent(now, int64(i+1), int64(i+1), "ready.example", false)
			events[i].Entry.PublishRunId = fmt.Sprintf("run-%04d", i+1)
			deadlines[events[i].Entry.PublishRunId] = until
		}
		if err := c.routingTable.ApplySnapshot(ingressv1.IngressRoutingTableSnapshot{ThroughRevision: count, Entries: events}); err != nil {
			t.Fatal(err)
		}
		checks := 0
		c.publicRunPrepared = func(entry ingressv1.IngressRoutingTableEntry, _ ingressv1.IngressLease, at time.Time) (time.Time, bool) {
			checks++
			deadline := deadlines[entry.PublishRunId]
			return deadline, at.Before(deadline)
		}
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- c.renewLoop(ctx) }()
		defer func() {
			cancel()
			if err := <-done; err != nil {
				t.Error(err)
			}
		}()
		page := func() map[string]ingressv1.IngressPublicRunObservation {
			t.Helper()
			select {
			case request := <-client.requests:
				if request.PreparedPublicRuns == nil || len(*request.PreparedPublicRuns) > 1000 {
					t.Fatal("unbounded observation request")
				}
				result := make(map[string]ingressv1.IngressPublicRunObservation)
				for _, observation := range *request.PreparedPublicRuns {
					result[observation.PublishRunId] = observation
				}
				return result
			case <-time.After(time.Second):
				t.Fatal("pending page waited for periodic renewal")
				return nil
			}
		}
		c.ServingStateChanged()
		if first := page(); len(first) != 1000 || first["run-0001"].EntryRevision != 1 {
			t.Fatal("first page", len(first))
		}
		// the first request is held while a resnapshot drops one run, a page
		// tombstones another, and a newer revision replaces a pending entry.
		snapshot := append([]ingressv1.IngressRoutingTableEvent{}, events[:1005]...)
		snapshot = append(snapshot, events[1006:]...)
		if err := c.routingTable.ApplySnapshot(ingressv1.IngressRoutingTableSnapshot{ThroughRevision: count, Entries: snapshot}); err != nil {
			t.Fatal(err)
		}
		removed, newer := events[1000], events[1003]
		removed.Kind, removed.RoutingTableRevision, removed.EntryRevision = ingressv1.PublicUrlTombstone, count+1, count+1
		removed.PublicUrlExpiresAt, removed.Entry.PublisherConnections = nil, nil
		newer.RoutingTableRevision, newer.EntryRevision = count+2, count+2
		if err := c.routingTable.ApplyPage(count, ingressv1.IngressRoutingTablePage{ThroughRevision: count + 2, NextRevision: count + 2,
			Events: []ingressv1.IngressRoutingTableEvent{removed, newer}}); err != nil {
			t.Fatal(err)
		}
		deadlines["run-1002"] = now.Add(time.Second)
		delete(deadlines, "run-1003")
		deadlines["run-1005"] = until.Add(20 * time.Second)
		c.ServingStateChanged()
		time.Sleep(2 * time.Second)
		client.resume <- struct{}{}
		second := page()
		if len(second) != 995 || !second["run-1005"].ValidUntil.Equal(until) {
			t.Fatal("pending page retained stale entries or extended its deadline", len(second), second["run-1005"])
		}
		for _, id := range []string{"run-1001", "run-1002", "run-1003", "run-1004", "run-1006"} {
			if _, ok := second[id]; ok {
				t.Fatal("reported removed, expired, withdrawn or replaced entry", id)
			}
		}
		c.ServingStateChanged() // more churn must not restart the pending snapshot.
		client.resume <- struct{}{}
		if tail := page(); len(tail) != 1 || tail["run-2001"].EntryRevision != 2001 {
			t.Fatal("churn starved the pending tail", tail)
		}
		if checks > 2*count {
			t.Fatal("rebuilt installation observations for each page", checks)
		}
		if !c.Lease().RenewedAt.Equal(now.Add(2 * time.Second)) {
			t.Fatal("paging did not renew the process lease")
		}
		client.resume <- struct{}{}
		if first := page(); len(first) != 1000 {
			t.Fatal("new installation notification was lost", len(first))
		}
		client.resume <- struct{}{}
		fresh := page()
		if len(fresh) != 997 || fresh["run-1004"].EntryRevision != count+2 ||
			!fresh["run-1005"].ValidUntil.Equal(deadlines["run-1005"]) {
			t.Fatal("new snapshot did not report newer installed evidence", len(fresh), fresh["run-1004"], fresh["run-1005"])
		}
		client.resume <- struct{}{}
		synctest.Wait()
		if len(client.requests) != 0 {
			t.Fatal("old page was sent after newer installation")
		}
		// ordinary renewal still runs once all notification pages have drained.
		time.Sleep(10 * time.Second)
		if periodic := page(); len(periodic) != 1000 {
			t.Fatal("paging displaced periodic renewal", len(periodic))
		}
		// cancel with the periodic request held and another page pending.
	})
}

func TestPublicReadinessCancellationJoinsPendingPageAndRouting(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now().UTC()
		lease := testIngressLease(now)
		events := make([]ingressv1.IngressRoutingTableEvent, 2001)
		for i := range events {
			events[i] = readinessEvent(now, int64(i+1), int64(i+1), "ready.example", false)
		}
		routingStopped := make(chan struct{})
		client := gatedReadinessRenewClient{
			lease: lease, requests: make(chan ingressv1.IngressRenewal, 1), resume: make(chan struct{}),
			ControlClient: leaseTestClient{
				register: func(context.Context, ingressv1.IngressRegistration) (ingressv1.IngressLease, error) {
					return lease, nil
				},
				snapshot: func(context.Context) (ingressv1.IngressRoutingTableSnapshot, error) {
					return ingressv1.IngressRoutingTableSnapshot{ThroughRevision: 2001, Entries: events}, nil
				},
				events: func(ctx context.Context) (ingressv1.IngressRoutingTablePage, error) {
					defer close(routingStopped)
					<-ctx.Done()
					return ingressv1.IngressRoutingTablePage{}, ctx.Err()
				},
			},
		}
		c := testLeaseController(t, client)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- c.Run(ctx) }()
		synctest.Wait()
		if len(client.requests) != 1 {
			t.Fatal("renewal did not start its first page")
		}
		cancel()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		select {
		case <-routingStopped:
		default:
			t.Fatal("controller returned before joining routing")
		}
		if len(client.requests) != 1 || c.Lease().IngressLeaseRevision != 0 {
			t.Fatal("cancellation started another page or retained the lease")
		}
	})
}
