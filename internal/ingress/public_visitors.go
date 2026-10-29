package ingress

import (
	"context"
	"errors"
	"net/netip"
	"sort"
	"sync"
	"time"

	ingressbackend "github.com/tnldotdev/tnl/internal/ingress/backend"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// PublicVisitorControl prepares permission policy and capacity independently of
// visitor connections. the controller owns these exact-run lifetimes.
type PublicVisitorControl interface {
	visitorPolicyClient
	streamCapacityClient
}

type publicVisitorRun struct {
	policy   *visitorPolicy
	capacity *streamCapacity
	cancel   context.CancelFunc
	done     chan struct{}
}

func preparePublicVisitorRun(ctx context.Context, client PublicVisitorControl, current func() ingressv1.IngressLease, entry ingressv1.IngressRoutingTableEntry, report func(error)) (*publicVisitorRun, error) {
	limits := trafficlimits.Default()
	if entry.Traffic != nil {
		limits.Connections = entry.Traffic.Connections
	}
	scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: entry.PublicUrlId}
	// each ingress prepares its full local setup bound. authorized capacity is
	// shared at the publisher, not split among ingresses.
	body := ingressv1.StreamCapacityRequest{Resource: controlv1.VisitorResourceScope{Kind: "public_url", Id: scope.ID}, RunId: entry.PublishRunId, RunNumber: entry.PublishRunNumber, Capacity: limits.Connections}
	capacity, err := newStreamCapacity(client, current(), body)
	if err != nil {
		return nil, err
	}
	policy, err := newVisitorPolicy(client, scope, current)
	if err != nil {
		capacity.pool.Close()
		return nil, err
	}
	life, cancel := context.WithCancel(ctx)
	r := &publicVisitorRun{policy: policy, capacity: capacity, cancel: cancel, done: make(chan struct{})}
	policy.observations = func() []ingressv1.IngressStreamAllocationObservation {
		return r.observationsFor(entry, current(), time.Now())
	}
	if err := r.refresh(life); err != nil {
		close(r.done)
		r.close(ctx)
		return nil, err
	}
	go func() {
		defer close(r.done)
		timer := time.NewTimer(capacity.refreshInterval())
		defer timer.Stop()
		for {
			select {
			case <-life.Done():
				return
			case <-timer.C:
				if err := r.refresh(life); err != nil && life.Err() == nil && report != nil {
					report(err)
				}
				timer.Reset(capacity.refreshInterval())
			}
		}
	}()
	return r, nil
}

func (r *publicVisitorRun) refresh(ctx context.Context) error {
	// one run owns fetch-through-install ordering. separate timers could keep
	// policy a capacity response behind until short publisher evidence expired.
	capacityErr := r.capacity.refresh(ctx)
	// a capacity outage must not stop policy renewal for still-live admissions.
	return errors.Join(capacityErr, r.policy.refresh(ctx))
}

func (r *publicVisitorRun) close(ctx context.Context) {
	r.cancel()
	<-r.done
	r.policy.Close()
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	_ = r.capacity.Close(cleanup)
}

func (r *publicVisitorRun) reserve(visitor string, source netip.Addr, stop func()) (*streamReservation, *visitorlease.ReservationGuard, error) {
	reservation, err := r.capacity.reserve(visitor, source, stop)
	if err != nil {
		return nil, nil, err
	}
	guard, err := r.policy.lease.BindReservationFrom(reservation.header, source, stop)
	if err != nil {
		reservation.Close()
		return nil, nil, err
	}
	return reservation, guard, nil
}

// LookupPublicURLs reads prepared state only. routing publication wakes the
// background owner; a missing policy or allocation never starts request-time I/O.
func (c *Controller) LookupPublicURLs(hostname string, forwarder *Forwarder, now time.Time) ([]PublicURL, LookupReason) {
	entries, reason := c.LookupAllWithReason(hostname, now)
	if reason != LookupCurrent {
		return nil, reason
	}
	if c.visitorControl == nil {
		return nil, LookupIngressUnavailable
	}
	routes, err := forwarder.PublicURLs(entries)
	if err != nil {
		return nil, LookupInvalidProjection
	}
	prepared := make([]PublicURL, 0, len(routes))
	process := c.Lease()
	for _, route := range routes {
		c.mu.RLock()
		run := c.publicVisitors[route.PublishRunID]
		c.mu.RUnlock()
		entry := ingressv1.IngressRoutingTableEntry{}
		for _, candidate := range entries {
			if candidate.PublishRunId == route.PublishRunID {
				entry = candidate
				break
			}
		}
		if run == nil || !run.preparedFor(entry, process, now) {
			continue
		}
		view, enabled, anonymous := run.policy.lease.Current()
		if !enabled || view.Hostname != hostname {
			continue
		}
		route.prepared = run
		if anonymous {
			route.AccessMode = "anonymous"
		} else {
			route.AccessMode = "restricted"
		}
		prepared = append(prepared, route)
	}
	if len(prepared) == 0 {
		return nil, LookupNoBackends
	}
	return prepared, LookupCurrent
}

func (c *Controller) runPublicVisitors(ctx context.Context) error {
	defer func() {
		c.mu.Lock()
		runs := c.publicVisitors
		c.publicVisitors = make(map[string]*publicVisitorRun)
		c.mu.Unlock()
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		jobs := make(chan *publicVisitorRun)
		var workers sync.WaitGroup
		for range min(8, len(runs)) {
			workers.Go(func() {
				for run := range jobs {
					run.close(cleanup)
				}
			})
		}
		for _, run := range runs {
			jobs <- run
		}
		close(jobs)
		workers.Wait()
	}()
	// discovery is independent of visitor arrivals and control's long-poll wait.
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	cursor := 0
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		process := c.Lease()
		if process.IngressLeaseRevision == 0 || process.Draining || !process.LeaseExpiresAt.After(time.Now()) {
			continue
		}
		// initial health follows local preparation, not the next process renewal.
		// starting URLs do not hold unrelated ready URLs behind this join gate.
		c.markPublicRoutingPrepared()
		c.routingTable.mu.RLock()
		current := make(map[string]ingressv1.IngressRoutingTableEntry)
		terminal := make(map[string]bool)
		for _, stored := range c.routingTable.routes {
			entry := stored.entry
			if entry.PublishRunClosed != nil && *entry.PublishRunClosed {
				terminal[entry.PublishRunId] = true
				continue
			}
			if !stored.tombstone && c.publicPool(entry) && entry.PublicUrlExpiresAt.After(time.Now()) {
				current[entry.PublishRunId] = entry
			}
		}
		c.routingTable.mu.RUnlock()
		c.mu.Lock()
		var retired []*publicVisitorRun
		for id, run := range c.publicVisitors {
			owner := run.capacity.owner
			// a missing/expired projection or temporary routing tombstone does not
			// close the run. retain its bounded prepared owner through recovery;
			// policy and allocation deadlines still fence work during an outage.
			if terminal[id] || owner.IngressRunId != process.IngressRunId || owner.IngressLeaseRevision != process.IngressLeaseRevision {
				delete(c.publicVisitors, id)
				retired = append(retired, run)
			}
		}
		var pending []string
		for id := range current {
			if c.publicVisitors[id] == nil {
				pending = append(pending, id)
			}
		}
		remaining := max(0, 4096-len(c.publicVisitors))
		c.mu.Unlock()
		for _, run := range retired {
			run.close(ctx)
		}
		if len(pending) == 0 {
			continue
		}
		sort.Strings(pending)
		start := cursor % len(pending)
		count := min(8, remaining, len(pending))
		cursor = start + max(1, count)
		var workers sync.WaitGroup
		for offset := range count {
			entry := current[pending[(start+offset)%len(pending)]]
			workers.Go(func() {
				run, err := preparePublicVisitorRun(ctx, c.visitorControl, c.Lease, entry, c.report)
				if err != nil {
					return
				}
				c.mu.Lock()
				c.publicVisitors[entry.PublishRunId] = run
				c.mu.Unlock()
			})
		}
		workers.Wait()
	}
}

func reservedBackends(backends []ingressbackend.Backend, reservation *streamReservation) []ingressbackend.Backend {
	result := make([]ingressbackend.Backend, 0, len(backends))
	for _, backend := range backends {
		bound, ok := backend.(forwardingBackend)
		if !ok {
			continue
		}
		bound.header.Reservation = reservation.header
		result = append(result, bound)
	}
	return result
}
