package ingress

import (
	"context"
	"sort"
	"sync"
	"time"

	ingressbackend "github.com/tnldotdev/tnl/internal/ingress/backend"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

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
	for _, route := range routes {
		c.mu.RLock()
		run := c.publicVisitors[route.PublishRunID]
		c.mu.RUnlock()
		if run == nil {
			continue
		}
		run.capacity.mu.Lock()
		ready := run.capacity.ready
		run.capacity.mu.Unlock()
		if !ready {
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
		c.publicVisitors = make(map[string]*preparedVisitorRun)
		c.mu.Unlock()
		retired := make([]*preparedVisitorRun, 0, len(runs))
		for _, run := range runs {
			retired = append(retired, run)
		}
		retirePreparedVisitors(ctx, retired)
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
		c.routingTable.mu.RLock()
		current := make(map[string]ingressv1.IngressRoutingTableEntry)
		terminal := make(map[string]bool)
		for _, stored := range c.routingTable.routes {
			entry := stored.entry
			if entry.PublishRunClosed != nil && *entry.PublishRunClosed {
				terminal[entry.PublishRunId] = true
				continue
			}
			if !stored.tombstone && entry.PublicUrlExpiresAt.After(time.Now()) {
				current[entry.PublishRunId] = entry
			}
		}
		c.routingTable.mu.RUnlock()
		c.mu.Lock()
		var retired []*preparedVisitorRun
		for id, run := range c.publicVisitors {
			_, present := current[id]
			owner := run.capacity.owner
			if terminal[id] || owner.IngressRunId != process.IngressRunId || owner.IngressLeaseRevision != process.IngressLeaseRevision || !present && !run.active() {
				delete(c.publicVisitors, id)
				retired = append(retired, run)
			}
		}
		var pending []string
		var existing []*preparedVisitorRun
		for id := range current {
			if c.publicVisitors[id] == nil {
				pending = append(pending, id)
			} else {
				existing = append(existing, c.publicVisitors[id])
			}
		}
		remaining := max(0, 4096-len(c.publicVisitors))
		c.mu.Unlock()
		retirePreparedVisitors(ctx, retired)
		// expansion observes local occupancy in this background loop. even a
		// full pool never turns a visitor into an allocation request.
		var expanding sync.WaitGroup
		for index := range min(8, len(existing)) {
			run := existing[(cursor+index)%len(existing)]
			expanding.Go(func() { run.expand(ctx, c.report) })
		}
		expanding.Wait()
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
				scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: entry.PublicUrlId}
				limits := trafficlimits.Default()
				if entry.Traffic != nil {
					limits.Connections = entry.Traffic.Connections
				}
				// start with a portion rather than taking the whole run from other
				// ingress processes; background occupancy can request more portions.
				body := ingressv1.StreamCapacityRequest{Resource: controlv1.VisitorResourceScope{Kind: "public_url", Id: scope.ID}, RunId: entry.PublishRunId, RunNumber: entry.PublishRunNumber, Capacity: max(1, limits.Connections/4)}
				capacity, err := prepareStreamCapacity(ctx, c.visitorControl, process, body, c.report)
				if err != nil {
					return
				}
				policy, err := prepareVisitorPolicy(ctx, c.visitorControl, scope, c.Lease, c.report)
				if err != nil {
					_ = capacity.Close(ctx)
					return
				}
				run := &preparedVisitorRun{policy: policy, capacity: capacity, limit: limits.Connections}
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
