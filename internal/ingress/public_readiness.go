package ingress

import (
	"time"

	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
)

func (c *Controller) markPublicRoutingPrepared() {
	if revision, initialized := c.routingTable.Revision(); initialized && c.publicRoutingPrepared(revision, c.now()) {
		c.mu.Lock()
		c.servingPrepared = true
		c.mu.Unlock()
	}
}

// publicRoutingPrepared gates the initial health-aware join, not routing
// acknowledgement. once joined, each URL prepares independently.
func (c *Controller) publicRoutingPrepared(revision int64, now time.Time) bool {
	if c.registration.ConnectorOnly != nil && *c.registration.ConnectorOnly {
		return true
	}
	c.routingTable.mu.RLock()
	var entries []ingressv1.IngressRoutingTableEntry
	for _, stored := range c.routingTable.routes {
		if !stored.tombstone && c.publicPool(stored.entry) && stored.entry.PublishRunReadyAt != nil && stored.entry.PublicUrlExpiresAt.After(now) {
			entries = append(entries, stored.entry)
		}
	}
	current := c.routingTable.initialized && c.routingTable.revision == revision
	c.routingTable.mu.RUnlock()
	if !current {
		return false
	}
	process := c.Lease()
	for _, entry := range entries {
		c.mu.RLock()
		run := c.publicVisitors[entry.PublishRunId]
		c.mu.RUnlock()
		if run == nil || !run.preparedFor(entry, process, now) {
			return false
		}
	}
	latest, initialized := c.routingTable.Revision()
	return initialized && latest == revision
}

func (c *Controller) publicPool(entry ingressv1.IngressRoutingTableEntry) bool {
	return entry.IngressPoolId == nil || c.registration.IngressPoolId == "" || *entry.IngressPoolId == c.registration.IngressPoolId
}

func (r *publicVisitorRun) ownedBy(process ingressv1.IngressLease) bool {
	owner := r.capacity.owner
	return owner.IngressId == process.IngressId && owner.IngressRunId == process.IngressRunId &&
		owner.IngressLeaseRevision == process.IngressLeaseRevision
}

func (r *publicVisitorRun) preparedFor(entry ingressv1.IngressRoutingTableEntry, process ingressv1.IngressLease, now time.Time) bool {
	_, ok := r.observationFor(entry, process, now)
	return ok
}

func (r *publicVisitorRun) observationsFor(entry ingressv1.IngressRoutingTableEntry, process ingressv1.IngressLease, now time.Time) []ingressv1.IngressStreamAllocationObservation {
	observation, ok := r.observationFor(entry, process, now)
	if !ok {
		return nil
	}
	return []ingressv1.IngressStreamAllocationObservation{observation}
}

func (r *publicVisitorRun) observationFor(entry ingressv1.IngressRoutingTableEntry, process ingressv1.IngressLease, now time.Time) (ingressv1.IngressStreamAllocationObservation, bool) {
	// capacity identity -> local slots -> installed policy is the read order.
	// refresh applies slots before publishing identity and never holds these
	// locks in reverse. retain identity throughout, including policy membership.
	r.capacity.mu.Lock()
	defer r.capacity.mu.Unlock()
	if !r.ownedBy(process) || !r.capacity.ready || !now.Before(r.capacity.publisherUntil) || process.Draining {
		return ingressv1.IngressStreamAllocationObservation{}, false
	}
	r.capacity.pool.mu.Lock()
	defer r.capacity.pool.mu.Unlock()
	id := r.capacity.id
	slots := r.capacity.pool.allocations[id]
	if r.capacity.pool.closed || slots == nil || slots.allocation.Retired || !now.Before(slots.allocation.ValidUntil) {
		return ingressv1.IngressStreamAllocationObservation{}, false
	}
	a := slots.allocation
	if a.ResourceKind != "public_url" || a.ResourceID != entry.PublicUrlId || a.RunID != entry.PublishRunId || a.RunNumber != uint64(entry.PublishRunNumber) ||
		a.IngressID != process.IngressId || a.IngressRunID != process.IngressRunId || a.IngressLeaseRevision != uint64(process.IngressLeaseRevision) {
		return ingressv1.IngressStreamAllocationObservation{}, false
	}
	view, installed, ok := r.policy.lease.ObserveAllocation(id, entry.PublishRunId, entry.PublishRunNumber)
	if !ok || view.Hostname != entry.CanonicalHostname || view.Scope.ID != entry.PublicUrlId ||
		installed.IngressId != process.IngressId || installed.IngressRunId != process.IngressRunId || installed.IngressLeaseRevision != process.IngressLeaseRevision {
		return ingressv1.IngressStreamAllocationObservation{}, false
	}
	until := view.ValidUntil
	for _, bound := range []time.Time{a.ValidUntil, r.capacity.publisherUntil} {
		if bound.Before(until) {
			until = bound
		}
	}
	until = view.AuthorityTime(until)
	for _, bound := range []time.Time{installed.ValidUntil, process.LeaseExpiresAt} {
		if bound.Before(until) {
			until = bound
		}
	}
	if !until.After(view.AuthorityTime(now)) {
		return ingressv1.IngressStreamAllocationObservation{}, false
	}
	return ingressv1.IngressStreamAllocationObservation{AllocationId: id, RunId: entry.PublishRunId, RunNumber: entry.PublishRunNumber, ValidUntil: until}, true
}
