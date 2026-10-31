package ingress

import (
	"slices"
	"strings"
	"time"

	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
)

// publicRunPreparedFunc reads already-installed policy; it must not fetch or
// promise later installation. it checks the exact resource, run, hostname and
// process lease, including the entry's policy revision. it must be concurrency
// safe and nonblocking. now is local time: the owner checks its conservative
// local expiry separately from the returned absolute control-clock deadline.
// return the installed deadline, never local now plus a fresh TTL; it is bounded
// by all installed policy authority. return false at local expiry. the permission
// owner calls ServingStateChanged after installation; the publisher checks its
// installed policy before each MarkPublishRunReady request and ready notification.
type publicRunPreparedFunc func(ingressv1.IngressRoutingTableEntry, ingressv1.IngressLease, time.Time) (time.Time, bool)

// ServingStateChanged wakes the existing renewal owner after local installation.
// it coalesces notifications and does not start an independent request lifetime.
func (c *Controller) ServingStateChanged() {
	select {
	case c.servingChanged <- struct{}{}:
	default:
	}
}

func (c *Controller) publicRunInstalled(entry ingressv1.IngressRoutingTableEntry, process ingressv1.IngressLease, now time.Time) (time.Time, bool) {
	if process.IngressLeaseRevision <= 0 || process.Draining || !process.LeaseExpiresAt.After(now) ||
		!entry.PublicUrlExpiresAt.After(now) || len(entry.PublisherConnections) == 0 ||
		entry.PublishRunClosed != nil && *entry.PublishRunClosed ||
		entry.IngressPoolId != nil && *entry.IngressPoolId != c.registration.IngressPoolId {
		return time.Time{}, false
	}
	until := entry.PublicUrlExpiresAt
	if process.LeaseExpiresAt.Before(until) {
		until = process.LeaseExpiresAt
	}
	policyUntil, ok := c.publicRunPrepared(entry, process, now)
	if !ok || policyUntil.IsZero() {
		return time.Time{}, false
	}
	if policyUntil.Before(until) {
		until = policyUntil
	}
	return until, true
}

type publicRunObservation struct {
	ingressv1.IngressPublicRunObservation
	routingKey string
}

func (c *Controller) publicRunObservations(process ingressv1.IngressLease, now time.Time) []publicRunObservation {
	c.routingTable.mu.RLock()
	// the table replaces its map and entries; this snapshot stays immutable.
	entries := c.routingTable.routes
	c.routingTable.mu.RUnlock()
	observations := make([]publicRunObservation, 0, len(entries))
	for key, stored := range entries {
		if stored.tombstone {
			continue
		}
		entry := cloneRoutingTableEntry(stored.entry)
		if until, ok := c.publicRunInstalled(entry, process, now); ok {
			observations = append(observations, publicRunObservation{
				IngressPublicRunObservation: ingressv1.IngressPublicRunObservation{
					PublishRunId: entry.PublishRunId, PublishRunNumber: entry.PublishRunNumber,
					EntryRevision: stored.entryRevision, ValidUntil: until,
				},
				routingKey: key,
			})
		}
	}
	slices.SortFunc(observations, func(a, b publicRunObservation) int {
		return strings.Compare(a.PublishRunId, b.PublishRunId)
	})
	return observations
}

func (c *Controller) publicRunObservationPage(pending []publicRunObservation, process ingressv1.IngressLease, now time.Time) []ingressv1.IngressPublicRunObservation {
	observations := make([]ingressv1.IngressPublicRunObservation, 0, len(pending))
	for _, candidate := range pending {
		c.routingTable.mu.RLock()
		stored, exists := c.routingTable.routes[candidate.routingKey]
		c.routingTable.mu.RUnlock()
		if !exists || stored.tombstone || stored.entryRevision != candidate.EntryRevision ||
			stored.entry.PublishRunId != candidate.PublishRunId || stored.publishRunNumber != candidate.PublishRunNumber {
			continue
		}
		until, ok := c.publicRunInstalled(cloneRoutingTableEntry(stored.entry), process, now)
		if !ok {
			continue
		}
		observation := candidate.IngressPublicRunObservation
		// revalidation may shorten evidence, never extend the snapshot's deadline.
		// a newer installation is reported by the next notified snapshot, after
		// all older pages; only this renewal owner sends requests.
		if until.Before(observation.ValidUntil) {
			observation.ValidUntil = until
		}
		observations = append(observations, observation)
	}
	return observations
}

// initial health prepares existing ready runs. after joining, starting runs and
// policy refreshes are fenced individually at lookup, never by a global barrier.
func (c *Controller) publicServingJoined(process ingressv1.IngressLease, now time.Time) bool {
	c.mu.RLock()
	joined := c.servingJoined
	c.mu.RUnlock()
	if joined {
		return true
	}
	c.routingTable.mu.RLock()
	defer c.routingTable.mu.RUnlock()
	if !c.routingTable.initialized {
		return false
	}
	for _, stored := range c.routingTable.routes {
		entry := stored.entry
		if stored.tombstone || entry.PublishRunReadyAt == nil || !entry.PublicUrlExpiresAt.After(now) ||
			entry.IngressPoolId != nil && *entry.IngressPoolId != c.registration.IngressPoolId {
			continue
		}
		if _, ok := c.publicRunInstalled(cloneRoutingTableEntry(entry), process, now); !ok {
			return false
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lease.IngressRunId != process.IngressRunId || c.lease.IngressLeaseRevision != process.IngressLeaseRevision || c.leaseLost || c.lease.Draining {
		return false
	}
	c.servingJoined = true
	return true
}
