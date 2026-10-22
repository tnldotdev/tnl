package ingress

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
)

var ErrPrivateRoutingStale = errors.New("ingress: private service routing state is stale")

// PrivateRoutingTable is an ID-keyed projection. no hostname or untrusted SNI
// is used to choose a private service. the owner must clear it on lease loss.
type PrivateRoutingTable struct {
	mu          sync.RWMutex
	initialized bool
	revision    int64
	services    map[string]ingressv1.PrivateServiceProjection
}

func validatePrivateProjection(p ingressv1.PrivateServiceProjection, now time.Time) error {
	if p.Revision <= 0 || !opaqueid.Valid(p.PrivateServiceId, opaqueid.PrivateServicePrefix) ||
		p.ExpiresAt.IsZero() || !p.Kind.Valid() {
		return ErrPrivateRoutingStale
	}
	if p.Kind == ingressv1.Upsert {
		if p.PrivateRunId == nil || !opaqueid.Valid(*p.PrivateRunId, opaqueid.PrivateRunPrefix) ||
			p.RunNumber == nil || *p.RunNumber <= 0 || p.ConnectedRelays == nil ||
			len(*p.ConnectedRelays) < 1 || len(*p.ConnectedRelays) > 2 || !p.ExpiresAt.After(now) {
			return ErrPrivateRoutingStale
		}
		seen := make(map[string]bool, 2)
		slots := make(map[int]bool, 2)
		for _, relay := range *p.ConnectedRelays {
			if !opaqueid.Valid(relay.PublisherConnectionId, opaqueid.PublisherConnectionPrefix) ||
				relay.ConnectionSlot < 0 || relay.ConnectionSlot > 1 ||
				relay.ConnectionAssignmentRevision < 1 || relay.RelayLeaseRevision < 1 ||
				relay.RelayServiceId == "" || relay.RelayId == "" ||
				!opaqueid.Valid(relay.RelayRunId, opaqueid.RelayRunPrefix) || relay.InternalRelayAddress == "" ||
				!relay.LeaseExpiresAt.After(now) || seen[relay.RelayServiceId] || slots[relay.ConnectionSlot] {
				return ErrPrivateRoutingStale
			}
			seen[relay.RelayServiceId] = true
			slots[relay.ConnectionSlot] = true
		}
	} else if p.ConnectedRelays != nil || (p.PrivateRunId == nil) != (p.RunNumber == nil) ||
		p.PrivateRunId != nil && (!opaqueid.Valid(*p.PrivateRunId, opaqueid.PrivateRunPrefix) || *p.RunNumber <= 0) {
		return ErrPrivateRoutingStale
	}
	return nil
}

func clonePrivateProjection(p ingressv1.PrivateServiceProjection) ingressv1.PrivateServiceProjection {
	if p.PrivateRunId != nil {
		id := *p.PrivateRunId
		p.PrivateRunId = &id
	}
	if p.RunNumber != nil {
		number := *p.RunNumber
		p.RunNumber = &number
	}
	if p.ConnectedRelays != nil {
		relays := append([]ingressv1.PrivateServiceRelay(nil), (*p.ConnectedRelays)...)
		p.ConnectedRelays = &relays
	}
	return p
}

func (t *PrivateRoutingTable) Clear() {
	t.mu.Lock()
	t.initialized = false
	t.revision = 0
	t.services = nil
	t.mu.Unlock()
}

func (t *PrivateRoutingTable) Revision() (int64, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.revision, t.initialized
}

func (t *PrivateRoutingTable) ApplySnapshot(snapshot ingressv1.PrivateServiceSnapshot, now time.Time) error {
	if snapshot.Revision < 0 {
		return ErrPrivateRoutingStale
	}
	services := make(map[string]ingressv1.PrivateServiceProjection, len(snapshot.Entries))
	for _, entry := range snapshot.Entries {
		if entry.Kind != ingressv1.Upsert || entry.Revision > snapshot.Revision || validatePrivateProjection(entry, now) != nil {
			return ErrPrivateRoutingStale
		}
		key := privateProjectionKey(entry)
		if _, present := services[key]; present {
			return ErrPrivateRoutingStale
		}
		services[key] = clonePrivateProjection(entry)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.initialized && snapshot.Revision < t.revision {
		return ErrPrivateRoutingStale
	}
	t.revision, t.services, t.initialized = snapshot.Revision, services, true
	return nil
}

func (t *PrivateRoutingTable) ApplyEvents(after int64, page ingressv1.PrivateServiceSnapshot, now time.Time) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.initialized || after != t.revision || page.Revision < after {
		return ErrPrivateRoutingStale
	}
	services := make(map[string]ingressv1.PrivateServiceProjection, len(t.services))
	for id, entry := range t.services {
		services[id] = entry
	}
	previous := after
	for _, entry := range page.Entries {
		if entry.Revision <= previous || entry.Revision > page.Revision || validatePrivateProjection(entry, now) != nil {
			return ErrPrivateRoutingStale
		}
		key := privateProjectionKey(entry)
		if old, exists := services[key]; exists && old.Kind == ingressv1.Upsert && entry.Kind == ingressv1.Upsert {
			if *entry.RunNumber < *old.RunNumber || *entry.RunNumber == *old.RunNumber &&
				*entry.PrivateRunId != *old.PrivateRunId {
				return ErrPrivateRoutingStale
			}
			for _, current := range *entry.ConnectedRelays {
				for _, earlier := range *old.ConnectedRelays {
					if current.ConnectionSlot == earlier.ConnectionSlot &&
						(current.ConnectionAssignmentRevision < earlier.ConnectionAssignmentRevision ||
							current.ConnectionAssignmentRevision == earlier.ConnectionAssignmentRevision && current.PublisherConnectionId != earlier.PublisherConnectionId) {
						return ErrPrivateRoutingStale
					}
				}
			}
		}
		if entry.Kind == ingressv1.Tombstone && entry.PrivateRunId == nil {
			for id, old := range services {
				if old.PrivateServiceId == entry.PrivateServiceId {
					delete(services, id)
				}
			}
		} else {
			services[key] = clonePrivateProjection(entry)
		}
		previous = entry.Revision
	}
	if len(page.Entries) != 0 && previous != page.Revision {
		return ErrPrivateRoutingStale
	}
	t.services, t.revision = services, page.Revision
	return nil
}

func (t *PrivateRoutingTable) Lookup(serviceID, runID string, number int64, now time.Time) (ingressv1.PrivateServiceProjection, bool) {
	t.mu.RLock()
	entry, exists := t.services[serviceID+"/"+runID]
	valid := t.initialized && exists && entry.Kind == ingressv1.Upsert && entry.ExpiresAt.After(now) &&
		entry.PrivateRunId != nil && *entry.PrivateRunId == runID && entry.RunNumber != nil && *entry.RunNumber == number
	t.mu.RUnlock()
	if !valid {
		return ingressv1.PrivateServiceProjection{}, false
	}
	entry = clonePrivateProjection(entry)
	live := (*entry.ConnectedRelays)[:0]
	for _, relay := range *entry.ConnectedRelays {
		if relay.LeaseExpiresAt.After(now) {
			if _, _, err := net.SplitHostPort(relay.InternalRelayAddress); err == nil {
				live = append(live, relay)
			}
		}
	}
	if len(live) == 0 {
		return ingressv1.PrivateServiceProjection{}, false
	}
	entry.ConnectedRelays = &live
	return entry, true
}

func privateProjectionKey(entry ingressv1.PrivateServiceProjection) string {
	if entry.PrivateRunId == nil {
		return entry.PrivateServiceId + "/"
	}
	return entry.PrivateServiceId + "/" + *entry.PrivateRunId
}
