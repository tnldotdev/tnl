package ingress

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
)

var ErrPrivateRoutingStale = errors.New("ingress: service routing state is stale")

// ServiceRoutingTable is an ID-keyed projection. no hostname or untrusted SNI
// is used to choose a service. the owner must clear it on lease loss.
type ServiceRoutingTable struct {
	mu          sync.RWMutex
	initialized bool
	revision    int64
	services    map[serviceRunKey]serviceRunUpsert
}

type serviceRunKey struct {
	serviceID string
	runID     string
}

type privateProjectionEvent interface{ privateProjectionEvent() }

type serviceRunUpsert struct {
	key       serviceRunKey
	number    int64
	revision  int64
	expiresAt time.Time
	relays    []ingressv1.ServiceRelay
}

type serviceRunTombstone struct {
	key    serviceRunKey
	number int64
}

type serviceTombstone struct{ serviceID string }

func (serviceRunUpsert) privateProjectionEvent()    {}
func (serviceRunTombstone) privateProjectionEvent() {}
func (serviceTombstone) privateProjectionEvent()    {}

// parsePrivateProjection confines optional wire fields to the decode boundary.
func parsePrivateProjection(p ingressv1.ServiceProjection, now time.Time) (privateProjectionEvent, error) {
	if err := validatePrivateProjection(p, now); err != nil {
		return nil, err
	}
	if p.Kind == ingressv1.Upsert {
		return serviceRunUpsert{key: serviceRunKey{p.ServiceId, *p.ServiceRunId}, number: *p.RunNumber,
			revision: p.Revision, expiresAt: p.ExpiresAt, relays: append([]ingressv1.ServiceRelay(nil), (*p.ConnectedRelays)...)}, nil
	}
	if p.ServiceRunId != nil {
		return serviceRunTombstone{key: serviceRunKey{p.ServiceId, *p.ServiceRunId}, number: *p.RunNumber}, nil
	}
	return serviceTombstone{serviceID: p.ServiceId}, nil
}

func validatePrivateProjection(p ingressv1.ServiceProjection, now time.Time) error {
	if p.Revision <= 0 || !opaqueid.Valid(p.ServiceId, opaqueid.ServicePrefix) ||
		p.ExpiresAt.IsZero() || !p.Kind.Valid() {
		return ErrPrivateRoutingStale
	}
	if p.Kind == ingressv1.Upsert {
		if p.ServiceRunId == nil || !opaqueid.Valid(*p.ServiceRunId, opaqueid.ServiceRunPrefix) ||
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
	} else if p.ConnectedRelays != nil || (p.ServiceRunId == nil) != (p.RunNumber == nil) ||
		p.ServiceRunId != nil && (!opaqueid.Valid(*p.ServiceRunId, opaqueid.ServiceRunPrefix) || *p.RunNumber <= 0) {
		return ErrPrivateRoutingStale
	}
	return nil
}

func clonePrivateProjection(p ingressv1.ServiceProjection) ingressv1.ServiceProjection {
	if p.ServiceRunId != nil {
		id := *p.ServiceRunId
		p.ServiceRunId = &id
	}
	if p.RunNumber != nil {
		number := *p.RunNumber
		p.RunNumber = &number
	}
	if p.ConnectedRelays != nil {
		relays := append([]ingressv1.ServiceRelay(nil), (*p.ConnectedRelays)...)
		p.ConnectedRelays = &relays
	}
	return p
}

func (t *ServiceRoutingTable) Clear() {
	t.mu.Lock()
	t.initialized = false
	t.revision = 0
	t.services = nil
	t.mu.Unlock()
}

func (t *ServiceRoutingTable) Revision() (int64, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.revision, t.initialized
}

func (t *ServiceRoutingTable) ApplySnapshot(snapshot ingressv1.ServiceSnapshot, now time.Time) error {
	if snapshot.Revision < 0 {
		return ErrPrivateRoutingStale
	}
	services := make(map[serviceRunKey]serviceRunUpsert, len(snapshot.Entries))
	for _, entry := range snapshot.Entries {
		parsed, err := parsePrivateProjection(entry, now)
		upsert, ok := parsed.(serviceRunUpsert)
		if err != nil || !ok || entry.Revision > snapshot.Revision {
			return ErrPrivateRoutingStale
		}
		if _, present := services[upsert.key]; present {
			return ErrPrivateRoutingStale
		}
		services[upsert.key] = upsert
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.initialized && snapshot.Revision < t.revision {
		return ErrPrivateRoutingStale
	}
	t.revision, t.services, t.initialized = snapshot.Revision, services, true
	return nil
}

func (t *ServiceRoutingTable) ApplyEvents(after int64, page ingressv1.ServiceSnapshot, now time.Time) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.initialized || after != t.revision || page.Revision < after {
		return ErrPrivateRoutingStale
	}
	services := make(map[serviceRunKey]serviceRunUpsert, len(t.services))
	for id, entry := range t.services {
		services[id] = entry
	}
	previous := after
	for _, entry := range page.Entries {
		parsed, err := parsePrivateProjection(entry, now)
		if entry.Revision <= previous || entry.Revision > page.Revision || err != nil {
			return ErrPrivateRoutingStale
		}
		switch change := parsed.(type) {
		case serviceRunUpsert:
			if old, exists := services[change.key]; exists {
				if change.number < old.number {
					return ErrPrivateRoutingStale
				}
				for _, current := range change.relays {
					for _, earlier := range old.relays {
						if current.ConnectionSlot == earlier.ConnectionSlot &&
							(current.ConnectionAssignmentRevision < earlier.ConnectionAssignmentRevision ||
								current.ConnectionAssignmentRevision == earlier.ConnectionAssignmentRevision && current.PublisherConnectionId != earlier.PublisherConnectionId) {
							return ErrPrivateRoutingStale
						}
					}
				}
			}
			services[change.key] = change
		case serviceRunTombstone:
			delete(services, change.key)
		case serviceTombstone:
			for key := range services {
				if key.serviceID == change.serviceID {
					delete(services, key)
				}
			}
		}
		previous = entry.Revision
	}
	if len(page.Entries) != 0 && previous != page.Revision {
		return ErrPrivateRoutingStale
	}
	t.services, t.revision = services, page.Revision
	return nil
}

func (t *ServiceRoutingTable) Lookup(serviceID, runID string, number int64, now time.Time) (ingressv1.ServiceProjection, bool) {
	t.mu.RLock()
	entry, exists := t.services[serviceRunKey{serviceID, runID}]
	valid := t.initialized && exists && entry.expiresAt.After(now) && entry.number == number
	t.mu.RUnlock()
	if !valid {
		return ingressv1.ServiceProjection{}, false
	}
	live := make([]ingressv1.ServiceRelay, 0, len(entry.relays))
	for _, relay := range entry.relays {
		if relay.LeaseExpiresAt.After(now) {
			if _, _, err := net.SplitHostPort(relay.InternalRelayAddress); err == nil {
				live = append(live, relay)
			}
		}
	}
	if len(live) == 0 {
		return ingressv1.ServiceProjection{}, false
	}
	return ingressv1.ServiceProjection{Kind: ingressv1.Upsert, ServiceId: serviceID, ServiceRunId: &runID,
		RunNumber: &entry.number, Revision: entry.revision, ExpiresAt: entry.expiresAt, ConnectedRelays: &live}, true
}
