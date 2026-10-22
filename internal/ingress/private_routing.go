package ingress

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
)

var ErrPrivateRoutingStale = errors.New("ingress: private service routing state is stale")

// PrivateRoutingTable is an ID-keyed projection. no hostname or untrusted SNI
// is used to choose a private service. the owner must clear it on lease loss.
type PrivateRoutingTable struct {
	mu          sync.RWMutex
	initialized bool
	revision    int64
	services    map[privateRunKey]privateRunUpsert
}

type privateRunKey struct {
	serviceID string
	runID     string
}

type privateProjectionEvent interface{ privateProjectionEvent() }

type privateRunUpsert struct {
	key       privateRunKey
	number    int64
	revision  int64
	expiresAt time.Time
	relays    []ingressv1.PrivateServiceRelay
}

type privateRunTombstone struct {
	key    privateRunKey
	number int64
}

type privateServiceTombstone struct{ serviceID string }

func (privateRunUpsert) privateProjectionEvent()        {}
func (privateRunTombstone) privateProjectionEvent()     {}
func (privateServiceTombstone) privateProjectionEvent() {}

// parsePrivateProjection confines optional wire fields to the decode boundary.
func parsePrivateProjection(p ingressv1.PrivateServiceProjection, now time.Time) (privateProjectionEvent, error) {
	if err := validatePrivateProjection(p, now); err != nil {
		return nil, err
	}
	if p.Kind == ingressv1.Upsert {
		return privateRunUpsert{key: privateRunKey{p.PrivateServiceId, *p.PrivateRunId}, number: *p.RunNumber,
			revision: p.Revision, expiresAt: p.ExpiresAt, relays: append([]ingressv1.PrivateServiceRelay(nil), (*p.ConnectedRelays)...)}, nil
	}
	if p.PrivateRunId != nil {
		return privateRunTombstone{key: privateRunKey{p.PrivateServiceId, *p.PrivateRunId}, number: *p.RunNumber}, nil
	}
	return privateServiceTombstone{serviceID: p.PrivateServiceId}, nil
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
	services := make(map[privateRunKey]privateRunUpsert, len(snapshot.Entries))
	for _, entry := range snapshot.Entries {
		parsed, err := parsePrivateProjection(entry, now)
		upsert, ok := parsed.(privateRunUpsert)
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

func (t *PrivateRoutingTable) ApplyEvents(after int64, page ingressv1.PrivateServiceSnapshot, now time.Time) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.initialized || after != t.revision || page.Revision < after {
		return ErrPrivateRoutingStale
	}
	services := make(map[privateRunKey]privateRunUpsert, len(t.services))
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
		case privateRunUpsert:
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
		case privateRunTombstone:
			delete(services, change.key)
		case privateServiceTombstone:
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

func (t *PrivateRoutingTable) Lookup(serviceID, runID string, number int64, now time.Time) (ingressv1.PrivateServiceProjection, bool) {
	t.mu.RLock()
	entry, exists := t.services[privateRunKey{serviceID, runID}]
	valid := t.initialized && exists && entry.expiresAt.After(now) && entry.number == number
	t.mu.RUnlock()
	if !valid {
		return ingressv1.PrivateServiceProjection{}, false
	}
	live := make([]ingressv1.PrivateServiceRelay, 0, len(entry.relays))
	for _, relay := range entry.relays {
		if relay.LeaseExpiresAt.After(now) {
			if _, _, err := net.SplitHostPort(relay.InternalRelayAddress); err == nil {
				live = append(live, relay)
			}
		}
	}
	if len(live) == 0 {
		return ingressv1.PrivateServiceProjection{}, false
	}
	return ingressv1.PrivateServiceProjection{Kind: ingressv1.Upsert, PrivateServiceId: serviceID, PrivateRunId: &runID,
		RunNumber: &entry.number, Revision: entry.revision, ExpiresAt: entry.expiresAt, ConnectedRelays: &live}, true
}
