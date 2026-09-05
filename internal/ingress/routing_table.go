package ingress

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
)

var (
	ErrRoutingTableNotInitialized = errors.New("ingress: routing table is not initialized")
	ErrRoutingTableRevision       = errors.New("ingress: routing-table revision is invalid")
	ErrRoutingTableEvent          = errors.New("ingress: routing-table event is invalid")
)

type routingTableEntry struct {
	routeID       string
	routeVersion  int64
	entryRevision int64
	tombstone     bool
	entry         ingressv1.IngressRoutingTableEntry
}

// RoutingTable is an atomically updated, fail-closed ingress routing table.
// Its zero value is uninitialized.
type RoutingTable struct {
	mu          sync.RWMutex
	initialized bool
	revision    int64
	routes      map[string]routingTableEntry
	challenges  map[string]routingTableEntry
}

func (t *RoutingTable) ApplySnapshot(snapshot ingressv1.IngressRoutingTableSnapshot) error {
	if snapshot.ThroughRevision < 0 || snapshot.RetainedAfterRevision < 0 ||
		snapshot.RetainedAfterRevision > snapshot.ThroughRevision {
		return fmt.Errorf("%w: snapshot bounds", ErrRoutingTableRevision)
	}
	routes := make(map[string]routingTableEntry, len(snapshot.Entries))
	challenges := make(map[string]routingTableEntry, len(snapshot.Entries))
	for _, event := range snapshot.Entries {
		if event.Kind != ingressv1.RouteUpsert && event.Kind != ingressv1.ChallengeUpsert ||
			event.RoutingTableRevision > snapshot.ThroughRevision {
			return fmt.Errorf("%w: snapshot contains a non-current event", ErrRoutingTableEvent)
		}
		if err := validateRoutingTableEvent(event); err != nil {
			return err
		}
		target := routes
		if isChallengeEvent(event.Kind) {
			target = challenges
		}
		if _, exists := target[event.CanonicalHostname]; exists {
			return fmt.Errorf("%w: snapshot contains duplicate hostname %q", ErrRoutingTableEvent, event.CanonicalHostname)
		}
		target[event.CanonicalHostname] = routingEntryForEvent(event)
	}
	t.mu.Lock()
	t.routes = routes
	t.challenges = challenges
	t.revision = snapshot.ThroughRevision
	t.initialized = true
	t.mu.Unlock()
	return nil
}

func (t *RoutingTable) ApplyPage(after int64, page ingressv1.IngressRoutingTablePage) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.initialized {
		return ErrRoutingTableNotInitialized
	}
	if after != t.revision || after < 0 || page.ThroughRevision < after ||
		page.RetainedAfterRevision < 0 || page.RetainedAfterRevision > after ||
		page.NextRevision < after || page.NextRevision > page.ThroughRevision {
		return ErrRoutingTableRevision
	}
	if page.More != (page.NextRevision < page.ThroughRevision) {
		return fmt.Errorf("%w: inconsistent more flag", ErrRoutingTableRevision)
	}
	if len(page.Events) == 0 {
		if page.NextRevision != after {
			return fmt.Errorf("%w: empty page advanced revision", ErrRoutingTableRevision)
		}
	} else if page.Events[len(page.Events)-1].RoutingTableRevision != page.NextRevision {
		return fmt.Errorf("%w: next revision does not match page", ErrRoutingTableRevision)
	}
	routes := cloneRoutingEntries(t.routes)
	challenges := cloneRoutingEntries(t.challenges)
	previousRevision := after
	for _, event := range page.Events {
		if event.RoutingTableRevision <= previousRevision || event.RoutingTableRevision > page.ThroughRevision {
			return fmt.Errorf("%w: events are not strictly ordered", ErrRoutingTableEvent)
		}
		if err := validateRoutingTableEvent(event); err != nil {
			return err
		}
		target := routes
		if isChallengeEvent(event.Kind) {
			target = challenges
		}
		if current, exists := target[event.CanonicalHostname]; exists && current.routeID == event.RouteId &&
			(event.RouteVersion < current.routeVersion ||
				event.RouteVersion == current.routeVersion && event.EntryRevision <= current.entryRevision) {
			return fmt.Errorf("%w: stale entry revision for hostname %q", ErrRoutingTableEvent, event.CanonicalHostname)
		}
		target[event.CanonicalHostname] = routingEntryForEvent(event)
		previousRevision = event.RoutingTableRevision
	}
	t.routes = routes
	t.challenges = challenges
	t.revision = page.NextRevision
	return nil
}

func (t *RoutingTable) Revision() (int64, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.revision, t.initialized
}

func (t *RoutingTable) Lookup(canonicalHostname string, now time.Time) (ingressv1.IngressRoutingTableEntry, bool) {
	return t.lookup(canonicalHostname, now, false)
}

func (t *RoutingTable) LookupChallenge(canonicalHostname string, now time.Time) (ingressv1.IngressRoutingTableEntry, bool) {
	return t.lookup(canonicalHostname, now, true)
}

func (t *RoutingTable) lookup(
	canonicalHostname string,
	now time.Time,
	challenge bool,
) (ingressv1.IngressRoutingTableEntry, bool) {
	canonical, err := naming.CanonicalizeHostname(canonicalHostname)
	if err != nil || canonical != canonicalHostname {
		return ingressv1.IngressRoutingTableEntry{}, false
	}
	t.mu.RLock()
	entries := t.routes
	if challenge {
		entries = t.challenges
	}
	stored, exists := entries[canonicalHostname]
	initialized := t.initialized
	t.mu.RUnlock()
	if !initialized || !exists || stored.tombstone || !stored.entry.RouteExpiresAt.After(now) {
		return ingressv1.IngressRoutingTableEntry{}, false
	}
	entry := cloneRoutingTableEntry(stored.entry)
	entry.PublisherConnections = entry.PublisherConnections[:0]
	for _, connection := range stored.entry.PublisherConnections {
		if connection.LeaseExpiresAt.After(now) {
			entry.PublisherConnections = append(entry.PublisherConnections, connection)
		}
	}
	if len(entry.PublisherConnections) == 0 {
		return ingressv1.IngressRoutingTableEntry{}, false
	}
	return entry, true
}

func validateRoutingTableEvent(event ingressv1.IngressRoutingTableEvent) error {
	canonical, err := naming.CanonicalizeHostname(event.CanonicalHostname)
	if event.RoutingTableRevision <= 0 || !event.Kind.Valid() || event.RouteId == "" ||
		event.RouteVersion <= 0 || err != nil || canonical != event.CanonicalHostname ||
		event.EntryRevision <= 0 || event.CreatedAt.IsZero() {
		return ErrRoutingTableEvent
	}
	entry := event.Entry
	if entry.RouteSessionId == "" || entry.RouteId != event.RouteId || entry.RouteVersion != event.RouteVersion ||
		entry.CanonicalHostname != event.CanonicalHostname || entry.PolicyRevision <= 0 ||
		entry.RouteExpiresAt.IsZero() || !entry.IpPolicy.Valid() || len(entry.AllowedIpPrefixes) > 64 ||
		len(entry.PublisherConnections) > 2 {
		return ErrRoutingTableEvent
	}
	if event.Kind == ingressv1.RouteUpsert || event.Kind == ingressv1.ChallengeUpsert {
		if event.RouteExpiresAt == nil || !event.RouteExpiresAt.Equal(entry.RouteExpiresAt) ||
			len(entry.PublisherConnections) == 0 {
			return ErrRoutingTableEvent
		}
	} else if event.RouteExpiresAt != nil || len(entry.PublisherConnections) != 0 {
		return ErrRoutingTableEvent
	}
	seenPrefixes := make(map[netip.Prefix]struct{}, len(entry.AllowedIpPrefixes))
	for _, value := range entry.AllowedIpPrefixes {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix != prefix.Masked() {
			return ErrRoutingTableEvent
		}
		if _, exists := seenPrefixes[prefix]; exists {
			return ErrRoutingTableEvent
		}
		seenPrefixes[prefix] = struct{}{}
	}
	seenSlots := make(map[int]struct{}, len(entry.PublisherConnections))
	seenConnections := make(map[string]struct{}, len(entry.PublisherConnections))
	seenRelayServices := make(map[string]struct{}, len(entry.PublisherConnections))
	for _, connection := range entry.PublisherConnections {
		if connection.ConnectionSlot < 0 || connection.ConnectionSlot > 1 ||
			connection.PublisherConnectionId == "" || connection.ConnectionAssignmentRevision <= 0 ||
			connection.RelayServiceId == "" || connection.RelayId == "" || connection.RelayRunId == "" ||
			connection.RelayLeaseRevision <= 0 || connection.InternalRelayAddress == "" ||
			connection.TlsServerName == "" || connection.LeaseExpiresAt.IsZero() {
			return ErrRoutingTableEvent
		}
		if _, exists := seenSlots[connection.ConnectionSlot]; exists {
			return ErrRoutingTableEvent
		}
		if _, exists := seenConnections[connection.PublisherConnectionId]; exists {
			return ErrRoutingTableEvent
		}
		if _, exists := seenRelayServices[connection.RelayServiceId]; exists {
			return ErrRoutingTableEvent
		}
		seenSlots[connection.ConnectionSlot] = struct{}{}
		seenConnections[connection.PublisherConnectionId] = struct{}{}
		seenRelayServices[connection.RelayServiceId] = struct{}{}
	}
	return nil
}

func routingEntryForEvent(event ingressv1.IngressRoutingTableEvent) routingTableEntry {
	return routingTableEntry{
		routeID: event.RouteId, routeVersion: event.RouteVersion, entryRevision: event.EntryRevision,
		tombstone: event.Kind == ingressv1.RouteTombstone || event.Kind == ingressv1.ChallengeTombstone,
		entry:     cloneRoutingTableEntry(event.Entry),
	}
}

func isChallengeEvent(kind ingressv1.IngressRoutingTableEventKind) bool {
	return kind == ingressv1.ChallengeUpsert || kind == ingressv1.ChallengeTombstone
}

func cloneRoutingEntries(source map[string]routingTableEntry) map[string]routingTableEntry {
	result := make(map[string]routingTableEntry, len(source))
	for hostname, entry := range source {
		entry.entry = cloneRoutingTableEntry(entry.entry)
		result[hostname] = entry
	}
	return result
}

func cloneRoutingTableEntry(source ingressv1.IngressRoutingTableEntry) ingressv1.IngressRoutingTableEntry {
	result := source
	result.AllowedIpPrefixes = append([]string(nil), source.AllowedIpPrefixes...)
	result.PublisherConnections = append(
		[]ingressv1.IngressRoutingPublisherConnection(nil), source.PublisherConnections...,
	)
	if source.RecoveryEpisodeId != nil {
		value := *source.RecoveryEpisodeId
		result.RecoveryEpisodeId = &value
	}
	return result
}
