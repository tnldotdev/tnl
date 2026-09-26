package ingress

import (
	"errors"
	"fmt"
	"maps"
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
	publicURLID      string
	publishRunNumber int64
	entryRevision    int64
	tombstone        bool
	entry            ingressv1.IngressRoutingTableEntry
}

// RoutingTable replaces its data as one operation and rejects lookups until it
// has been initialized.
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
		if event.Kind != ingressv1.PublicUrlUpsert && event.Kind != ingressv1.ChallengeUpsert ||
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
		return nil
	}
	if page.Events[len(page.Events)-1].RoutingTableRevision != page.NextRevision {
		return fmt.Errorf("%w: next revision does not match page", ErrRoutingTableRevision)
	}
	// Stored entries are immutable; only incoming entries need deep copies.
	routes := maps.Clone(t.routes)
	challenges := maps.Clone(t.challenges)
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
		if current, exists := target[event.CanonicalHostname]; exists && current.publicURLID == event.PublicUrlId &&
			(event.PublishRunNumber < current.publishRunNumber ||
				event.PublishRunNumber == current.publishRunNumber && event.EntryRevision <= current.entryRevision) {
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
	entry, reason := t.lookup(canonicalHostname, now, false)
	return entry, reason == ""
}

func (t *RoutingTable) LookupChallenge(canonicalHostname string, now time.Time) (ingressv1.IngressRoutingTableEntry, bool) {
	entry, reason := t.lookup(canonicalHostname, now, true)
	return entry, reason == ""
}

func (t *RoutingTable) LookupChallengeWithReason(canonicalHostname string, now time.Time) (ingressv1.IngressRoutingTableEntry, string) {
	return t.lookup(canonicalHostname, now, true)
}

func (t *RoutingTable) lookup(
	canonicalHostname string,
	now time.Time,
	challenge bool,
) (ingressv1.IngressRoutingTableEntry, string) {
	canonical, err := naming.CanonicalizeHostname(canonicalHostname)
	if err != nil {
		return ingressv1.IngressRoutingTableEntry{}, "invalid_hostname"
	}
	t.mu.RLock()
	entries := t.routes
	if challenge {
		entries = t.challenges
	}
	stored, exists := entries[canonical]
	initialized := t.initialized
	t.mu.RUnlock()
	if !initialized {
		return ingressv1.IngressRoutingTableEntry{}, "uninitialized"
	}
	if !exists {
		return ingressv1.IngressRoutingTableEntry{}, "missing"
	}
	if stored.tombstone {
		return ingressv1.IngressRoutingTableEntry{}, "tombstone"
	}
	if !stored.entry.PublicUrlExpiresAt.After(now) {
		return ingressv1.IngressRoutingTableEntry{}, "public_url_expired"
	}
	entry := cloneRoutingTableEntry(stored.entry)
	// A relay can renew its lease without changing this route projection. Its
	// copied deadline is therefore only a hint; the relay checks its current
	// lease and exact process identity before accepting an internal stream.
	return entry, ""
}

func validateRoutingTableEvent(event ingressv1.IngressRoutingTableEvent) error {
	canonical, err := naming.CanonicalizeHostname(event.CanonicalHostname)
	if event.RoutingTableRevision <= 0 || !event.Kind.Valid() || event.PublicUrlId == "" ||
		event.PublishRunNumber <= 0 || err != nil || canonical != event.CanonicalHostname ||
		event.EntryRevision <= 0 || event.CreatedAt.IsZero() {
		return ErrRoutingTableEvent
	}
	entry := event.Entry
	if entry.PublishRunId == "" || entry.PublicUrlId != event.PublicUrlId || entry.PublishRunNumber != event.PublishRunNumber ||
		entry.CanonicalHostname != event.CanonicalHostname || entry.PolicyRevision <= 0 ||
		entry.PublicUrlExpiresAt.IsZero() || !entry.IpPolicy.Valid() || len(entry.AllowedIpPrefixes) > 64 ||
		len(entry.PublisherConnections) > 2 {
		return ErrRoutingTableEvent
	}
	if event.Kind == ingressv1.PublicUrlUpsert || event.Kind == ingressv1.ChallengeUpsert {
		if event.PublicUrlExpiresAt == nil || !event.PublicUrlExpiresAt.Equal(entry.PublicUrlExpiresAt) ||
			len(entry.PublisherConnections) == 0 {
			return ErrRoutingTableEvent
		}
	} else if event.PublicUrlExpiresAt != nil || len(entry.PublisherConnections) != 0 {
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
		publicURLID: event.PublicUrlId, publishRunNumber: event.PublishRunNumber, entryRevision: event.EntryRevision,
		tombstone: event.Kind == ingressv1.PublicUrlTombstone || event.Kind == ingressv1.ChallengeTombstone,
		entry:     cloneRoutingTableEntry(event.Entry),
	}
}

func isChallengeEvent(kind ingressv1.IngressRoutingTableEventKind) bool {
	return kind == ingressv1.ChallengeUpsert || kind == ingressv1.ChallengeTombstone
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
