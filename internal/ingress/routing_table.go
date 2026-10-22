package ingress

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/ippolicy"
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
}

func (t *RoutingTable) ApplySnapshot(snapshot ingressv1.IngressRoutingTableSnapshot) error {
	if snapshot.ThroughRevision < 0 || snapshot.RetainedAfterRevision < 0 ||
		snapshot.RetainedAfterRevision > snapshot.ThroughRevision {
		return fmt.Errorf("%w: snapshot bounds", ErrRoutingTableRevision)
	}
	routes := make(map[string]routingTableEntry, len(snapshot.Entries))
	for _, event := range snapshot.Entries {
		if event.Kind != ingressv1.PublicUrlUpsert ||
			event.RoutingTableRevision > snapshot.ThroughRevision {
			return fmt.Errorf("%w: snapshot contains a non-current event", ErrRoutingTableEvent)
		}
		if err := validateRoutingTableEvent(event); err != nil {
			return err
		}
		target := routes
		key := routingEventKey(event)
		if _, exists := target[key]; exists {
			return fmt.Errorf("%w: snapshot contains duplicate hostname %q", ErrRoutingTableEvent, event.CanonicalHostname)
		}
		target[key] = routingEntryForEvent(event)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.initialized && snapshot.ThroughRevision < t.revision {
		return ErrRoutingTableRevision
	}
	t.routes = routes
	t.revision = snapshot.ThroughRevision
	t.initialized = true
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
	// stored entries are immutable; only incoming entries need deep copies.
	routes := maps.Clone(t.routes)
	previousRevision := after
	for _, event := range page.Events {
		if event.RoutingTableRevision <= previousRevision || event.RoutingTableRevision > page.ThroughRevision {
			return fmt.Errorf("%w: events are not strictly ordered", ErrRoutingTableEvent)
		}
		if err := validateRoutingTableEvent(event); err != nil {
			return err
		}
		target := routes
		key := routingEventKey(event)
		if current, exists := target[key]; exists && current.publicURLID == event.PublicUrlId {
			if event.PublishRunNumber < current.publishRunNumber ||
				event.PublishRunNumber == current.publishRunNumber && event.EntryRevision <= current.entryRevision {
				return fmt.Errorf("%w: stale entry revision for hostname %q", ErrRoutingTableEvent, event.CanonicalHostname)
			}
			if current.entry.PublishRunClosed != nil && *current.entry.PublishRunClosed &&
				(event.Entry.PublishRunClosed == nil || !*event.Entry.PublishRunClosed) {
				return fmt.Errorf("%w: closed publish run cannot resume", ErrRoutingTableEvent)
			}
		}
		updated := routingEntryForEvent(event)
		target[key] = updated
		previousRevision = event.RoutingTableRevision
	}
	t.routes = routes
	t.revision = page.NextRevision
	return nil
}

func (t *RoutingTable) Revision() (int64, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.revision, t.initialized
}

// TerminalTrafficRuns proves that control closed these exact runs. absence,
// temporary tombstones, sibling runs, and expired projections prove nothing.
// traffic keeps unknown totals in its bounded key table and fails closed at
// capacity rather than resetting a potentially live run after a resnapshot.
func (t *RoutingTable) TerminalTrafficRuns(candidates []TrafficRun) map[TrafficRun]struct{} {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if !t.initialized || len(candidates) == 0 {
		return nil
	}
	requested := make(map[TrafficRun]struct{}, len(candidates))
	for _, candidate := range candidates {
		requested[candidate] = struct{}{}
	}
	runs := make(map[TrafficRun]struct{})
	for _, stored := range t.routes {
		if stored.tombstone && stored.entry.PublishRunClosed != nil && *stored.entry.PublishRunClosed {
			entry := stored.entry
			run := TrafficRun{PublicURLID: entry.PublicUrlId, PublishRunID: entry.PublishRunId, PublishRunNumber: uint64(entry.PublishRunNumber)}
			if _, wanted := requested[run]; wanted {
				runs[run] = struct{}{}
			}
		}
	}
	return runs
}

func (t *RoutingTable) Lookup(canonicalHostname string, now time.Time) (ingressv1.IngressRoutingTableEntry, bool) {
	entry, reason := t.lookup(canonicalHostname, now)
	return entry, reason == LookupCurrent
}

func (t *RoutingTable) lookup(
	canonicalHostname string,
	now time.Time,
) (ingressv1.IngressRoutingTableEntry, LookupReason) {
	canonical, err := naming.CanonicalizeHostname(canonicalHostname)
	if err != nil {
		return ingressv1.IngressRoutingTableEntry{}, LookupInvalidHostname
	}
	entries, reason := t.LookupAllWithReason(canonical, now)
	if len(entries) == 0 {
		return ingressv1.IngressRoutingTableEntry{}, reason
	}
	return entries[0], LookupCurrent
}

func currentEntry(stored routingTableEntry, initialized, exists bool, now time.Time) (ingressv1.IngressRoutingTableEntry, LookupReason) {
	if !initialized {
		return ingressv1.IngressRoutingTableEntry{}, LookupUninitialized
	}
	if !exists {
		return ingressv1.IngressRoutingTableEntry{}, LookupMissing
	}
	if stored.tombstone {
		return ingressv1.IngressRoutingTableEntry{}, LookupTombstone
	}
	if !stored.entry.PublicUrlExpiresAt.After(now) {
		return ingressv1.IngressRoutingTableEntry{}, LookupPublicURLExpired
	}
	entry := cloneRoutingTableEntry(stored.entry)
	// relay renewal does not republish this public URL projection. the copied
	// deadline is a hint; the relay checks its current lease and exact process
	// identity before accepting each internal stream.
	return entry, LookupCurrent
}

func validateRoutingTableEvent(event ingressv1.IngressRoutingTableEvent) error {
	canonical, err := naming.CanonicalizeHostname(event.CanonicalHostname)
	if event.RoutingTableRevision <= 0 || !event.Kind.Valid() || event.PublicUrlId == "" ||
		event.PublishRunNumber <= 0 || err != nil || canonical != event.CanonicalHostname ||
		event.EntryRevision <= 0 || event.CreatedAt.IsZero() {
		return ErrRoutingTableEvent
	}
	entry := event.Entry
	if entry.Traffic != nil {
		if _, err := routingTraffic(*entry.Traffic); err != nil {
			return ErrRoutingTableEvent
		}
	}
	if entry.PublishRunId == "" || entry.PublicUrlId != event.PublicUrlId || entry.PublishRunNumber != event.PublishRunNumber ||
		entry.CanonicalHostname != event.CanonicalHostname || entry.PolicyRevision <= 0 ||
		entry.PublicUrlExpiresAt.IsZero() || !entry.IpPolicy.Valid() ||
		len(entry.PublisherConnections) > 2 {
		return ErrRoutingTableEvent
	}
	if entry.ServiceProtocol != nil && *entry.ServiceProtocol != ingressv1.Http ||
		entry.IngressPoolId != nil && *entry.IngressPoolId == "" {
		return ErrRoutingTableEvent
	}
	if event.Kind == ingressv1.PublicUrlUpsert {
		if entry.PublishRunClosed != nil && *entry.PublishRunClosed {
			return ErrRoutingTableEvent
		}
		if event.PublicUrlExpiresAt == nil || !event.PublicUrlExpiresAt.Equal(entry.PublicUrlExpiresAt) ||
			len(entry.PublisherConnections) == 0 {
			return ErrRoutingTableEvent
		}
	} else if event.PublicUrlExpiresAt != nil || len(entry.PublisherConnections) != 0 {
		return ErrRoutingTableEvent
	}
	if entry.IpPolicy == ingressv1.HashedAllowlist {
		if entry.IpPolicyKey == nil || len(*entry.IpPolicyKey) != 32 {
			return ErrRoutingTableEvent
		}
		var key [32]byte
		copy(key[:], *entry.IpPolicyKey)
		hashes := make([]ippolicy.Entry, len(entry.AllowedIpHashes))
		for index, hashed := range entry.AllowedIpHashes {
			hashes[index] = ippolicy.Entry{
				Family: string(hashed.Family), Bits: hashed.PrefixLength, Digest: hashed.Digest,
			}
		}
		if _, err := ippolicy.New(key, hashes); err != nil {
			return ErrRoutingTableEvent
		}
	} else if entry.IpPolicy != ingressv1.AllowAll || len(entry.AllowedIpHashes) != 0 || entry.IpPolicyKey != nil {
		return ErrRoutingTableEvent
	}
	seenSlots := make(map[int]struct{}, len(entry.PublisherConnections))
	seenConnections := make(map[string]struct{}, len(entry.PublisherConnections))
	seenRelayServices := make(map[string]struct{}, len(entry.PublisherConnections))
	for _, connection := range entry.PublisherConnections {
		if connection.AvailableStreams != nil && *connection.AvailableStreams < 0 {
			return ErrRoutingTableEvent
		}
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
		tombstone: event.Kind == ingressv1.PublicUrlTombstone,
		entry:     cloneRoutingTableEntry(event.Entry),
	}
}

func cloneRoutingTableEntry(source ingressv1.IngressRoutingTableEntry) ingressv1.IngressRoutingTableEntry {
	result := source
	if source.PublishRunClosed != nil {
		closed := *source.PublishRunClosed
		result.PublishRunClosed = &closed
	}
	if source.Traffic != nil {
		traffic := *source.Traffic
		if traffic.TotalConnections != nil {
			value := *traffic.TotalConnections
			traffic.TotalConnections = &value
		}
		if traffic.TotalUploadBytes != nil {
			value := *traffic.TotalUploadBytes
			traffic.TotalUploadBytes = &value
		}
		if traffic.TotalDownloadBytes != nil {
			value := *traffic.TotalDownloadBytes
			traffic.TotalDownloadBytes = &value
		}
		result.Traffic = &traffic
	}
	if source.IngressPoolId != nil {
		pool := *source.IngressPoolId
		result.IngressPoolId = &pool
	}
	if source.ServiceProtocol != nil {
		protocol := *source.ServiceProtocol
		result.ServiceProtocol = &protocol
	}
	result.AllowedIpHashes = append([]ingressv1.HashedIPPrefix(nil), source.AllowedIpHashes...)
	if source.IpPolicyKey != nil {
		key := append([]byte(nil), (*source.IpPolicyKey)...)
		result.IpPolicyKey = &key
	}
	result.PublisherConnections = append(
		[]ingressv1.IngressRoutingPublisherConnection(nil), source.PublisherConnections...,
	)
	for index := range result.PublisherConnections {
		if count := result.PublisherConnections[index].AvailableStreams; count != nil {
			value := *count
			result.PublisherConnections[index].AvailableStreams = &value
		}
	}
	if source.RecoveryEpisodeId != nil {
		value := *source.RecoveryEpisodeId
		result.RecoveryEpisodeId = &value
	}
	return result
}

func routingEventKey(event ingressv1.IngressRoutingTableEvent) string {
	return event.CanonicalHostname + "/" + event.PublicUrlId + "/" + strconv.FormatInt(event.PublishRunNumber, 10)
}

// each run has an independent projection and tombstone. a new run number must
// never erase a healthy sibling, including while its certificate is renewing.
func (t *RoutingTable) LookupAllWithReason(host string, now time.Time) ([]ingressv1.IngressRoutingTableEntry, LookupReason) {
	canonical, err := naming.CanonicalizeHostname(host)
	if err != nil {
		return nil, LookupInvalidHostname
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	if !t.initialized {
		return nil, LookupUninitialized
	}
	result := []ingressv1.IngressRoutingTableEntry{}
	reason := LookupMissing
	for _, stored := range t.routes {
		if stored.entry.CanonicalHostname != canonical {
			continue
		}
		entry, current := currentEntry(stored, true, true, now)
		if current != LookupCurrent {
			reason = current
			continue
		}
		result = append(result, entry)
	}
	slices.SortFunc(result, func(a, b ingressv1.IngressRoutingTableEntry) int {
		if a.PublishRunNumber < b.PublishRunNumber {
			return -1
		}
		if a.PublishRunNumber > b.PublishRunNumber {
			return 1
		}
		return 0
	})
	if len(result) > 0 {
		return result, LookupCurrent
	}
	return nil, reason
}
