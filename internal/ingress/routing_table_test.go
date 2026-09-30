package ingress

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
)

func TestRoutingTablePageOwnershipAndAtomicity(t *testing.T) {
	for _, kind := range []ingressv1.IngressRoutingTableEventKind{ingressv1.PublicUrlUpsert, ingressv1.ChallengeUpsert} {
		t.Run(string(kind), func(t *testing.T) {
			now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
			makeEvent := func(revision int64, name string) ingressv1.IngressRoutingTableEvent {
				entry := forwardingTestEntry(now, "relay.example:443")
				entry.PublicUrlId = "public_url_" + name
				entry.CanonicalHostname = name + ".example"
				entry.PolicyRevision = 1
				entry.IpPolicy = ingressv1.Allowlist
				entry.AllowedIpPrefixes = []string{"192.0.2.0/24"}
				recoveryEpisodeID := int64(1)
				entry.RecoveryEpisodeId = &recoveryEpisodeID
				return ingressv1.IngressRoutingTableEvent{
					RoutingTableRevision: revision, Kind: kind, PublicUrlId: entry.PublicUrlId,
					PublishRunNumber: entry.PublishRunNumber, CanonicalHostname: entry.CanonicalHostname,
					EntryRevision: revision, Entry: entry, PublicUrlExpiresAt: &entry.PublicUrlExpiresAt, CreatedAt: now,
				}
			}
			var table RoutingTable
			lookup := table.Lookup
			if kind == ingressv1.ChallengeUpsert {
				lookup = table.LookupChallenge
			}
			first, second := makeEvent(1, "first"), makeEvent(2, "second")
			if err := table.ApplySnapshot(ingressv1.IngressRoutingTableSnapshot{
				ThroughRevision: 1, Entries: []ingressv1.IngressRoutingTableEvent{first},
			}); err != nil {
				t.Fatal(err)
			}
			if err := table.ApplyPage(1, ingressv1.IngressRoutingTablePage{
				ThroughRevision: 2, NextRevision: 2, Events: []ingressv1.IngressRoutingTableEvent{second},
			}); err != nil {
				t.Fatal(err)
			}
			// Neither input nor lookup mutations may change retained or new entries.
			for _, event := range []ingressv1.IngressRoutingTableEvent{first, second} {
				event.Entry.AllowedIpPrefixes[0] = "198.51.100.0/24"
				event.Entry.PublisherConnections[0].RelayId = "changed"
				*event.Entry.RecoveryEpisodeId = 99
				entry, ok := lookup(event.CanonicalHostname, now)
				if !ok {
					t.Fatal("route missing after page")
				}
				entry.AllowedIpPrefixes[0] = "203.0.113.0/24"
				entry.PublisherConnections[0].RelayId = "changed"
				*entry.RecoveryEpisodeId = 100
			}
			// A valid first event must not leak out when a later event is stale.
			updated, stale := makeEvent(3, "first"), makeEvent(4, "second")
			updated.Entry.AllowedIpPrefixes[0] = "198.51.100.0/24"
			stale.EntryRevision = 2
			if err := table.ApplyPage(2, ingressv1.IngressRoutingTablePage{
				ThroughRevision: 4, NextRevision: 4, Events: []ingressv1.IngressRoutingTableEvent{updated, stale},
			}); !errors.Is(err, ErrRoutingTableEvent) {
				t.Fatalf("stale page error = %v", err)
			}
			if err := table.ApplyPage(2, ingressv1.IngressRoutingTablePage{ThroughRevision: 2, NextRevision: 2}); err != nil {
				t.Fatalf("empty page: %v", err)
			}
			if err := table.ApplyPage(2, ingressv1.IngressRoutingTablePage{ThroughRevision: 3, NextRevision: 3}); !errors.Is(err, ErrRoutingTableRevision) {
				t.Fatalf("empty page advancing revision error = %v", err)
			}
			for _, name := range []string{"first", "second"} {
				want := makeEvent(1, name).Entry
				got, ok := lookup(want.CanonicalHostname, now)
				if !ok || !reflect.DeepEqual(got, want) {
					t.Fatalf("route %s changed: got %#v, want %#v", name, got, want)
				}
			}
			if revision, initialized := table.Revision(); !initialized || revision != 2 {
				t.Fatalf("table revision = %d, initialized = %t", revision, initialized)
			}
		})
	}
}

func TestRoutingTableAcceptsLargePublicURLIPPolicy(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	entry := forwardingTestEntry(now, "relay.example:443")
	entry.CanonicalHostname = "route.example"
	entry.PolicyRevision = 1
	entry.IpPolicy = ingressv1.Allowlist
	for index := range 256 {
		entry.AllowedIpPrefixes = append(entry.AllowedIpPrefixes, fmt.Sprintf("2001:db8:%x::/48", index))
	}
	event := ingressv1.IngressRoutingTableEvent{
		RoutingTableRevision: 1, Kind: ingressv1.PublicUrlUpsert,
		PublicUrlId: entry.PublicUrlId, PublishRunNumber: entry.PublishRunNumber,
		CanonicalHostname: entry.CanonicalHostname, EntryRevision: 1,
		Entry: entry, PublicUrlExpiresAt: &entry.PublicUrlExpiresAt, CreatedAt: now,
	}
	var table RoutingTable
	if err := table.ApplySnapshot(ingressv1.IngressRoutingTableSnapshot{
		ThroughRevision: 1, Entries: []ingressv1.IngressRoutingTableEvent{event},
	}); err != nil {
		t.Fatal(err)
	}
	got, ok := table.Lookup(entry.CanonicalHostname, now)
	if !ok || len(got.AllowedIpPrefixes) != 256 {
		t.Fatalf("large routing table entry = %t, %d prefixes", ok, len(got.AllowedIpPrefixes))
	}
	prefixes := make([]netip.Prefix, len(got.AllowedIpPrefixes))
	for index, value := range got.AllowedIpPrefixes {
		prefixes[index] = netip.MustParsePrefix(value)
	}
	if !ipAllowed(netip.MustParseAddr("2001:db8:ff::1"), prefixes) ||
		ipAllowed(netip.MustParseAddr("2001:db8:100::1"), prefixes) {
		t.Fatal("large routing table IP policy matched the wrong source")
	}
}

func TestRoutingTableSnapshotDoesNotRegressRevision(t *testing.T) {
	var table RoutingTable
	if err := table.ApplySnapshot(ingressv1.IngressRoutingTableSnapshot{ThroughRevision: 4}); err != nil {
		t.Fatal(err)
	}
	if err := table.ApplySnapshot(ingressv1.IngressRoutingTableSnapshot{ThroughRevision: 3}); !errors.Is(err, ErrRoutingTableRevision) {
		t.Fatalf("stale snapshot = %v", err)
	}
	if revision, ready := table.Revision(); !ready || revision != 4 {
		t.Fatalf("snapshot rolled routing revision back to %d, ready = %t", revision, ready)
	}
}

func TestRoutingTableExplainsUnavailableChallenge(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	entry := forwardingTestEntry(now, "relay.example:443")
	entry.CanonicalHostname = "route.example"
	entry.PolicyRevision = 1
	entry.IpPolicy = ingressv1.AllowAll
	event := ingressv1.IngressRoutingTableEvent{
		RoutingTableRevision: 1, Kind: ingressv1.ChallengeUpsert,
		PublicUrlId: entry.PublicUrlId, PublishRunNumber: entry.PublishRunNumber,
		CanonicalHostname: entry.CanonicalHostname, EntryRevision: 1,
		Entry: entry, PublicUrlExpiresAt: &entry.PublicUrlExpiresAt, CreatedAt: now,
	}
	for _, test := range []struct {
		name, reason string
		change       func(*ingressv1.IngressRoutingTableEvent)
	}{
		{"ready", "", func(*ingressv1.IngressRoutingTableEvent) {}},
		{"renewed relay with old projected deadline", "", func(e *ingressv1.IngressRoutingTableEvent) {
			e.Entry.PublisherConnections[0].LeaseExpiresAt = now
		}},
		{"route expired", "public_url_expired", func(e *ingressv1.IngressRoutingTableEvent) {
			e.Entry.PublicUrlExpiresAt = now
			e.PublicUrlExpiresAt = &e.Entry.PublicUrlExpiresAt
		}},
		{"tombstone", "tombstone", func(e *ingressv1.IngressRoutingTableEvent) {
			e.Kind = ingressv1.ChallengeTombstone
			e.PublicUrlExpiresAt = nil
			e.Entry.PublisherConnections = nil
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			current := event
			current.Entry = cloneRoutingTableEntry(event.Entry)
			test.change(&current)
			var table RoutingTable
			if test.name == "tombstone" {
				if err := table.ApplySnapshot(ingressv1.IngressRoutingTableSnapshot{
					ThroughRevision: 1, Entries: []ingressv1.IngressRoutingTableEvent{event},
				}); err != nil {
					t.Fatal(err)
				}
				current.RoutingTableRevision, current.EntryRevision = 2, 2
				if err := table.ApplyPage(1, ingressv1.IngressRoutingTablePage{
					ThroughRevision: 2, NextRevision: 2, Events: []ingressv1.IngressRoutingTableEvent{current},
				}); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := table.ApplySnapshot(ingressv1.IngressRoutingTableSnapshot{
					ThroughRevision: 1, Entries: []ingressv1.IngressRoutingTableEvent{current},
				}); err != nil {
					t.Fatal(err)
				}
			}
			_, reason := table.LookupChallengeWithReason(entry.CanonicalHostname, now)
			if reason != test.reason {
				t.Fatalf("challenge lookup reason = %q, want %q", reason, test.reason)
			}
			if test.name == "ready" {
				_, reason = table.LookupChallengeWithReason("missing.example", now)
				if reason != "missing" {
					t.Fatalf("missing challenge reason = %q", reason)
				}
			}
		})
	}
}
