package ingress

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/ippolicy"
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
				hashedRoutingPolicyForTest(t, &entry, "192.0.2.0/24")
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
			// neither input nor lookup mutations may change retained or new entries.
			for _, event := range []ingressv1.IngressRoutingTableEvent{first, second} {
				event.Entry.AllowedIpHashes[0].Digest = "changed"
				event.Entry.PublisherConnections[0].RelayId = "changed"
				*event.Entry.RecoveryEpisodeId = 99
				entry, ok := lookup(event.CanonicalHostname, now)
				if !ok {
					t.Fatal("route missing after page")
				}
				entry.AllowedIpHashes[0].Digest = "changed"
				entry.PublisherConnections[0].RelayId = "changed"
				*entry.RecoveryEpisodeId = 100
			}
			// a valid first event must not leak out when a later event is stale.
			updated, stale := makeEvent(3, "first"), makeEvent(4, "second")
			updatedHash, err := ippolicy.Hash(policyTestKey, netip.MustParsePrefix("198.51.100.0/24"))
			if err != nil {
				t.Fatal(err)
			}
			updated.Entry.AllowedIpHashes[0].Digest = updatedHash.Digest
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

func TestRoutingTablePortClaimsStayAtomicAcrossPages(t *testing.T) {
	now := time.Now().UTC()
	event := func(revision int64, hostname, pool string, port int) ingressv1.IngressRoutingTableEvent {
		entry := forwardingTestEntry(now, "relay.example:443")
		entry.PublicUrlId = "public_url_" + hostname
		entry.CanonicalHostname = hostname + ".example"
		entry.PolicyRevision = 1
		entry.IpPolicy = ingressv1.AllowAll
		id, protocol := ingressv1.Identifier(pool), ingressv1.Postgres
		entry.IngressPoolId, entry.ServiceProtocol, entry.PublicPort = &id, &protocol, &port
		return ingressv1.IngressRoutingTableEvent{
			RoutingTableRevision: revision, Kind: ingressv1.PublicUrlUpsert,
			PublicUrlId: entry.PublicUrlId, PublishRunNumber: entry.PublishRunNumber,
			CanonicalHostname: entry.CanonicalHostname, EntryRevision: revision,
			Entry: entry, PublicUrlExpiresAt: &entry.PublicUrlExpiresAt, CreatedAt: now,
		}
	}
	first := event(1, "one", "ingress-a", 5432)
	var table RoutingTable
	if err := table.ApplySnapshot(ingressv1.IngressRoutingTableSnapshot{ThroughRevision: 1, Entries: []ingressv1.IngressRoutingTableEvent{first}}); err != nil {
		t.Fatal(err)
	}
	*first.Entry.PublicPort = 9999
	if got, reason := table.LookupPortWithReason("ingress-a", 5432, now); reason != "" || *got.PublicPort != 5432 {
		t.Fatalf("retained port = %+v, reason %q", got, reason)
	}
	if _, reason := table.LookupPortWithReason("ingress-b", 5432, now); reason != "missing" {
		t.Fatalf("wrong pool lookup reason = %q", reason)
	}
	second := event(2, "two", "ingress-a", 5432)
	if err := table.ApplyPage(1, ingressv1.IngressRoutingTablePage{ThroughRevision: 2, NextRevision: 2, Events: []ingressv1.IngressRoutingTableEvent{second}}); !errors.Is(err, ErrRoutingTableEvent) {
		t.Fatalf("colliding port page = %v", err)
	}
	if got, reason := table.LookupPortWithReason("ingress-a", 5432, now); reason != "" || got.PublicUrlId != first.PublicUrlId {
		t.Fatalf("collision changed active port: %+v, %q", got, reason)
	}
	if err := table.ApplySnapshot(ingressv1.IngressRoutingTableSnapshot{ThroughRevision: 2, Entries: []ingressv1.IngressRoutingTableEvent{event(1, "one", "ingress-a", 5432), second}}); !errors.Is(err, ErrRoutingTableEvent) {
		t.Fatalf("colliding snapshot = %v", err)
	}
	tombstone := event(2, "one", "ingress-a", 5432)
	tombstone.Kind, tombstone.PublicUrlExpiresAt, tombstone.Entry.PublisherConnections = ingressv1.PublicUrlTombstone, nil, nil
	otherPool := event(3, "two", "ingress-b", 5432)
	if err := table.ApplyPage(1, ingressv1.IngressRoutingTablePage{ThroughRevision: 3, NextRevision: 3, Events: []ingressv1.IngressRoutingTableEvent{tombstone, otherPool}}); err != nil {
		t.Fatal(err)
	}
	if _, reason := table.LookupPortWithReason("ingress-a", 5432, now); reason != "missing" {
		t.Fatalf("tombstoned port reason = %q", reason)
	}
	if got, reason := table.LookupPortWithReason("ingress-b", 5432, now); reason != "" || got.PublicUrlId != otherPool.PublicUrlId {
		t.Fatalf("other pool port = %+v, %q", got, reason)
	}
}

func TestRoutingTableAcceptsLargePublicURLIPPolicy(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	entry := forwardingTestEntry(now, "relay.example:443")
	entry.CanonicalHostname = "route.example"
	entry.PolicyRevision = 1
	entry.IpPolicy = ingressv1.HashedAllowlist
	key := append([]byte(nil), policyTestKey[:]...)
	entry.IpPolicyKey = &key
	for index := range 256 {
		hashed, err := ippolicy.Hash(policyTestKey, netip.MustParsePrefix(fmt.Sprintf("2001:db8:%x::/48", index)))
		if err != nil {
			t.Fatal(err)
		}
		entry.AllowedIpHashes = append(entry.AllowedIpHashes, ingressv1.HashedIPPrefix{
			Family: ingressv1.HashedIPPrefixFamily(hashed.Family), PrefixLength: hashed.Bits, Digest: hashed.Digest,
		})
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
	if !ok || len(got.AllowedIpHashes) != 256 {
		t.Fatalf("large routing table entry = %t, %d hashes", ok, len(got.AllowedIpHashes))
	}
	entries := make([]ippolicy.Entry, len(got.AllowedIpHashes))
	for index, value := range got.AllowedIpHashes {
		entries[index] = ippolicy.Entry{Family: string(value.Family), Bits: value.PrefixLength, Digest: value.Digest}
	}
	policy, err := ippolicy.New(policyTestKey, entries)
	if err != nil || !policy.Allows(netip.MustParseAddr("2001:db8:ff::1")) ||
		policy.Allows(netip.MustParseAddr("2001:db8:100::1")) {
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
