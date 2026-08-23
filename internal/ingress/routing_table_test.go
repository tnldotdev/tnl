package ingress

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
)

func TestRoutingTablePageOwnershipAndAtomicity(t *testing.T) {
	for _, kind := range []ingressv1.IngressRoutingTableEventKind{ingressv1.RouteUpsert, ingressv1.ChallengeUpsert} {
		t.Run(string(kind), func(t *testing.T) {
			now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
			makeEvent := func(revision int64, name string) ingressv1.IngressRoutingTableEvent {
				entry := forwardingTestEntry(now, "relay.example:443")
				entry.RouteId = "route_" + name
				entry.CanonicalHostname = name + ".example"
				entry.PolicyRevision = 1
				entry.IpPolicy = ingressv1.Allowlist
				entry.AllowedIpPrefixes = []string{"192.0.2.0/24"}
				recoveryEpisodeID := int64(1)
				entry.RecoveryEpisodeId = &recoveryEpisodeID
				return ingressv1.IngressRoutingTableEvent{
					RoutingTableRevision: revision, Kind: kind, RouteId: entry.RouteId,
					RouteVersion: entry.RouteVersion, CanonicalHostname: entry.CanonicalHostname,
					EntryRevision: revision, Entry: entry, RouteExpiresAt: &entry.RouteExpiresAt, CreatedAt: now,
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
