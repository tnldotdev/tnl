package ingress

import (
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
)

func serviceRoutingEntry(t *testing.T, now time.Time) ingressv1.ServiceProjection {
	t.Helper()
	run, number := privateTestID(t, opaqueid.ServiceRunPrefix), int64(1)
	relays := []ingressv1.ServiceRelay{{PublisherConnectionId: privateTestID(t, opaqueid.PublisherConnectionPrefix), ConnectionSlot: 0,
		ConnectionAssignmentRevision: 3, RelayServiceId: "relay-a", RelayId: "process-a", RelayRunId: privateTestID(t, opaqueid.RelayRunPrefix),
		RelayLeaseRevision: 2, LeaseExpiresAt: now.Add(time.Minute), InternalRelayAddress: "127.0.0.1:443"}}
	return ingressv1.ServiceProjection{ServiceId: privateTestID(t, opaqueid.ServicePrefix), ServiceRunId: &run,
		RunNumber: &number, Revision: 1, Kind: ingressv1.Upsert, ExpiresAt: now.Add(2 * time.Minute), ConnectedRelays: &relays}
}

func TestPrivateRoutingRejectsCrossFieldVariants(t *testing.T) {
	now := time.Now()
	valid := serviceRoutingEntry(t, now)
	for name, change := range map[string]func(*ingressv1.ServiceProjection){
		"upsert missing run":    func(p *ingressv1.ServiceProjection) { p.ServiceRunId = nil },
		"upsert missing number": func(p *ingressv1.ServiceProjection) { p.RunNumber = nil },
		"upsert missing relays": func(p *ingressv1.ServiceProjection) { p.ConnectedRelays = nil },
		"tombstone relays":      func(p *ingressv1.ServiceProjection) { p.Kind = ingressv1.Tombstone },
		"tombstone missing run": func(p *ingressv1.ServiceProjection) {
			p.Kind = ingressv1.Tombstone
			p.ConnectedRelays = nil
			p.ServiceRunId = nil
		},
		"tombstone missing number": func(p *ingressv1.ServiceProjection) {
			p.Kind = ingressv1.Tombstone
			p.ConnectedRelays = nil
			p.RunNumber = nil
		},
		"duplicate slot": func(p *ingressv1.ServiceProjection) {
			other := (*p.ConnectedRelays)[0]
			other.RelayServiceId = "relay-b"
			*p.ConnectedRelays = append(*p.ConnectedRelays, other)
		},
		"duplicate service": func(p *ingressv1.ServiceProjection) {
			other := (*p.ConnectedRelays)[0]
			other.ConnectionSlot = 1
			*p.ConnectedRelays = append(*p.ConnectedRelays, other)
		},
		"expired relay": func(p *ingressv1.ServiceProjection) { (*p.ConnectedRelays)[0].LeaseExpiresAt = now },
	} {
		t.Run(name, func(t *testing.T) {
			entry := clonePrivateProjection(valid)
			change(&entry)
			if _, err := parsePrivateProjection(entry, now); !errors.Is(err, ErrPrivateRoutingStale) {
				t.Fatalf("invalid variant accepted: %v", err)
			}
		})
	}
	// tombstones may already be expired when read; they still remove state.
	tombstone := clonePrivateProjection(valid)
	tombstone.Kind, tombstone.ConnectedRelays, tombstone.ExpiresAt = ingressv1.Tombstone, nil, now.Add(-time.Second)
	if _, ok := mustParsePrivateProjection(t, tombstone, now).(serviceRunTombstone); !ok {
		t.Fatal("run tombstone not narrowed")
	}
	tombstone.ServiceRunId, tombstone.RunNumber = nil, nil
	if _, ok := mustParsePrivateProjection(t, tombstone, now).(serviceTombstone); !ok {
		t.Fatal("service tombstone not narrowed")
	}
}

func mustParsePrivateProjection(t *testing.T, p ingressv1.ServiceProjection, now time.Time) privateProjectionEvent {
	t.Helper()
	parsed, err := parsePrivateProjection(p, now)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestPrivateRoutingPageRollbackAndExactTombstoneScope(t *testing.T) {
	now := time.Now()
	first := serviceRoutingEntry(t, now)
	sibling := clonePrivateProjection(first)
	run := privateTestID(t, opaqueid.ServiceRunPrefix)
	sibling.ServiceRunId, sibling.Revision = &run, 2
	unrelated := serviceRoutingEntry(t, now)
	unrelated.Revision = 3
	var table ServiceRoutingTable
	if err := table.ApplySnapshot(ingressv1.ServiceSnapshot{Revision: 3, Entries: []ingressv1.ServiceProjection{first, sibling, unrelated}}, now); err != nil {
		t.Fatal(err)
	}
	tombstone := clonePrivateProjection(first)
	tombstone.Kind, tombstone.ConnectedRelays, tombstone.Revision = ingressv1.Tombstone, nil, 4
	update := clonePrivateProjection(sibling)
	update.Revision = 5
	(*update.ConnectedRelays)[0].ConnectionAssignmentRevision++
	(*update.ConnectedRelays)[0].PublisherConnectionId = privateTestID(t, opaqueid.PublisherConnectionPrefix)
	for name, invalid := range map[string]func() ingressv1.ServiceSnapshot{
		"invalid tail": func() ingressv1.ServiceSnapshot {
			bad := clonePrivateProjection(unrelated)
			bad.Revision, bad.RunNumber = 6, nil
			return ingressv1.ServiceSnapshot{Revision: 6, Entries: []ingressv1.ServiceProjection{tombstone, update, bad}}
		},
		"revision gap": func() ingressv1.ServiceSnapshot {
			return ingressv1.ServiceSnapshot{Revision: 6, Entries: []ingressv1.ServiceProjection{tombstone, update}}
		},
		"reordered tail": func() ingressv1.ServiceSnapshot {
			return ingressv1.ServiceSnapshot{Revision: 5, Entries: []ingressv1.ServiceProjection{update, tombstone}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := table.ApplyEvents(3, invalid(), now); !errors.Is(err, ErrPrivateRoutingStale) {
				t.Fatalf("invalid page accepted: %v", err)
			}
			if revision, _ := table.Revision(); revision != 3 {
				t.Fatal("failed page advanced cursor")
			}
			for _, expected := range []ingressv1.ServiceProjection{first, sibling, unrelated} {
				got, ok := table.Lookup(expected.ServiceId, *expected.ServiceRunId, *expected.RunNumber, now)
				if !ok || !reflect.DeepEqual(got, expected) {
					t.Fatal("failed page partially changed state")
				}
			}
		})
	}
	if err := table.ApplyEvents(3, ingressv1.ServiceSnapshot{Revision: 5, Entries: []ingressv1.ServiceProjection{tombstone, update}}, now); err != nil {
		t.Fatal(err)
	}
	if _, ok := table.Lookup(first.ServiceId, *first.ServiceRunId, 1, now); ok {
		t.Fatal("run tombstone left run live")
	}
	if _, ok := table.Lookup(sibling.ServiceId, run, 1, now); !ok {
		t.Fatal("run tombstone removed sibling")
	}
	tombstone.ServiceRunId, tombstone.RunNumber, tombstone.Revision = nil, nil, 6
	if err := table.ApplyEvents(5, ingressv1.ServiceSnapshot{Revision: 6, Entries: []ingressv1.ServiceProjection{tombstone}}, now); err != nil {
		t.Fatal(err)
	}
	if _, ok := table.Lookup(sibling.ServiceId, run, 1, now); ok {
		t.Fatal("service tombstone left sibling live")
	}
	if _, ok := table.Lookup(unrelated.ServiceId, *unrelated.ServiceRunId, 1, now); !ok {
		t.Fatal("service tombstone removed another service")
	}
}

func TestPrivateRoutingAssignmentRollbackAndOwnedProjections(t *testing.T) {
	now := time.Now()
	entry := serviceRoutingEntry(t, now)
	*entry.RunNumber = 2
	var table ServiceRoutingTable
	if err := table.ApplySnapshot(ingressv1.ServiceSnapshot{Revision: 1, Entries: []ingressv1.ServiceProjection{entry}}, now); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*ingressv1.ServiceProjection){
		"assignment rollback": func(p *ingressv1.ServiceProjection) { (*p.ConnectedRelays)[0].ConnectionAssignmentRevision-- },
		"same revision new connection": func(p *ingressv1.ServiceProjection) {
			(*p.ConnectedRelays)[0].PublisherConnectionId = privateTestID(t, opaqueid.PublisherConnectionPrefix)
		},
		"run rollback": func(p *ingressv1.ServiceProjection) { *p.RunNumber = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := clonePrivateProjection(entry)
			bad.Revision = 2
			change(&bad)
			if err := table.ApplyEvents(1, ingressv1.ServiceSnapshot{Revision: 2, Entries: []ingressv1.ServiceProjection{bad}}, now); !errors.Is(err, ErrPrivateRoutingStale) {
				t.Fatalf("stale assignment accepted: %v", err)
			}
		})
	}
	service, run := entry.ServiceId, *entry.ServiceRunId
	(*entry.ConnectedRelays)[0].RelayId = "caller-mutated"
	*entry.RunNumber = 99
	got, ok := table.Lookup(service, run, 2, now)
	if !ok || (*got.ConnectedRelays)[0].RelayId == "caller-mutated" {
		t.Fatal("snapshot aliases caller memory")
	}
	(*got.ConnectedRelays)[0].RelayId = "reader-mutated"
	*got.RunNumber = 99
	got, ok = table.Lookup(service, run, 2, now)
	if !ok || (*got.ConnectedRelays)[0].RelayId == "reader-mutated" {
		t.Fatal("lookup aliases table memory")
	}
	if _, ok := table.Lookup(service, run, 2, now.Add(time.Minute)); ok {
		t.Fatal("private routing ignored copied relay lease expiry")
	}
}

func TestPrivateRoutingConcurrentLookupAndAtomicPages(t *testing.T) {
	now := time.Now()
	entry := serviceRoutingEntry(t, now)
	var table ServiceRoutingTable
	if err := table.ApplySnapshot(ingressv1.ServiceSnapshot{Revision: 1, Entries: []ingressv1.ServiceProjection{entry}}, now); err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for range 4 {
		group.Go(func() {
			for range 100 {
				got, ok := table.Lookup(entry.ServiceId, *entry.ServiceRunId, 1, now)
				if !ok {
					t.Error("atomic update lost live run")
					return
				}
				(*got.ConnectedRelays)[0].RelayId = "reader-owned"
			}
		})
	}
	for revision := int64(2); revision <= 100; revision++ {
		update := clonePrivateProjection(entry)
		update.Revision = revision
		if err := table.ApplyEvents(revision-1, ingressv1.ServiceSnapshot{Revision: revision, Entries: []ingressv1.ServiceProjection{update}}, now); err != nil {
			t.Fatal(err)
		}
	}
	group.Wait()
}

func TestPrivateRoutingInvalidSnapshotKeepsInstalledState(t *testing.T) {
	now := time.Now()
	entry := serviceRoutingEntry(t, now)
	var table ServiceRoutingTable
	if err := table.ApplySnapshot(ingressv1.ServiceSnapshot{Revision: 3, Entries: []ingressv1.ServiceProjection{entry}}, now); err != nil {
		t.Fatal(err)
	}
	tombstone := clonePrivateProjection(entry)
	tombstone.Kind, tombstone.ConnectedRelays = ingressv1.Tombstone, nil
	for name, snapshot := range map[string]ingressv1.ServiceSnapshot{
		"older cursor":  {Revision: 2, Entries: []ingressv1.ServiceProjection{entry}},
		"duplicate run": {Revision: 4, Entries: []ingressv1.ServiceProjection{entry, entry}},
		"tombstone":     {Revision: 4, Entries: []ingressv1.ServiceProjection{tombstone}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := table.ApplySnapshot(snapshot, now); !errors.Is(err, ErrPrivateRoutingStale) {
				t.Fatalf("invalid snapshot accepted: %v", err)
			}
			if revision, ready := table.Revision(); !ready || revision != 3 {
				t.Fatal("invalid snapshot replaced cursor")
			}
			if got, ok := table.Lookup(entry.ServiceId, *entry.ServiceRunId, *entry.RunNumber, now); !ok || !reflect.DeepEqual(got, entry) {
				t.Fatal("invalid snapshot replaced routing state")
			}
		})
	}
}
