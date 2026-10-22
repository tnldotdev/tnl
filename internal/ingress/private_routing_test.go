package ingress

import (
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
)

func privateRoutingEntry(t *testing.T, now time.Time) ingressv1.PrivateServiceProjection {
	t.Helper()
	run, number := privateTestID(t, opaqueid.PrivateRunPrefix), int64(1)
	relays := []ingressv1.PrivateServiceRelay{{PublisherConnectionId: privateTestID(t, opaqueid.PublisherConnectionPrefix), ConnectionSlot: 0,
		ConnectionAssignmentRevision: 3, RelayServiceId: "relay-a", RelayId: "process-a", RelayRunId: privateTestID(t, opaqueid.RelayRunPrefix),
		RelayLeaseRevision: 2, LeaseExpiresAt: now.Add(time.Minute), InternalRelayAddress: "127.0.0.1:443"}}
	return ingressv1.PrivateServiceProjection{PrivateServiceId: privateTestID(t, opaqueid.PrivateServicePrefix), PrivateRunId: &run,
		RunNumber: &number, Revision: 1, Kind: ingressv1.Upsert, ExpiresAt: now.Add(2 * time.Minute), ConnectedRelays: &relays}
}

func TestPrivateRoutingRejectsCrossFieldVariants(t *testing.T) {
	now := time.Now()
	valid := privateRoutingEntry(t, now)
	for name, change := range map[string]func(*ingressv1.PrivateServiceProjection){
		"upsert missing run":    func(p *ingressv1.PrivateServiceProjection) { p.PrivateRunId = nil },
		"upsert missing number": func(p *ingressv1.PrivateServiceProjection) { p.RunNumber = nil },
		"upsert missing relays": func(p *ingressv1.PrivateServiceProjection) { p.ConnectedRelays = nil },
		"tombstone relays":      func(p *ingressv1.PrivateServiceProjection) { p.Kind = ingressv1.Tombstone },
		"tombstone missing run": func(p *ingressv1.PrivateServiceProjection) {
			p.Kind = ingressv1.Tombstone
			p.ConnectedRelays = nil
			p.PrivateRunId = nil
		},
		"tombstone missing number": func(p *ingressv1.PrivateServiceProjection) {
			p.Kind = ingressv1.Tombstone
			p.ConnectedRelays = nil
			p.RunNumber = nil
		},
		"duplicate slot": func(p *ingressv1.PrivateServiceProjection) {
			other := (*p.ConnectedRelays)[0]
			other.RelayServiceId = "relay-b"
			*p.ConnectedRelays = append(*p.ConnectedRelays, other)
		},
		"duplicate service": func(p *ingressv1.PrivateServiceProjection) {
			other := (*p.ConnectedRelays)[0]
			other.ConnectionSlot = 1
			*p.ConnectedRelays = append(*p.ConnectedRelays, other)
		},
		"expired relay": func(p *ingressv1.PrivateServiceProjection) { (*p.ConnectedRelays)[0].LeaseExpiresAt = now },
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
	if _, ok := mustParsePrivateProjection(t, tombstone, now).(privateRunTombstone); !ok {
		t.Fatal("run tombstone not narrowed")
	}
	tombstone.PrivateRunId, tombstone.RunNumber = nil, nil
	if _, ok := mustParsePrivateProjection(t, tombstone, now).(privateServiceTombstone); !ok {
		t.Fatal("service tombstone not narrowed")
	}
}

func mustParsePrivateProjection(t *testing.T, p ingressv1.PrivateServiceProjection, now time.Time) privateProjectionEvent {
	t.Helper()
	parsed, err := parsePrivateProjection(p, now)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestPrivateRoutingPageRollbackAndExactTombstoneScope(t *testing.T) {
	now := time.Now()
	first := privateRoutingEntry(t, now)
	sibling := clonePrivateProjection(first)
	run := privateTestID(t, opaqueid.PrivateRunPrefix)
	sibling.PrivateRunId, sibling.Revision = &run, 2
	unrelated := privateRoutingEntry(t, now)
	unrelated.Revision = 3
	var table PrivateRoutingTable
	if err := table.ApplySnapshot(ingressv1.PrivateServiceSnapshot{Revision: 3, Entries: []ingressv1.PrivateServiceProjection{first, sibling, unrelated}}, now); err != nil {
		t.Fatal(err)
	}
	tombstone := clonePrivateProjection(first)
	tombstone.Kind, tombstone.ConnectedRelays, tombstone.Revision = ingressv1.Tombstone, nil, 4
	update := clonePrivateProjection(sibling)
	update.Revision = 5
	(*update.ConnectedRelays)[0].ConnectionAssignmentRevision++
	(*update.ConnectedRelays)[0].PublisherConnectionId = privateTestID(t, opaqueid.PublisherConnectionPrefix)
	for name, invalid := range map[string]func() ingressv1.PrivateServiceSnapshot{
		"invalid tail": func() ingressv1.PrivateServiceSnapshot {
			bad := clonePrivateProjection(unrelated)
			bad.Revision, bad.RunNumber = 6, nil
			return ingressv1.PrivateServiceSnapshot{Revision: 6, Entries: []ingressv1.PrivateServiceProjection{tombstone, update, bad}}
		},
		"revision gap": func() ingressv1.PrivateServiceSnapshot {
			return ingressv1.PrivateServiceSnapshot{Revision: 6, Entries: []ingressv1.PrivateServiceProjection{tombstone, update}}
		},
		"reordered tail": func() ingressv1.PrivateServiceSnapshot {
			return ingressv1.PrivateServiceSnapshot{Revision: 5, Entries: []ingressv1.PrivateServiceProjection{update, tombstone}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := table.ApplyEvents(3, invalid(), now); !errors.Is(err, ErrPrivateRoutingStale) {
				t.Fatalf("invalid page accepted: %v", err)
			}
			if revision, _ := table.Revision(); revision != 3 {
				t.Fatal("failed page advanced cursor")
			}
			for _, expected := range []ingressv1.PrivateServiceProjection{first, sibling, unrelated} {
				got, ok := table.Lookup(expected.PrivateServiceId, *expected.PrivateRunId, *expected.RunNumber, now)
				if !ok || !reflect.DeepEqual(got, expected) {
					t.Fatal("failed page partially changed state")
				}
			}
		})
	}
	if err := table.ApplyEvents(3, ingressv1.PrivateServiceSnapshot{Revision: 5, Entries: []ingressv1.PrivateServiceProjection{tombstone, update}}, now); err != nil {
		t.Fatal(err)
	}
	if _, ok := table.Lookup(first.PrivateServiceId, *first.PrivateRunId, 1, now); ok {
		t.Fatal("run tombstone left run live")
	}
	if _, ok := table.Lookup(sibling.PrivateServiceId, run, 1, now); !ok {
		t.Fatal("run tombstone removed sibling")
	}
	tombstone.PrivateRunId, tombstone.RunNumber, tombstone.Revision = nil, nil, 6
	if err := table.ApplyEvents(5, ingressv1.PrivateServiceSnapshot{Revision: 6, Entries: []ingressv1.PrivateServiceProjection{tombstone}}, now); err != nil {
		t.Fatal(err)
	}
	if _, ok := table.Lookup(sibling.PrivateServiceId, run, 1, now); ok {
		t.Fatal("service tombstone left sibling live")
	}
	if _, ok := table.Lookup(unrelated.PrivateServiceId, *unrelated.PrivateRunId, 1, now); !ok {
		t.Fatal("service tombstone removed another service")
	}
}

func TestPrivateRoutingAssignmentRollbackAndOwnedProjections(t *testing.T) {
	now := time.Now()
	entry := privateRoutingEntry(t, now)
	*entry.RunNumber = 2
	var table PrivateRoutingTable
	if err := table.ApplySnapshot(ingressv1.PrivateServiceSnapshot{Revision: 1, Entries: []ingressv1.PrivateServiceProjection{entry}}, now); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*ingressv1.PrivateServiceProjection){
		"assignment rollback": func(p *ingressv1.PrivateServiceProjection) { (*p.ConnectedRelays)[0].ConnectionAssignmentRevision-- },
		"same revision new connection": func(p *ingressv1.PrivateServiceProjection) {
			(*p.ConnectedRelays)[0].PublisherConnectionId = privateTestID(t, opaqueid.PublisherConnectionPrefix)
		},
		"run rollback": func(p *ingressv1.PrivateServiceProjection) { *p.RunNumber = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := clonePrivateProjection(entry)
			bad.Revision = 2
			change(&bad)
			if err := table.ApplyEvents(1, ingressv1.PrivateServiceSnapshot{Revision: 2, Entries: []ingressv1.PrivateServiceProjection{bad}}, now); !errors.Is(err, ErrPrivateRoutingStale) {
				t.Fatalf("stale assignment accepted: %v", err)
			}
		})
	}
	service, run := entry.PrivateServiceId, *entry.PrivateRunId
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
	entry := privateRoutingEntry(t, now)
	var table PrivateRoutingTable
	if err := table.ApplySnapshot(ingressv1.PrivateServiceSnapshot{Revision: 1, Entries: []ingressv1.PrivateServiceProjection{entry}}, now); err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for range 4 {
		group.Go(func() {
			for range 100 {
				got, ok := table.Lookup(entry.PrivateServiceId, *entry.PrivateRunId, 1, now)
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
		if err := table.ApplyEvents(revision-1, ingressv1.PrivateServiceSnapshot{Revision: revision, Entries: []ingressv1.PrivateServiceProjection{update}}, now); err != nil {
			t.Fatal(err)
		}
	}
	group.Wait()
}

func TestPrivateRoutingInvalidSnapshotKeepsInstalledState(t *testing.T) {
	now := time.Now()
	entry := privateRoutingEntry(t, now)
	var table PrivateRoutingTable
	if err := table.ApplySnapshot(ingressv1.PrivateServiceSnapshot{Revision: 3, Entries: []ingressv1.PrivateServiceProjection{entry}}, now); err != nil {
		t.Fatal(err)
	}
	tombstone := clonePrivateProjection(entry)
	tombstone.Kind, tombstone.ConnectedRelays = ingressv1.Tombstone, nil
	for name, snapshot := range map[string]ingressv1.PrivateServiceSnapshot{
		"older cursor":  {Revision: 2, Entries: []ingressv1.PrivateServiceProjection{entry}},
		"duplicate run": {Revision: 4, Entries: []ingressv1.PrivateServiceProjection{entry, entry}},
		"tombstone":     {Revision: 4, Entries: []ingressv1.PrivateServiceProjection{tombstone}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := table.ApplySnapshot(snapshot, now); !errors.Is(err, ErrPrivateRoutingStale) {
				t.Fatalf("invalid snapshot accepted: %v", err)
			}
			if revision, ready := table.Revision(); !ready || revision != 3 {
				t.Fatal("invalid snapshot replaced cursor")
			}
			if got, ok := table.Lookup(entry.PrivateServiceId, *entry.PrivateRunId, *entry.RunNumber, now); !ok || !reflect.DeepEqual(got, entry) {
				t.Fatal("invalid snapshot replaced routing state")
			}
		})
	}
}
