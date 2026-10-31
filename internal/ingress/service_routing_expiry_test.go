package ingress

import (
	"errors"
	"testing"
	"time"

	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
)

func TestPrivateRoutingPageCrossesHistoricalExpiry(t *testing.T) {
	// control reads an older upsert while it is still live. its relay lease
	// expires in transit, but the same page contains the renewed projection.
	for _, expiry := range []string{"run", "relay"} {
		t.Run(expiry, func(t *testing.T) { privateRoutingPageCrossesExpiry(t, expiry) })
	}
}

func privateRoutingPageCrossesExpiry(t *testing.T, expiry string) {
	t.Helper()
	readAt := time.Date(2026, time.October, 29, 0, 0, 0, 0, time.UTC)
	initial := serviceRoutingEntry(t, readAt)
	var table ServiceRoutingTable
	if err := table.ApplySnapshot(ingressv1.ServiceSnapshot{Revision: 1, Entries: []ingressv1.ServiceProjection{initial}}); err != nil {
		t.Fatal(err)
	}
	older := clonePrivateProjection(initial)
	older.Revision = 2
	if expiry == "run" {
		older.ExpiresAt = readAt.Add(time.Millisecond)
	} else {
		(*older.ConnectedRelays)[0].LeaseExpiresAt = readAt.Add(time.Millisecond)
	}
	renewed := clonePrivateProjection(initial)
	renewed.Revision = 3
	page := ingressv1.ServiceSnapshot{Revision: 3, Entries: []ingressv1.ServiceProjection{older, renewed}}
	for _, entry := range page.Entries {
		if err := validateDirectProjection(entry, readAt); err != nil {
			t.Fatalf("control produced an invalid projection: %v", err)
		}
	}
	receivedAt := readAt.Add(2 * time.Millisecond)
	if err := table.ApplyEvents(1, page); err != nil {
		t.Fatalf("expired history rejected the current relay: %v", err)
	}
	got, ok := table.Lookup(initial.ServiceId, *initial.ServiceRunId, *initial.RunNumber, receivedAt)
	if !ok || got.Revision != renewed.Revision || len(*got.ConnectedRelays) != 1 || !(*got.ConnectedRelays)[0].LeaseExpiresAt.Equal((*renewed.ConnectedRelays)[0].LeaseExpiresAt) {
		t.Fatalf("renewed relay unavailable after applying page: %+v, found=%v", got, ok)
	}
	if revision, ready := table.Revision(); !ready || revision != page.Revision {
		t.Fatalf("page was not installed atomically: cursor=%d ready=%v", revision, ready)
	}

	// an expired final event advances history without making its run routable.
	older.Revision = 4
	if err := table.ApplyEvents(3, ingressv1.ServiceSnapshot{Revision: 4, Entries: []ingressv1.ServiceProjection{older}}); err != nil {
		t.Fatal(err)
	}
	if _, ok := table.Lookup(initial.ServiceId, *initial.ServiceRunId, *initial.RunNumber, receivedAt); ok {
		t.Fatal("expired final event became routable")
	}
	// expiration does not erase assignment history or permit a rollback.
	rollback := clonePrivateProjection(renewed)
	rollback.Revision = 5
	(*rollback.ConnectedRelays)[0].ConnectionAssignmentRevision--
	if err := table.ApplyEvents(4, ingressv1.ServiceSnapshot{Revision: 5, Entries: []ingressv1.ServiceProjection{rollback}}); !errors.Is(err, ErrPrivateRoutingStale) {
		t.Fatalf("expired history permitted assignment rollback: %v", err)
	}
	if revision, _ := table.Revision(); revision != 4 {
		t.Fatal("rejected rollback advanced cursor")
	}
	renewed.Revision = 5
	if err := table.ApplyEvents(4, ingressv1.ServiceSnapshot{Revision: 5, Entries: []ingressv1.ServiceProjection{renewed}}); err != nil {
		t.Fatal(err)
	}
	if _, ok := table.Lookup(initial.ServiceId, *initial.ServiceRunId, *initial.RunNumber, receivedAt); !ok {
		t.Fatal("later renewal did not restore routing")
	}
}

func TestPrivateRoutingExpiredHistoryStillValidatesShape(t *testing.T) {
	now := time.Date(2026, time.October, 29, 0, 0, 0, 0, time.UTC)
	initial := serviceRoutingEntry(t, now)
	for name, change := range map[string]func(*ingressv1.ServiceProjection){
		"missing run":          func(p *ingressv1.ServiceProjection) { p.ServiceRunId = nil },
		"missing run expiry":   func(p *ingressv1.ServiceProjection) { p.ExpiresAt = time.Time{} },
		"missing relay expiry": func(p *ingressv1.ServiceProjection) { (*p.ConnectedRelays)[0].LeaseExpiresAt = time.Time{} },
		"duplicate slot": func(p *ingressv1.ServiceProjection) {
			other := (*p.ConnectedRelays)[0]
			other.RelayServiceId = "relay-b"
			*p.ConnectedRelays = append(*p.ConnectedRelays, other)
		},
	} {
		t.Run(name, func(t *testing.T) {
			var table ServiceRoutingTable
			if err := table.ApplySnapshot(ingressv1.ServiceSnapshot{Revision: 1, Entries: []ingressv1.ServiceProjection{initial}}); err != nil {
				t.Fatal(err)
			}
			older := clonePrivateProjection(initial)
			older.Revision, older.ExpiresAt = 2, now.Add(-time.Second)
			change(&older)
			renewed := clonePrivateProjection(initial)
			renewed.Revision = 3
			if err := table.ApplyEvents(1, ingressv1.ServiceSnapshot{Revision: 3, Entries: []ingressv1.ServiceProjection{older, renewed}}); !errors.Is(err, ErrPrivateRoutingStale) {
				t.Fatalf("malformed history accepted: %v", err)
			}
			if revision, _ := table.Revision(); revision != 1 {
				t.Fatal("malformed page advanced cursor")
			}
			if got, ok := table.Lookup(initial.ServiceId, *initial.ServiceRunId, *initial.RunNumber, now); !ok || got.Revision != 1 {
				t.Fatal("malformed page changed routing")
			}
		})
	}
}

func TestPrivateRoutingPageKeepsUnexpiredRelaySibling(t *testing.T) {
	readAt := time.Date(2026, time.October, 29, 0, 0, 0, 0, time.UTC)
	initial := serviceRoutingEntry(t, readAt)
	sibling := serviceRoutingEntry(t, readAt)
	other := (*sibling.ConnectedRelays)[0]
	other.ConnectionSlot, other.RelayServiceId, other.RelayId = 1, "relay-b", "process-b"
	*initial.ConnectedRelays = append(*initial.ConnectedRelays, other)
	var table ServiceRoutingTable
	if err := table.ApplySnapshot(ingressv1.ServiceSnapshot{Revision: 1, Entries: []ingressv1.ServiceProjection{initial}}); err != nil {
		t.Fatal(err)
	}
	update := clonePrivateProjection(initial)
	update.Revision = 2
	(*update.ConnectedRelays)[0].LeaseExpiresAt = readAt.Add(time.Millisecond)
	receivedAt := readAt.Add(2 * time.Millisecond)
	if err := table.ApplyEvents(1, ingressv1.ServiceSnapshot{Revision: 2, Entries: []ingressv1.ServiceProjection{update}}); err != nil {
		t.Fatal(err)
	}
	got, ok := table.Lookup(initial.ServiceId, *initial.ServiceRunId, *initial.RunNumber, receivedAt)
	if !ok || len(*got.ConnectedRelays) != 1 || (*got.ConnectedRelays)[0].RelayId != other.RelayId {
		t.Fatal("one expired relay removed the live sibling")
	}
	if _, ok := table.Lookup(initial.ServiceId, *initial.ServiceRunId, *initial.RunNumber, other.LeaseExpiresAt); ok {
		t.Fatal("expired sibling stayed routable")
	}
}

func TestPrivateRoutingSnapshotCrossesExpiry(t *testing.T) {
	for _, boundary := range []string{"relay sibling", "independent run relay", "independent run expiry"} {
		t.Run(boundary, func(t *testing.T) {
			readAt := time.Date(2026, time.October, 29, 0, 0, 0, 0, time.UTC)
			first := serviceRoutingEntry(t, readAt)
			healthy := serviceRoutingEntry(t, readAt)
			healthy.Revision = 2
			expires := readAt.Add(time.Millisecond)
			snapshot := ingressv1.ServiceSnapshot{Revision: 2, Entries: []ingressv1.ServiceProjection{first, healthy}}
			switch boundary {
			case "relay sibling":
				other := (*healthy.ConnectedRelays)[0]
				other.ConnectionSlot, other.RelayServiceId, other.RelayId = 1, "relay-b", "process-b"
				*first.ConnectedRelays = append(*first.ConnectedRelays, other)
				(*first.ConnectedRelays)[0].LeaseExpiresAt = expires
				snapshot.Entries = []ingressv1.ServiceProjection{first}
				healthy = first
			case "independent run relay":
				(*first.ConnectedRelays)[0].LeaseExpiresAt = expires
			case "independent run expiry":
				snapshot.Entries[0].ExpiresAt = expires
			}
			// control's exact snapshot is valid when read. the first run or
			// relay expires before receipt, while the sibling remains live.
			for _, entry := range snapshot.Entries {
				if err := validateDirectProjection(entry, readAt); err != nil {
					t.Fatalf("invalid snapshot at control read: %v", err)
				}
			}
			receivedAt := expires.Add(time.Millisecond)
			var table ServiceRoutingTable
			if err := table.ApplySnapshot(snapshot); err != nil {
				t.Fatalf("expiry in transit rejected healthy snapshot state: %v", err)
			}
			got, ok := table.Lookup(healthy.ServiceId, *healthy.ServiceRunId, *healthy.RunNumber, receivedAt)
			if !ok || len(*got.ConnectedRelays) != 1 {
				t.Fatal("healthy sibling unavailable after snapshot")
			}
			if boundary == "relay sibling" {
				if (*got.ConnectedRelays)[0].RelayId != "process-b" {
					t.Fatal("expired relay remained selectable")
				}
			} else if _, ok := table.Lookup(first.ServiceId, *first.ServiceRunId, *first.RunNumber, receivedAt); ok {
				t.Fatal("expired snapshot entry became routable")
			}
			if revision, ready := table.Revision(); !ready || revision != snapshot.Revision {
				t.Fatal("snapshot was not fully installed")
			}
			if _, ok := table.Lookup(healthy.ServiceId, *healthy.ServiceRunId, *healthy.RunNumber, readAt.Add(time.Minute)); ok {
				t.Fatal("snapshot's last relay stayed routable at expiry")
			}
		})
	}
}
