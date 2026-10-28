package visitorlease

import (
	"bytes"
	"errors"
	"maps"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/ippolicy"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func allocationFixture(t *testing.T) (*Lease, Update, tunnelv1.StreamReservation) {
	t.Helper()
	l, update, _ := fixture(t)
	a := controlv1.StreamCapacityAllocation{Id: "salloc_" + strings.Repeat("A", 22), Resource: controlv1.VisitorResourceScope{Kind: "public_url", Id: update.View.Scope.ID},
		RunId: "pr_" + strings.Repeat("B", 22), RunNumber: 1, IngressId: "ingress", IngressRunId: "process", IngressLeaseRevision: 2,
		Capacity: 2, ObservedAt: time.Now(), ValidUntil: time.Now().Add(10 * time.Second), ReservationKey: bytes.Repeat([]byte{1}, 32)}
	update.Allocations = map[string]controlv1.StreamCapacityAllocation{a.Id: a}
	h := tunnelv1.StreamReservation{ID: "sres_" + strings.Repeat("C", 22), AllocationID: a.Id, Sequence: 1, ResourceKind: "public_url", ResourceID: update.View.Scope.ID,
		RunID: a.RunId, RunNumber: 1, VisitorConnectionID: "vc_" + strings.Repeat("D", 22), IngressID: a.IngressId, IngressRunID: a.IngressRunId, IngressLeaseRevision: 2}
	signReservationFixture(t, a.ReservationKey, &h, "192.0.2.1")
	if err := h.Validate(); err != nil {
		t.Fatal(err)
	}
	return l, update, h
}

func signReservationFixture(t *testing.T, key []byte, reservation *tunnelv1.StreamReservation, source string) {
	t.Helper()
	if err := visitortoken.SignReservation(key, reservation, netip.MustParseAddr(source)); err != nil {
		t.Fatal(err)
	}
}

func TestReservationSourceFencesOnlyAffectedTransports(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lease, update, first := allocationFixture(t)
		if err := lease.Apply(lease.Begin(), update); err != nil {
			t.Fatal(err)
		}
		var stopped [2]atomic.Int64
		for index, source := range []string{"192.0.2.1", "198.51.100.1"} {
			header := first
			header.Slot = uint32(index)
			header.VisitorConnectionID = "vc_" + strings.Repeat(string(rune('D'+index)), 22)
			signReservationFixture(t, update.Allocations[header.AllocationID].ReservationKey, &header, source)
			guard, err := lease.BindReservation(header, func() { stopped[index].Add(1) })
			if err != nil {
				t.Fatal(err)
			}
			defer guard.Close()
			if err := guard.BindSource(netip.MustParseAddr(source)); err != nil {
				t.Fatal(err)
			}
			if err := guard.BindSource(netip.MustParseAddr("203.0.113.1")); err == nil {
				t.Fatal("reservation changed its trusted source")
			}
		}
		var key [32]byte
		key[0] = 1
		entry, err := ippolicy.Hash(key, netip.MustParsePrefix("198.51.100.0/24"))
		if err != nil {
			t.Fatal(err)
		}
		ip, err := ippolicy.New(key, []ippolicy.Entry{entry})
		if err != nil {
			t.Fatal(err)
		}
		update.IP = &ip
		if err := lease.Apply(lease.Begin(), update); err != nil {
			t.Fatal(err)
		}
		if stopped[0].Load() != 1 || stopped[1].Load() != 0 {
			t.Fatal("IP policy update affected an unrelated transport")
		}
	})
}

func TestReservationRejectsRelayRewritesBeforeVisitorBytes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lease, update, signed := allocationFixture(t)
		if err := lease.Apply(lease.Begin(), update); err != nil {
			t.Fatal(err)
		}
		for name, change := range map[string]func(*tunnelv1.StreamReservation){
			"source":   func(r *tunnelv1.StreamReservation) { r.SourceIP = "198.51.100.1" },
			"slot":     func(r *tunnelv1.StreamReservation) { r.Slot = 1 },
			"run":      func(r *tunnelv1.StreamReservation) { r.RunID = "pr_" + strings.Repeat("Z", 22) },
			"sequence": func(r *tunnelv1.StreamReservation) { r.Sequence++ },
		} {
			forged := signed
			change(&forged)
			if err := lease.ValidateReservation(forged); !errors.Is(err, ErrUpdate) {
				t.Fatal("relay rewrite reached the publisher", name, err)
			}
		}
		guard, err := lease.BindReservationFrom(signed, netip.MustParseAddr("192.0.2.1"), func() {})
		if err != nil {
			t.Fatal("exact ingress proof was rejected", err)
		}
		guard.Close()
	})
}

func TestReservationSlotsPreventReplayAcrossRelayConnections(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l, update, h := allocationFixture(t)
		if err := l.Apply(l.Begin(), update); err != nil {
			t.Fatal(err)
		}
		first, err := l.BindReservation(h, func() {})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := l.BindReservation(h, func() {}); !errors.Is(err, ErrUpdate) {
			t.Fatal("same slot admitted through both relay connections", err)
		}
		first.Close()
		if _, err := l.BindReservation(h, func() {}); !errors.Is(err, ErrUpdate) {
			t.Fatal("released reservation was spent again", err)
		}
		h.Sequence++
		signReservationFixture(t, update.Allocations[h.AllocationID].ReservationKey, &h, h.SourceIP)
		replacement, err := l.BindReservation(h, func() {})
		if err != nil {
			t.Fatal(err)
		}
		defer replacement.Close()
		first.Close()
		h.Sequence++
		signReservationFixture(t, update.Allocations[h.AllocationID].ReservationKey, &h, h.SourceIP)
		if _, err := l.BindReservation(h, func() {}); !errors.Is(err, ErrUpdate) {
			t.Fatal("stale release freed the replacement slot", err)
		}
		h.Slot = 2
		if err := l.ValidateReservation(h); !errors.Is(err, ErrUpdate) {
			t.Fatal("slot outside delegated capacity was admitted", err)
		}
	})
}

func TestReservationObservedAllocationsMatchInstalledRunAndDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lease, update, header := allocationFixture(t)
		if ids := lease.ObservedAllocations(header.RunID); len(ids) != 0 {
			t.Fatal("publisher acknowledged an uninstalled allocation", ids)
		}
		first := update.Allocations[header.AllocationID]
		first.ValidUntil = first.ObservedAt.Add(4 * time.Second)
		update.Allocations[first.Id] = first
		second := first
		second.Id = "salloc_" + strings.Repeat("Z", 22)
		second.ValidUntil = second.ObservedAt.Add(10 * time.Second)
		update.Allocations[second.Id] = second
		other := second
		other.Id = "salloc_" + strings.Repeat("Y", 22)
		other.RunId = "pr_" + strings.Repeat("E", 22)
		update.Allocations[other.Id] = other
		retired := second
		retired.Id = "salloc_" + strings.Repeat("X", 22)
		retired.Retired = true
		update.Allocations[retired.Id] = retired
		if err := lease.Apply(lease.Begin(), update); err != nil {
			t.Fatal(err)
		}
		ids := lease.ObservedAllocations(header.RunID)
		if len(ids) != 2 || ids[0] != first.Id || ids[1] != second.Id {
			t.Fatal("observed allocations were unordered, retired or from another run", ids)
		}
		time.Sleep(4 * time.Second)
		ids = lease.ObservedAllocations(header.RunID)
		if len(ids) != 1 || ids[0] != second.Id {
			t.Fatal("publisher acknowledged expired allocation authority", ids)
		}
		time.Sleep(6 * time.Second)
		if ids := lease.ObservedAllocations(header.RunID); len(ids) != 0 {
			t.Fatal("publisher acknowledged allocations after local policy expiry", ids)
		}
	})
}

func TestReservationExpiryStopsTrafficDespiteCurrentPolicyAndToken(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l, update, h := allocationFixture(t)
		a := update.Allocations[h.AllocationID]
		a.ValidUntil = a.ObservedAt.Add(4 * time.Second)
		update.Allocations[h.AllocationID] = a
		if err := l.Apply(l.Begin(), update); err != nil {
			t.Fatal(err)
		}
		var stopped atomic.Int64
		guard, err := l.BindReservation(h, func() { stopped.Add(1) })
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(4 * time.Second)
		synctest.Wait()
		if _, current, _ := l.Current(); !current || stopped.Load() != 1 {
			t.Fatal("allocation deadline did not independently stop traffic")
		}
		guard.Close()
		l.Close()
		if stopped.Load() != 1 {
			t.Fatal("expiry and cleanup stopped the reservation twice")
		}
	})
}

func TestReservationRenewalAndOutageKeepReplayWatermarks(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l, update, h := allocationFixture(t)
		if err := l.Apply(l.Begin(), update); err != nil {
			t.Fatal(err)
		}
		guard, err := l.BindReservation(h, func() {})
		if err != nil {
			t.Fatal(err)
		}
		guard.Close()
		// changing the decoded caller's map cannot change applied authority.
		update.Allocations = maps.Clone(update.Allocations)
		time.Sleep(11 * time.Second)
		synctest.Wait()
		update.View.ObservedAt, update.View.ValidUntil = time.Now(), time.Now().Add(10*time.Second)
		a := update.Allocations[h.AllocationID]
		a.ObservedAt, a.ValidUntil = time.Now(), time.Now().Add(10*time.Second)
		update.Allocations[h.AllocationID] = a
		if err := l.Apply(l.Begin(), update); err != nil {
			t.Fatal(err)
		}
		if _, err := l.BindReservation(h, func() {}); !errors.Is(err, ErrUpdate) {
			t.Fatal("local policy outage forgot a spent slot still renewed by ingress", err)
		}
		h.IngressRunID = "restarted-process"
		h.Sequence++
		if err := l.ValidateReservation(h); !errors.Is(err, ErrUpdate) {
			t.Fatal("restarted process reused an old allocation", err)
		}
	})
}

func TestReservationSnapshotOwnsAllocationValues(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l, update, h := allocationFixture(t)
		if err := l.Apply(l.Begin(), update); err != nil {
			t.Fatal(err)
		}
		delete(update.Allocations, h.AllocationID)
		if err := l.ValidateReservation(h); err != nil {
			t.Fatal("caller changed applied allocation authority", err)
		}
	})
}

func TestReservationOlderControlObservationCannotForgetSpentSlots(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l, update, h := allocationFixture(t)
		initial := l.Begin()
		time.Sleep(time.Second)
		later := l.Begin()
		// a later-started request can reach a different replica first. its
		// older control observation must not replace a newer allocation view.
		old := update
		old.Allocations = nil
		update.View.ObservedAt, update.View.ValidUntil = time.Now(), time.Now().Add(10*time.Second)
		if err := l.Apply(initial, update); err != nil {
			t.Fatal(err)
		}
		guard, err := l.BindReservation(h, func() {})
		if err != nil {
			t.Fatal(err)
		}
		guard.Close()
		if err := l.Apply(later, old); !errors.Is(err, ErrUpdate) {
			t.Fatal("older control observation discarded reservation replay history", err)
		}
		if _, err := l.BindReservation(h, func() {}); !errors.Is(err, ErrUpdate) {
			t.Fatal("out-of-order observation made a spent slot reusable", err)
		}
	})
}
