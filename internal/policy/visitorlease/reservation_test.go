package visitorlease

import (
	"errors"
	"maps"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func allocationFixture(t *testing.T) (*Lease, Update, tunnelv1.StreamReservation) {
	t.Helper()
	l, update, _ := fixture(t)
	a := controlv1.StreamCapacityAllocation{Id: "salloc_" + strings.Repeat("A", 22), Resource: controlv1.VisitorResourceScope{Kind: "public_url", Id: update.View.Scope.ID},
		RunId: "pr_" + strings.Repeat("B", 22), RunNumber: 1, IngressId: "ingress", IngressRunId: "process", IngressLeaseRevision: 2,
		Capacity: 2, ObservedAt: time.Now(), ValidUntil: time.Now().Add(10 * time.Second)}
	update.Allocations = map[string]controlv1.StreamCapacityAllocation{a.Id: a}
	h := tunnelv1.StreamReservation{ID: "sres_" + strings.Repeat("C", 22), AllocationID: a.Id, Sequence: 1, ResourceKind: "public_url", ResourceID: update.View.Scope.ID,
		RunID: a.RunId, RunNumber: 1, VisitorConnectionID: "vc_" + strings.Repeat("D", 22), IngressID: a.IngressId, IngressRunID: a.IngressRunId, IngressLeaseRevision: 2}
	if err := h.Validate(); err != nil {
		t.Fatal(err)
	}
	return l, update, h
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
		replacement, err := l.BindReservation(h, func() {})
		if err != nil {
			t.Fatal(err)
		}
		defer replacement.Close()
		first.Close()
		h.Sequence++
		if _, err := l.BindReservation(h, func() {}); !errors.Is(err, ErrUpdate) {
			t.Fatal("stale release freed the replacement slot", err)
		}
		h.Slot = 2
		if err := l.ValidateReservation(h); !errors.Is(err, ErrUpdate) {
			t.Fatal("slot outside delegated capacity was admitted", err)
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
