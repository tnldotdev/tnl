package ingress

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func reservationAllocation(now time.Time) streamAllocation {
	return streamAllocation{ID: "salloc_" + strings.Repeat("A", 22), ResourceKind: "service", ResourceID: "svc_" + strings.Repeat("B", 22), RunID: "srun_" + strings.Repeat("C", 22), RunNumber: 1,
		IngressID: "ingress", IngressRunID: "process", IngressLeaseRevision: 2, Capacity: 4, ObservedAt: now, ValidUntil: now.Add(10 * time.Second)}
}

func TestStreamReservationsShareCapacityAndReleaseExactlyOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pool := newStreamReservations(nil)
		defer pool.Close()
		allocation := reservationAllocation(time.Now())
		if err := pool.apply(allocation, time.Now()); err != nil {
			t.Fatal(err)
		}
		var workers sync.WaitGroup
		var mu sync.Mutex
		var held []*streamReservation
		for index := range 20 {
			workers.Go(func() {
				id := "vc_" + strings.Repeat(string(rune('A'+index)), 22)
				reservation, err := pool.reserve(allocation.ID, id, func() {})
				if err == nil {
					mu.Lock()
					held = append(held, reservation)
					mu.Unlock()
				} else if !errors.Is(err, ErrStreamReservation) {
					t.Error(err)
				}
			})
		}
		workers.Wait()
		if len(held) != 4 {
			t.Fatalf("reserved %d connections from four delegated slots", len(held))
		}
		old := held[0]
		old.Close()
		replacement, err := pool.reserve(allocation.ID, old.header.VisitorConnectionID, func() {})
		if err != nil {
			t.Fatal(err)
		}
		if replacement.header.Slot != old.header.Slot || replacement.header.Sequence <= old.header.Sequence || replacement.header.ID == old.header.ID {
			t.Fatal("reused slot did not receive a new reservation and sequence")
		}
		defer replacement.Close()
		old.Close()
		if _, err := pool.reserve(allocation.ID, "vc_"+strings.Repeat("Z", 22), func() {}); !errors.Is(err, ErrStreamReservation) {
			t.Fatal("stale release freed replacement capacity", err)
		}
		for _, reservation := range held[1:] {
			reservation.Close()
			reservation.Close()
		}
	})
}

func TestStreamReservationExpiryCancelsAndRejectsOldAllocation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pool := newStreamReservations(nil)
		defer pool.Close()
		allocation := reservationAllocation(time.Now())
		if err := pool.apply(allocation, time.Now()); err != nil {
			t.Fatal(err)
		}
		var stopped atomic.Int64
		reservation, err := pool.reserve(allocation.ID, "vc_"+strings.Repeat("D", 22), func() { stopped.Add(1) })
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Second)
		synctest.Wait()
		if stopped.Load() != 1 {
			t.Fatal("expired allocation retained active traffic")
		}
		reservation.Close()
		allocation.ObservedAt, allocation.ValidUntil = time.Now(), time.Now().Add(10*time.Second)
		if err := pool.apply(allocation, time.Now()); !errors.Is(err, ErrStreamReservation) {
			t.Fatal("expired allocation identity restored authority", err)
		}
		time.Sleep(10 * time.Second)
		synctest.Wait()
		pool.mu.Lock()
		retained := len(pool.allocations)
		pool.mu.Unlock()
		if retained != 0 {
			t.Fatal("retired allocation retained its replay tombstone indefinitely")
		}
	})
}
