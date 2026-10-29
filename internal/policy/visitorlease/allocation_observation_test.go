package visitorlease

import (
	"testing"
	"testing/synctest"
	"time"
)

func TestBoundedAllocationObservationUsesInstalledPolicyAndAllocation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lease, update, header := allocationFixture(t)
		defer lease.Close()
		if len(lease.BoundedAllocations(header.RunID)) != 0 {
			t.Fatal("uninstalled response supplied evidence")
		}
		if err := lease.Apply(lease.Begin(), update); err != nil {
			t.Fatal(err)
		}
		view, allocation, ok := lease.ObserveAllocation(header.AllocationID, header.RunID, int64(header.RunNumber))
		if !ok || len(allocation.ReservationKey) != 0 {
			t.Fatal("read-only observation omitted installed state or exposed a key")
		}
		observations := lease.BoundedAllocations(header.RunID)
		if len(observations) != 1 || observations[0].ValidUntil.After(view.AuthorityTime(view.ValidUntil)) || observations[0].ValidUntil.After(allocation.ValidUntil) {
			t.Fatal("observation exceeded installed material")
		}
		time.Sleep(10 * time.Second)
		if len(lease.BoundedAllocations(header.RunID)) != 0 {
			t.Fatal("expired installed material remained observable")
		}
	})
}
