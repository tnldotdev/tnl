package visitorlease

import (
	"sort"

	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// BoundedAllocations observes only material already installed by Apply. each
// deadline belongs to that immutable allocation and policy, not a later renewal.
func (l *Lease) BoundedAllocations(run string) []controlv1.StreamCapacityObservation {
	l.mu.Lock()
	defer l.mu.Unlock()
	observed := []controlv1.StreamCapacityObservation{}
	for id, allocation := range l.update.Allocations {
		view, installed, ok := l.observeAllocationLocked(id, run, allocation.RunNumber)
		if ok {
			until := view.AuthorityTime(view.ValidUntil)
			if installed.ValidUntil.Before(until) {
				until = installed.ValidUntil
			}
			observed = append(observed, controlv1.StreamCapacityObservation{AllocationId: id, RunId: run, RunNumber: installed.RunNumber, ValidUntil: until})
		}
	}
	sort.Slice(observed, func(i, j int) bool { return observed[i].AllocationId < observed[j].AllocationId })
	return observed
}

// ObserveAllocation returns one consistent installed policy/allocation snapshot.
// the copy contains identity and deadlines, never the reservation key.
func (l *Lease) ObserveAllocation(id, run string, number int64) (visitortoken.View, controlv1.StreamCapacityAllocation, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.observeAllocationLocked(id, run, number)
}

func (l *Lease) observeAllocationLocked(id, run string, number int64) (visitortoken.View, controlv1.StreamCapacityAllocation, bool) {
	view := l.update.View
	now := l.now()
	allocation, found := l.update.Allocations[id]
	if l.closed || !l.current || !l.update.Enabled || !now.Before(view.ValidUntil) || !found || allocation.Retired ||
		allocation.RunId != run || allocation.RunNumber != number || !allocation.ValidUntil.After(view.AuthorityTime(now)) {
		return visitortoken.View{}, controlv1.StreamCapacityAllocation{}, false
	}
	allocation.ReservationKey = nil
	return view, allocation, true
}
