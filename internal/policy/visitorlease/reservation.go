package visitorlease

import (
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type reservationSlot struct {
	allocation string
	slot       uint32
}

// ObservedAllocations reports only installed, current allocations for this run.
// publishers send this on background updates before ingress can use new slots.
func (l *Lease) ObservedAllocations(run string) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	ids := []string{}
	if !l.current || !l.now().Before(l.update.View.ValidUntil) {
		return ids
	}
	for id, allocation := range l.update.Allocations {
		if allocation.RunId == run && !allocation.Retired && allocation.ValidUntil.After(l.update.View.AuthorityTime(l.now())) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

// ReservationGuard holds one delegated slot at the publisher. its sequence
// watermark survives release, so the same reservation cannot be spent again on
// the other relay connection. the run owner separately enforces its total limit.
type ReservationGuard struct {
	lease  *Lease
	header tunnelv1.StreamReservation
	source netip.Addr
	stop   func()
	once   sync.Once
	timer  *time.Timer
}

func validAllocation(a controlv1.StreamCapacityAllocation, scope visitorscope.Scope) bool {
	probe := tunnelv1.StreamReservation{ID: "sres_aaaaaaaaaaaaaaaaaaaaaa", AllocationID: a.Id, Sequence: 1, ResourceKind: string(a.Resource.Kind), ResourceID: a.Resource.Id, RunID: a.RunId,
		RunNumber: uint64(a.RunNumber), VisitorConnectionID: "vc_aaaaaaaaaaaaaaaaaaaaaa", IngressID: a.IngressId, IngressRunID: a.IngressRunId, IngressLeaseRevision: uint64(a.IngressLeaseRevision)}
	duration := a.ValidUntil.Sub(a.ObservedAt)
	return probe.Validate() == nil && a.Resource.Id == scope.ID && string(a.Resource.Kind) == string(scope.Kind) && a.Capacity > 0 && a.Capacity <= 1<<20 && a.RunNumber > 0 && a.IngressLeaseRevision > 0 && !a.ObservedAt.IsZero() && duration > 0 && duration <= 10*time.Second
}

func (l *Lease) BindReservation(header tunnelv1.StreamReservation, stop func()) (*ReservationGuard, error) {
	return l.bindReservation(header, netip.Addr{}, stop)
}

// BindReservationFrom also fences the transport when its trusted source no
// longer passes current IP policy. it does not authorize application requests.
func (l *Lease) BindReservationFrom(header tunnelv1.StreamReservation, source netip.Addr, stop func()) (*ReservationGuard, error) {
	if !source.IsValid() || source.Zone() != "" {
		return nil, ErrUpdate
	}
	return l.bindReservation(header, source.Unmap(), stop)
}

func (l *Lease) bindReservation(header tunnelv1.StreamReservation, source netip.Addr, stop func()) (*ReservationGuard, error) {
	if stop == nil {
		return nil, ErrUpdate
	}
	l.mu.Lock()
	now := l.now()
	key := reservationSlot{header.AllocationID, header.Slot}
	if l.validateReservationLocked(header, now) != nil || source.IsValid() && l.update.IP != nil && !l.update.IP.Allows(source) || l.reservations[key] != nil || l.visitors[header.VisitorConnectionID] != nil || header.Sequence <= l.sequences[key] {
		l.mu.Unlock()
		return nil, ErrUpdate
	}
	guard := &ReservationGuard{lease: l, header: header, source: source, stop: stop}
	l.sequences[key], l.reservations[key], l.visitors[header.VisitorConnectionID] = header.Sequence, guard, guard
	guard.resetLocked(now)
	l.mu.Unlock()
	return guard, nil
}

func (g *ReservationGuard) resetLocked(now time.Time) {
	l := g.lease
	until := earlier(l.update.View.ValidUntil, l.update.View.LocalDeadline(l.update.Allocations[g.header.AllocationID].ValidUntil))
	delay := max(0, until.Sub(now))
	if g.timer == nil {
		g.timer = time.AfterFunc(delay, l.expire)
	} else {
		g.timer.Reset(delay)
	}
}

// BindSource follows decoding the ingress-owned PROXY v2 header. the earlier
// reservation claim already fenced replay before any visitor TLS work began.
func (g *ReservationGuard) BindSource(source netip.Addr) error {
	l := g.lease
	l.mu.Lock()
	defer l.mu.Unlock()
	if !source.IsValid() || source.Zone() != "" || l.reservations[reservationSlot{g.header.AllocationID, g.header.Slot}] != g ||
		l.validateReservationLocked(g.header, l.now()) != nil || g.source.IsValid() && g.source != source.Unmap() || l.update.IP != nil && !l.update.IP.Allows(source.Unmap()) {
		return ErrUpdate
	}
	g.source = source.Unmap()
	return nil
}

func (l *Lease) checkReservationsLocked(now time.Time) []*ReservationGuard {
	var stopped []*ReservationGuard
	for key, guard := range l.reservations {
		if l.validateReservationLocked(guard.header, now) != nil || guard.source.IsValid() && l.update.IP != nil && !l.update.IP.Allows(guard.source) {
			delete(l.reservations, key)
			delete(l.visitors, guard.header.VisitorConnectionID)
			stopped = append(stopped, guard)
		} else {
			guard.resetLocked(now)
		}
	}
	// only a current authenticated observation can retire replay watermarks.
	// a local outage cannot forget slots while ingress still renews them.
	if l.current {
		for key := range l.sequences {
			if _, exists := l.update.Allocations[key.allocation]; !exists {
				delete(l.sequences, key)
			}
		}
	}
	return stopped
}

func (g *ReservationGuard) Close() {
	l := g.lease
	l.mu.Lock()
	key := reservationSlot{g.header.AllocationID, g.header.Slot}
	if l.reservations[key] == g {
		delete(l.reservations, key)
		delete(l.visitors, g.header.VisitorConnectionID)
	}
	if g.timer != nil {
		g.timer.Stop()
	}
	l.mu.Unlock()
	g.once.Do(func() {})
}

func stopReservations(guards []*ReservationGuard) {
	for _, guard := range guards {
		if guard.timer != nil {
			guard.timer.Stop()
		}
		guard.once.Do(guard.stop)
	}
}
