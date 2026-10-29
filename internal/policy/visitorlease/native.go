package visitorlease

import (
	"net/netip"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

// NativeGuard owns stream permission, not a borrowed HTTP request guard. only
// BindNative constructs it from verified native subject evidence. the service
// admission must separately retain and check its concrete physical owner and C.
type NativeGuard struct{ guard *Guard }

type nativePermission struct {
	metadata    int64
	reservation *ReservationGuard
}

// BindNative binds a native stream to current policy and, on ingress, its exact
// source-bound reservation. committing and retaining that association share the
// canonical lease lock; reservation loss cannot race a later callback into use.
// peers pass nil: packet delivery is not an ingress capacity reservation.
func (l *Lease) BindNative(permission visitortoken.VerifiedPermission, source netip.Addr, metadata int64, reservation *ReservationGuard, stop func()) (*NativeGuard, error) {
	if l == nil || l.scope.Kind != visitorscope.Service || stop == nil || metadata < 1 || !source.IsValid() || source.Zone() != "" {
		return nil, ErrUpdate
	}
	if _, err := visitortoken.NativeSubject(permission.Facts().Subject); err != nil {
		return nil, err
	}
	l.mu.Lock()
	now := l.now()
	g := &Guard{lease: l, permission: permission, source: source.Unmap(), stop: stop,
		confirmedUntil: l.update.View.ValidUntil,
		native:         &nativePermission{metadata: metadata, reservation: reservation}}
	if reservation != nil && (reservation.lease != l || reservation.source != g.source) || !g.allowedLocked(now) {
		l.mu.Unlock()
		return nil, visitortoken.ErrPolicy
	}
	if reservation != nil {
		reservation.committed = true
	}
	l.guards[g] = struct{}{}
	g.resetLocked()
	l.mu.Unlock()
	return &NativeGuard{guard: g}, nil
}

// Current is a callback-free local operation entry. membership, metadata,
// permission, source and the retained reservation are checked under their one
// canonical mutex, including absolute expiry when timer delivery is delayed.
// it never admits a new stream, renews authority, or constructs an owner proof.
func (n *NativeGuard) Current() (time.Time, error) {
	if n == nil || n.guard == nil {
		return time.Time{}, ErrUpdate
	}
	g := n.guard
	l := g.lease
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if _, active := l.guards[g]; !active || !g.allowedLocked(now) {
		return time.Time{}, visitortoken.ErrPolicy
	}
	view := l.update.View
	until := earlier(view.ValidUntil, view.LocalDeadline(g.permission.Facts().ExpiresAt))
	if g.renewable && g.permission.Facts().VisitorPolicyRevision != view.VisitorPolicyRevision {
		until = earlier(until, g.confirmedUntil)
	}
	if workload, ok := g.permission.Facts().Subject.(visitortoken.Workload); ok {
		parent, _ := view.Workload(workload.SessionID)
		until = earlier(until, view.LocalDeadline(parent.ExpiresAt))
	}
	if r := g.native.reservation; r != nil {
		until = earlier(until, view.LocalDeadline(l.update.Allocations[r.header.AllocationID].ValidUntil))
	}
	return until, nil
}

func (n *NativeGuard) Renew(permission visitortoken.VerifiedPermission) error {
	if n == nil || n.guard == nil {
		return ErrUpdate
	}
	return n.guard.Renew(permission)
}

func (n *NativeGuard) AllowRenewal() error {
	if n == nil || n.guard == nil {
		return ErrUpdate
	}
	return n.guard.AllowRenewal()
}

func (n *NativeGuard) Close() {
	if n != nil && n.guard != nil {
		n.guard.Close()
	}
}

func (n *NativeGuard) Revoke() {
	if n != nil && n.guard != nil {
		n.guard.Revoke()
	}
}

func (g *ReservationGuard) currentLocked(now time.Time) bool {
	l := g.lease
	return g.source.IsValid() && l.reservations[reservationSlot{g.header.AllocationID, g.header.Slot}] == g &&
		l.validateReservationLocked(g.header, now) == nil && (l.update.IP == nil || l.update.IP.Allows(g.source))
}
