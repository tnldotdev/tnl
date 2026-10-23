// package visitorlease owns one scope's local visitor-policy deadline and the
// admissions using it. ingress and publisher own fetching, retries, and process
// lifetime; this package performs no network work or control permission rules.
package visitorlease

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"maps"
	"net/netip"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/ippolicy"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

var ErrUpdate = errors.New("visitor policy update is stale or incomplete")

// Update is a decoded, authenticated control observation. View timestamps use
// control's clock until Apply converts them to a conservative local deadline.
type Update struct {
	View               visitortoken.View
	KeyRevision        int64
	Enabled, Anonymous bool
	IP                 *ippolicy.Policy
	AfterRevision      int64
	Events             []int64
	Snapshot           bool
	Allocations        map[string]controlv1.StreamCapacityAllocation
}

type Request struct {
	AfterRevision   int64
	Snapshot        bool
	StartedAt       time.Time
	sequence, epoch uint64
}

type Lease struct {
	mu                       sync.Mutex
	scope                    visitorscope.Scope
	now                      func() time.Time
	update                   Update
	sequence, applied, epoch uint64
	revision, keyRevision    int64
	current, closed          bool
	timer                    *time.Timer
	guards                   map[*Guard]struct{}
	reservations             map[reservationSlot]*ReservationGuard
	sequences                map[reservationSlot]uint64
	visitors                 map[string]*ReservationGuard
}

func New(scope visitorscope.Scope, now func() time.Time) (*Lease, error) {
	if !scope.Valid() {
		return nil, ErrUpdate
	}
	if now == nil {
		now = time.Now
	}
	return &Lease{scope: scope, now: now, guards: make(map[*Guard]struct{}), reservations: make(map[reservationSlot]*ReservationGuard), sequences: make(map[reservationSlot]uint64), visitors: make(map[string]*ReservationGuard)}, nil
}

func (l *Lease) Begin() Request {
	l.mu.Lock()
	stopped := l.expireLocked(l.now())
	l.sequence++
	r := Request{AfterRevision: l.revision, Snapshot: !l.current, StartedAt: l.now(), sequence: l.sequence, epoch: l.epoch}
	l.mu.Unlock()
	stopGuards(stopped)
	return r
}

func (l *Lease) Apply(request Request, update Update) error {
	l.mu.Lock()
	now := l.now()
	stopped := l.expireLocked(now)
	err := l.applyLocked(request, update, now)
	if err == nil {
		for guard := range l.guards {
			if !l.allowedLocked(guard.permission, guard.source, now) {
				delete(l.guards, guard)
				stopped = append(stopped, guard)
			} else {
				guard.resetLocked()
			}
		}
	}
	reservations := l.checkReservationsLocked(now)
	l.mu.Unlock()
	stopGuards(stopped)
	stopReservations(reservations)
	return err
}

func (l *Lease) applyLocked(request Request, update Update, now time.Time) error {
	view := update.View
	duration := view.ValidUntil.Sub(view.ObservedAt)
	if l.closed || request.epoch != l.epoch || request.sequence <= l.applied || request.sequence > l.sequence || request.StartedAt.IsZero() || now.Before(request.StartedAt) ||
		(l.revision > 0 && view.ObservedAt.Before(l.update.View.ControlTime)) ||
		view.Scope != l.scope || view.VisitorPolicyRevision < l.revision || update.KeyRevision < l.keyRevision || update.KeyRevision < 1 || view.VisitorPolicyRevision < 1 ||
		duration <= 0 || duration > visitortoken.PolicyLifetime || !now.Before(request.StartedAt.Add(duration)) || len(view.Keys) > 64 {
		return ErrUpdate
	}
	if request.Snapshot && !update.Snapshot {
		return ErrUpdate
	}
	if !update.Snapshot {
		if update.AfterRevision != request.AfterRevision || update.AfterRevision != l.revision {
			return ErrUpdate
		}
		revision := update.AfterRevision
		for _, next := range update.Events {
			if next != revision+1 {
				return ErrUpdate
			}
			revision = next
		}
		if revision != view.VisitorPolicyRevision {
			return ErrUpdate
		}
	}
	keys := make(map[string]ed25519.PublicKey, len(view.Keys))
	for id, key := range view.Keys {
		if id == "" || len(key) != ed25519.PublicKeySize {
			return ErrUpdate
		}
		keys[id] = bytes.Clone(key)
	}
	workloads := make(map[string]visitortoken.WorkloadLease, len(view.Workloads))
	for id, parent := range view.Workloads {
		workloads[id] = parent
	}
	view.Keys, view.Workloads = keys, workloads
	if len(update.Allocations) > 2048 {
		return ErrUpdate
	}
	for id, a := range update.Allocations {
		if id != a.Id || !validAllocation(a, l.scope) {
			return ErrUpdate
		}
	}
	update.Allocations = maps.Clone(update.Allocations)
	view.ControlTime = view.ObservedAt
	view.ObservedAt, view.ValidUntil = request.StartedAt, request.StartedAt.Add(duration)
	update.View, update.Events = view, nil
	l.update, l.revision, l.keyRevision, l.applied, l.current = update, view.VisitorPolicyRevision, update.KeyRevision, request.sequence, true
	if l.timer == nil {
		l.timer = time.AfterFunc(view.ValidUntil.Sub(now), l.expire)
	} else {
		l.timer.Reset(view.ValidUntil.Sub(now))
	}
	return nil
}

func (l *Lease) Current() (visitortoken.View, bool, bool) {
	l.mu.Lock()
	stopped := l.expireLocked(l.now())
	view, enabled, anonymous := l.update.View, l.current && l.update.Enabled, l.current && l.update.Enabled && l.update.Anonymous
	if !l.current {
		view = visitortoken.View{}
	}
	l.mu.Unlock()
	stopGuards(stopped)
	return view, enabled, anonymous
}

func (l *Lease) ValidateReservation(reservation tunnelv1.StreamReservation) error {
	if reservation.Validate() != nil {
		return ErrUpdate
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.validateReservationLocked(reservation, l.now())
}

func (l *Lease) validateReservationLocked(reservation tunnelv1.StreamReservation, now time.Time) error {
	if reservation.Validate() != nil || !l.current || !l.update.Enabled || !now.Before(l.update.View.ValidUntil) {
		return visitortoken.ErrPolicy
	}
	a, found := l.update.Allocations[reservation.AllocationID]
	if !found || a.Retired || reservation.Slot >= uint32(a.Capacity) || !a.ValidUntil.After(l.update.View.AuthorityTime(now)) || string(a.Resource.Kind) != reservation.ResourceKind || a.Resource.Id != reservation.ResourceID ||
		a.RunId != reservation.RunID || uint64(a.RunNumber) != reservation.RunNumber || a.IngressId != reservation.IngressID || a.IngressRunId != reservation.IngressRunID || uint64(a.IngressLeaseRevision) != reservation.IngressLeaseRevision {
		return ErrUpdate
	}
	return nil
}

func (l *Lease) allowedLocked(permission visitortoken.Permission, source netip.Addr, now time.Time) bool {
	return l.current && l.update.Enabled && visitortoken.CheckCurrent(permission, l.update.View, now) == nil && (l.update.IP == nil || l.update.IP.Allows(source))
}

type Guard struct {
	lease      *Lease
	permission visitortoken.Permission
	source     netip.Addr
	stop       func()
	once       sync.Once
	timer      *time.Timer
}

// Bind follows signature and possession verification. each HTTP request binds
// separately so cancellation never closes unrelated HTTP/2 request streams.
func (l *Lease) Bind(permission visitortoken.Permission, source netip.Addr, stop func()) (*Guard, error) {
	if stop == nil {
		return nil, ErrUpdate
	}
	l.mu.Lock()
	now := l.now()
	stopped := l.expireLocked(now)
	if !l.allowedLocked(permission, source, now) {
		l.mu.Unlock()
		stopGuards(stopped)
		return nil, visitortoken.ErrPolicy
	}
	guard := &Guard{lease: l, permission: permission, source: source, stop: stop}
	l.guards[guard] = struct{}{}
	guard.resetLocked()
	l.mu.Unlock()
	stopGuards(stopped)
	return guard, nil
}

func (g *Guard) resetLocked() {
	view := g.lease.update.View
	until := view.LocalDeadline(g.permission.ExpiresAt)
	subject := g.permission.Subject
	if certificate, ok := subject.(visitortoken.Certificate); ok {
		subject = certificate.Source
	}
	if workload, ok := subject.(visitortoken.Workload); ok {
		until = earlier(until, view.LocalDeadline(view.Workloads[workload.SessionID].ExpiresAt))
	}
	delay := max(0, until.Sub(g.lease.now()))
	if g.timer == nil {
		g.timer = time.AfterFunc(delay, g.expire)
	} else {
		g.timer.Reset(delay)
	}
}

func (g *Guard) expire() {
	l := g.lease
	l.mu.Lock()
	_, found := l.guards[g]
	if found && !l.allowedLocked(g.permission, g.source, l.now()) {
		delete(l.guards, g)
	} else {
		found = false
	}
	l.mu.Unlock()
	if found {
		g.abort()
	}
}

func (g *Guard) abort() { g.once.Do(g.stop) }

func (g *Guard) Close() {
	l := g.lease
	l.mu.Lock()
	delete(l.guards, g)
	if g.timer != nil {
		g.timer.Stop()
	}
	l.mu.Unlock()
	g.once.Do(func() {})
}

func (l *Lease) expireLocked(now time.Time) []*Guard {
	if !l.current || now.Before(l.update.View.ValidUntil) {
		return nil
	}
	l.current = false
	l.epoch++
	var guards []*Guard
	for guard := range l.guards {
		guards = append(guards, guard)
		delete(l.guards, guard)
	}
	return guards
}

func (l *Lease) expire() {
	l.mu.Lock()
	stopped := l.expireLocked(l.now())
	reservations := l.checkReservationsLocked(l.now())
	l.mu.Unlock()
	stopGuards(stopped)
	stopReservations(reservations)
}

func (l *Lease) Close() {
	l.mu.Lock()
	l.closed = true
	if l.timer != nil {
		l.timer.Stop()
	}
	l.current = false
	l.epoch++
	var guards []*Guard
	for guard := range l.guards {
		guards = append(guards, guard)
		delete(l.guards, guard)
	}
	reservations := l.checkReservationsLocked(l.now())
	clear(l.sequences)
	clear(l.visitors)
	l.mu.Unlock()
	stopGuards(guards)
	stopReservations(reservations)
}

func stopGuards(guards []*Guard) {
	for _, guard := range guards {
		if guard.timer != nil {
			guard.timer.Stop()
		}
		guard.abort()
	}
}
func earlier(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
