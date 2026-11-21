// package visitorlease owns one scope's local visitor-policy deadline and the
// admissions using it. the publisher owns fetching, retries, and process
// lifetime; this package performs no network work or control permission rules.
package visitorlease

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/controloutage"
	"github.com/tnldotdev/tnl/internal/policy/ippolicy"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

var ErrUpdate = errors.New("visitor policy update is stale or incomplete")

// Update is a decoded, authenticated control observation. View timestamps use
// control's clock until Apply converts them to a conservative local deadline.
type Update struct {
	ConfirmationKey    string
	View               visitortoken.View
	KeyRevision        int64
	Enabled, Anonymous bool
	BoundConnections   bool
	IP                 *ippolicy.Policy
	PublicEndpoint     *controlv1.VisitorPublicEndpoint
	AfterRevision      int64
	Events             []int64
	Snapshot           bool
}

type Request struct {
	confirmationKey string
	AfterRevision   int64
	Snapshot        bool
	StartedAt       time.Time
	Deadline        time.Time
	sequence, epoch uint64
}

// Confirm applies a fresh control observation to the same still-current
// snapshot. a missing or different key, elapsed lease or intervening full
// update needs a full observation. watch notices never enter this path.
func (l *Lease) Confirm(request Request, evidence controlv1.PublisherPolicyConfirmation) error {
	l.mu.Lock()
	update := l.update
	current := l.phase == leaseCurrent && !request.Snapshot && update.Enabled && !update.BoundConnections &&
		controlv1.ValidPublisherPolicyBookmark(evidence.ConfirmationKey) && update.ConfirmationKey == evidence.ConfirmationKey &&
		update.View.Hostname == evidence.Hostname && update.View.VisitorPolicyRevision == request.AfterRevision
	l.mu.Unlock()
	if !current {
		return ErrUpdate
	}
	request.confirmationKey = evidence.ConfirmationKey
	update.View.ObservedAt, update.View.ValidUntil = evidence.ObservedAt, evidence.ValidUntil
	update.Snapshot, update.AfterRevision, update.Events = false, request.AfterRevision, nil
	return l.Apply(request, update)
}

type Lease struct {
	mu                       sync.Mutex
	scope                    visitorscope.Scope
	now                      func() time.Time
	update                   Update
	sequence, applied, epoch uint64
	revision, keyRevision    int64
	controlValidUntil        time.Time
	phase                    leasePhase
	timer                    *time.Timer
	guards                   map[*Guard]struct{}
	changed                  chan struct{}
}

// the last authenticated update survives expiry for revision and control-clock
// fences. only a current lease grants authority; closed is terminal.
type leasePhase uint8

const (
	leaseNeedsSnapshot leasePhase = iota
	leaseCurrent
	leaseClosed
)

func New(scope visitorscope.Scope, now func() time.Time) (*Lease, error) {
	if !scope.Valid() {
		return nil, ErrUpdate
	}
	if now == nil {
		now = time.Now
	}
	return &Lease{scope: scope, now: now, guards: make(map[*Guard]struct{}), changed: make(chan struct{})}, nil
}

func (l *Lease) Begin() Request {
	l.mu.Lock()
	stopped := l.expireLocked(l.now())
	l.sequence++
	r := Request{AfterRevision: l.revision, Snapshot: l.phase != leaseCurrent, StartedAt: l.now(), sequence: l.sequence, epoch: l.epoch}
	l.mu.Unlock()
	stopGuards(stopped)
	return r
}

func (l *Lease) Apply(request Request, update Update) error {
	l.mu.Lock()
	now := l.now()
	stopped := l.expireLocked(now)
	// an overdue timer is not authority. retire expired workload admissions
	// against their previous accepted permission before installing newer policy.
	for guard := range l.guards {
		if _, workload := guard.permission.WorkloadPermission(); workload && !guard.allowedLocked(now) {
			delete(l.guards, guard)
			stopped = append(stopped, guard)
		}
	}
	err := l.applyLocked(request, update, now)
	if err == nil {
		for guard := range l.guards {
			if workload, ok := guard.permission.WorkloadPermission(); ok {
				// only this distinctly verified identity profile follows current
				// control-confirmed workload permission. fixed tokens never do.
				permission, err := workload.Renew(l.update.View, now)
				if err == nil {
					guard.permission = permission
				} else {
					delete(l.guards, guard)
					guard.policyRefused = true
					stopped = append(stopped, guard)
					continue
				}
			}
			if !guard.allowedLocked(now) {
				delete(l.guards, guard)
				guard.policyRefused = true
				stopped = append(stopped, guard)
			} else {
				if guard.anonymous || guard.permission.Facts().VisitorPolicyRevision == l.update.View.VisitorPolicyRevision {
					guard.confirmedUntil = l.update.View.ValidUntil
				}
				guard.resetLocked()
			}
		}
	}
	l.mu.Unlock()
	stopGuards(stopped)
	return err
}

func (l *Lease) applyLocked(request Request, update Update, now time.Time) error {
	if request.confirmationKey != "" && (l.phase != leaseCurrent || l.update.ConfirmationKey != request.confirmationKey) {
		return ErrUpdate
	}
	view := update.View
	duration := view.ValidUntil.Sub(view.ObservedAt)
	deadline, deadlineErr := controloutage.LocalDeadline(request.StartedAt, view.ObservedAt, view.ValidUntil, now)
	observedAt := request.StartedAt
	if l.phase == leaseClosed || request.epoch != l.epoch || request.sequence <= l.applied || request.sequence > l.sequence || request.StartedAt.IsZero() || now.Before(request.StartedAt) ||
		(!request.Deadline.IsZero() && !now.Before(request.Deadline)) ||
		(l.revision > 0 && view.ObservedAt.Before(l.update.View.ControlTime)) ||
		view.Scope != l.scope || view.VisitorPolicyRevision < l.revision || update.KeyRevision < l.keyRevision || update.KeyRevision < 1 || view.VisitorPolicyRevision < 1 ||
		deadlineErr != nil || !view.ValidVerificationKeys() {
		return ErrUpdate
	}
	if l.revision > 0 && view.ObservedAt.Equal(l.update.View.ControlTime) {
		// repeated evidence may carry a learned denial, but cannot acquire a
		// later local deadline merely by arriving in another request.
		observedAt = l.update.View.ObservedAt
		deadline = earlier(observedAt.Add(duration), l.update.View.ValidUntil)
		if !now.Before(deadline) {
			return ErrUpdate
		}
	}
	if l.revision > 0 && !view.ValidUntil.After(l.controlValidUntil) {
		deadline = earlier(deadline, l.update.View.ValidUntil.Add(min(0, view.ValidUntil.Sub(l.controlValidUntil))))
		if !now.Before(deadline) {
			return ErrUpdate
		}
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
	if update.IP != nil {
		// detach the caller's policy value; its private maps are immutable.
		ip := *update.IP
		update.IP = &ip
	}
	if update.PublicEndpoint != nil {
		if !validPublicEndpoint(*update.PublicEndpoint) {
			return ErrUpdate
		}
		endpoint := *update.PublicEndpoint
		update.PublicEndpoint = &endpoint
	}
	view.ControlTime = view.ObservedAt
	l.controlValidUntil = view.ValidUntil
	view.ObservedAt, view.ValidUntil = observedAt, deadline
	update.View, update.Events = view, nil
	l.update, l.revision, l.keyRevision, l.applied, l.phase = update, view.VisitorPolicyRevision, update.KeyRevision, request.sequence, leaseCurrent
	l.notifyLocked()
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
	view, enabled, anonymous := l.update.View, l.phase == leaseCurrent && l.update.Enabled, l.phase == leaseCurrent && l.update.Enabled && l.update.Anonymous
	if l.phase != leaseCurrent {
		view = visitortoken.View{}
	}
	l.mu.Unlock()
	stopGuards(stopped)
	return view, enabled, anonymous
}

// WaitRevision joins background policy installation, not a control request.
// waiting never grants authority or extends the caller's setup deadline.
func (l *Lease) WaitRevision(ctx context.Context, revision int64) error {
	if ctx == nil || revision < 1 {
		return ErrUpdate
	}
	for {
		l.mu.Lock()
		stopped := l.expireLocked(l.now())
		current := l.phase == leaseCurrent && l.update.Enabled
		installed, changed := l.revision, l.changed
		l.mu.Unlock()
		stopGuards(stopped)
		if err := context.Cause(ctx); err != nil {
			return err
		}
		if !current {
			return visitortoken.ErrPolicy
		}
		if installed >= revision {
			return nil
		}
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-changed:
		}
	}
}

func (l *Lease) notifyLocked() {
	close(l.changed)
	l.changed = make(chan struct{})
}

func (l *Lease) allowedLocked(permission visitortoken.VerifiedPermission, source netip.Addr, now time.Time) bool {
	return l.phase == leaseCurrent && l.update.Enabled && visitortoken.CheckCurrent(permission, l.update.View, now) == nil && (l.update.IP == nil || l.update.IP.Allows(source))
}

type Guard struct {
	lease                              *Lease
	permission                         visitortoken.VerifiedPermission
	source                             netip.Addr
	stop                               func()
	once                               sync.Once
	timer                              *time.Timer
	anonymous                          bool
	connection                         bool
	renewable                          bool
	confirmedUntil                     time.Time
	permissionUntil, permissionExpires time.Time
	parentUntil, parentExpires         time.Time
	workloadCredentialUntil            time.Time
	policyRefused                      bool
	connector                          *connectorPermission
	publicEndpoint                     *controlv1.VisitorPublicEndpoint
}

func (g *Guard) allowedLocked(now time.Time) bool {
	l := g.lease
	if !g.permissionUntil.IsZero() && !now.Before(g.permissionUntil) ||
		!g.parentUntil.IsZero() && !now.Before(g.parentUntil) ||
		!g.workloadCredentialUntil.IsZero() && !now.Before(g.workloadCredentialUntil) {
		return false
	}
	if g.publicEndpoint != nil {
		return l.phase != leaseClosed && l.update.Enabled && l.update.PublicEndpoint != nil &&
			*g.publicEndpoint == *l.update.PublicEndpoint &&
			(!l.update.BoundConnections || l.phase == leaseCurrent && now.Before(l.update.View.ValidUntil)) &&
			(l.update.IP == nil || l.update.IP.Allows(g.source))
	}
	if g.connector != nil && g.connector.metadata != l.update.View.MetadataRevision {
		return false
	}
	if g.connection {
		return l.phase == leaseCurrent && l.update.Enabled && l.update.BoundConnections && now.Before(l.update.View.ValidUntil)
	}
	if g.anonymous {
		return l.phase == leaseCurrent && l.update.Enabled && l.update.Anonymous && now.Before(l.update.View.ValidUntil) && (l.update.IP == nil || l.update.IP.Allows(g.source))
	}
	if l.allowedLocked(g.permission, g.source, now) {
		return true
	}
	if !g.renewable || l.phase != leaseCurrent || !l.update.Enabled || !now.Before(g.confirmedUntil) || g.permission.Facts().VisitorPolicyRevision == l.update.View.VisitorPolicyRevision ||
		(l.update.IP != nil && !l.update.IP.Allows(g.source)) {
		return false
	}
	prior := l.update.View
	prior.VisitorPolicyRevision = g.permission.Facts().VisitorPolicyRevision
	return visitortoken.CheckCurrent(g.permission, prior, now) == nil
}

// Bind follows signature and possession verification. each HTTP request binds
// separately so cancellation never closes unrelated HTTP/2 request streams.
func (l *Lease) Bind(permission visitortoken.VerifiedPermission, source netip.Addr, stop func()) (*Guard, error) {
	return l.bind(permission, false, source, stop)
}

func (l *Lease) BindAnonymous(source netip.Addr, stop func()) (*Guard, error) {
	return l.bind(visitortoken.VerifiedPermission{}, true, source, stop)
}

// BindConnection fences time-limited serving authority, including idle TLS and
// setup connections. it grants no visitor permission. ordinary policies retain
// their request-level guards and return no connection guard.
func (l *Lease) BindConnection(stop func()) (*Guard, error) {
	if stop == nil {
		return nil, ErrUpdate
	}
	l.mu.Lock()
	now := l.now()
	stopped := l.expireLocked(now)
	var guard *Guard
	var err error
	if l.phase != leaseCurrent || !l.update.Enabled {
		err = visitortoken.ErrPolicy
	} else if l.update.BoundConnections {
		guard = &Guard{lease: l, connection: true, stop: stop}
		l.guards[guard] = struct{}{}
		guard.resetLocked()
	}
	l.mu.Unlock()
	stopGuards(stopped)
	return guard, err
}

func (l *Lease) bind(permission visitortoken.VerifiedPermission, anonymous bool, source netip.Addr, stop func()) (*Guard, error) {
	if stop == nil {
		return nil, ErrUpdate
	}
	l.mu.Lock()
	now := l.now()
	stopped := l.expireLocked(now)
	guard := &Guard{lease: l, permission: permission, source: source, stop: stop, anonymous: anonymous, confirmedUntil: l.update.View.ValidUntil}
	if !guard.allowedLocked(now) {
		l.mu.Unlock()
		stopGuards(stopped)
		return nil, visitortoken.ErrPolicy
	}
	l.guards[guard] = struct{}{}
	guard.resetLocked()
	l.mu.Unlock()
	stopGuards(stopped)
	return guard, nil
}

func (g *Guard) resetLocked() {
	// ordinary HTTP policy expires per request. an idle endpoint guard grants
	// no access; only time-limited serving authority also expires the socket.
	if g.publicEndpoint != nil && !g.lease.update.BoundConnections {
		if g.timer != nil {
			g.timer.Stop()
		}
		return
	}
	view := g.lease.update.View
	facts := g.permission.Facts()
	until := view.ValidUntil
	if !g.anonymous && !g.connection && g.publicEndpoint == nil {
		g.permissionUntil = retainedCredentialDeadline(g.permissionUntil, g.permissionExpires, view.LocalDeadline(facts.ExpiresAt), facts.ExpiresAt)
		g.permissionExpires = facts.ExpiresAt
		until = g.permissionUntil
		if g.renewable && facts.VisitorPolicyRevision != view.VisitorPolicyRevision {
			until = earlier(until, g.confirmedUntil)
		}
	}
	subject := facts.Subject
	if certificate, ok := subject.(visitortoken.Certificate); ok {
		subject = certificate.Source
	}
	if workload, ok := subject.(visitortoken.Workload); ok {
		parent, _ := view.Workload(workload.SessionID)
		g.parentUntil = retainedCredentialDeadline(g.parentUntil, g.parentExpires, view.LocalDeadline(parent.ExpiresAt), parent.ExpiresAt)
		g.parentExpires = parent.ExpiresAt
		until = earlier(until, g.parentUntil)
	}
	if permission, ok := g.permission.WorkloadPermission(); ok {
		deadline := view.LocalDeadline(permission.Identity().ExpiresAt)
		if g.workloadCredentialUntil.IsZero() {
			g.workloadCredentialUntil = deadline
		} else {
			g.workloadCredentialUntil = earlier(g.workloadCredentialUntil, deadline)
		}
		until = earlier(until, g.workloadCredentialUntil)
	}
	if key, ok := subject.(visitortoken.RegisteredKey); ok {
		parent, _ := view.RegisteredKey(key.AuthorityID())
		g.parentUntil = retainedCredentialDeadline(g.parentUntil, g.parentExpires, view.LocalDeadline(parent.ExpiresAt), parent.ExpiresAt)
		g.parentExpires = parent.ExpiresAt
		until = earlier(until, g.parentUntil)
	}
	delay := max(0, until.Sub(g.lease.now()))
	if g.timer == nil {
		g.timer = time.AfterFunc(delay, g.expire)
	} else {
		g.timer.Reset(delay)
	}
}

// a new policy observation does not renew a signed credential or its parent.
// only a changed absolute expiry can change the previously accepted bound.
func retainedCredentialDeadline(previous, previousExpiry, next, expiry time.Time) time.Time {
	if previous.IsZero() {
		return next
	}
	return earlier(next, previous.Add(expiry.Sub(previousExpiry)))
}

func (g *Guard) expire() {
	l := g.lease
	l.mu.Lock()
	_, found := l.guards[g]
	now := l.now()
	if found && !g.allowedLocked(now) {
		delete(l.guards, g)
		g.policyRefused = l.phase == leaseCurrent && now.Before(l.update.View.ValidUntil)
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
	g.policyRefused = false
	if g.timer != nil {
		g.timer.Stop()
	}
	l.mu.Unlock()
	g.once.Do(func() {})
}

// Renew follows local verification of a newly issued token for the same source.
// it cannot change the admitted subject or revive an expired/canceled request.
func (g *Guard) Renew(permission visitortoken.VerifiedPermission) error {
	l := g.lease
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if _, active := l.guards[g]; !active || g.anonymous || !permission.SameAdmission(g.permission) || !g.allowedLocked(now) || !l.allowedLocked(permission, g.source, now) {
		return visitortoken.ErrPolicy
	}
	g.permission = permission
	g.confirmedUntil = l.update.View.ValidUntil
	g.resetLocked()
	return nil
}

// AllowRenewal records an explicit credential owner's responsibility to obtain
// fresh permission. a changed revision can retain only the last confirmed
// policy deadline; unrelated policy renewals never extend that allowance.
func (g *Guard) AllowRenewal() error {
	l := g.lease
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, active := l.guards[g]; !active || g.anonymous || !l.allowedLocked(g.permission, g.source, l.now()) {
		return visitortoken.ErrPolicy
	}
	g.renewable = true
	return nil
}

// Revoke stops this one admission when its credential owner learns a terminal
// authority result. it does not affect siblings sharing the visitor connection.
func (g *Guard) Revoke() {
	l := g.lease
	l.mu.Lock()
	_, active := l.guards[g]
	delete(l.guards, g)
	g.policyRefused = false
	if g.timer != nil {
		g.timer.Stop()
	}
	l.mu.Unlock()
	if active {
		g.abort()
	}
}

func (l *Lease) expireLocked(now time.Time) []*Guard {
	if l.phase != leaseCurrent || now.Before(l.update.View.ValidUntil) {
		return nil
	}
	l.phase = leaseNeedsSnapshot
	l.notifyLocked()
	l.epoch++
	var guards []*Guard
	for guard := range l.guards {
		if guard.publicEndpoint != nil && !l.update.BoundConnections {
			continue
		}
		guards = append(guards, guard)
		delete(l.guards, guard)
	}
	return guards
}

func (l *Lease) expire() {
	l.mu.Lock()
	stopped := l.expireLocked(l.now())
	l.mu.Unlock()
	stopGuards(stopped)
}

func (l *Lease) Close() {
	l.mu.Lock()
	l.phase = leaseClosed
	l.notifyLocked()
	if l.timer != nil {
		l.timer.Stop()
	}
	l.epoch++
	var guards []*Guard
	for guard := range l.guards {
		guards = append(guards, guard)
		delete(l.guards, guard)
	}
	l.mu.Unlock()
	stopGuards(guards)
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
