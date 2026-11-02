package visitorlease

import (
	"net/netip"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

// ConnectorGuard owns stream permission, not a borrowed HTTP request guard. only
// BindConnector constructs it from verified connector subject evidence. the service
// admission must separately retain and check its concrete physical owner and C.
type ConnectorGuard struct{ guard *Guard }

type connectorPermission struct {
	metadata int64
}

// BindConnector binds one verified connector stream to canonical policy and source.
// packet delivery supplies neither application permission nor capacity.
func (l *Lease) BindConnector(permission visitortoken.VerifiedPermission, source netip.Addr, metadata int64, stop func()) (*ConnectorGuard, error) {
	if l == nil || l.scope.Kind != visitorscope.Service || stop == nil || metadata < 1 || !source.IsValid() || source.Zone() != "" {
		return nil, ErrUpdate
	}
	if _, err := visitortoken.ConnectorSubject(permission.Facts().Subject); err != nil {
		return nil, err
	}
	l.mu.Lock()
	now := l.now()
	g := &Guard{lease: l, permission: permission, source: source.Unmap(), stop: stop,
		confirmedUntil: l.update.View.ValidUntil,
		connector:      &connectorPermission{metadata: metadata}}
	if !g.allowedLocked(now) {
		l.mu.Unlock()
		return nil, visitortoken.ErrPolicy
	}
	l.guards[g] = struct{}{}
	g.resetLocked()
	l.mu.Unlock()
	return &ConnectorGuard{guard: g}, nil
}

// Current is a callback-free local operation entry. membership, metadata,
// permission and source are checked under their one canonical mutex, including
// absolute expiry when timer delivery is delayed.
// it never admits a new stream, renews authority, or constructs an owner proof.
func (n *ConnectorGuard) Current() (time.Time, error) {
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
	return until, nil
}

func (n *ConnectorGuard) Renew(permission visitortoken.VerifiedPermission) error {
	if n == nil || n.guard == nil {
		return ErrUpdate
	}
	return n.guard.Renew(permission)
}

func (n *ConnectorGuard) AllowRenewal() error {
	if n == nil || n.guard == nil {
		return ErrUpdate
	}
	return n.guard.AllowRenewal()
}

func (n *ConnectorGuard) Close() {
	if n != nil && n.guard != nil {
		n.guard.Close()
	}
}

func (n *ConnectorGuard) Revoke() {
	if n != nil && n.guard != nil {
		n.guard.Revoke()
	}
}
