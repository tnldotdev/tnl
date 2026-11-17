package visitorlease

import (
	"fmt"
	"net/netip"

	"github.com/tnldotdev/tnl/internal/policy/serviceendpoint"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// ErrSourceDenied retains the policy fence while identifying an actual source
// rejection, not an unavailable snapshot or a different endpoint revision.
var ErrSourceDenied = fmt.Errorf("visitor source is not permitted by the service IP policy: %w", visitortoken.ErrPolicy)

func validPublicEndpoint(endpoint controlv1.VisitorPublicEndpoint) bool {
	protocol := "tcp"
	if endpoint.Port == 443 {
		protocol = "http"
	}
	return endpoint.EndpointRevision > 0 && serviceendpoint.Valid(protocol, endpoint.Hostname, endpoint.Port, true)
}

// BindPublicConnection keeps a public connection within the current endpoint
// and IP policy. it grants no visitor access and does not bind connector traffic.
func (l *Lease) BindPublicConnection(endpoint controlv1.VisitorPublicEndpoint, source netip.Addr, stop func()) (*Guard, error) {
	if l == nil || !validPublicEndpoint(endpoint) || !source.IsValid() || source.IsUnspecified() || source.Zone() != "" || stop == nil {
		return nil, ErrUpdate
	}
	l.mu.Lock()
	now := l.now()
	stopped := l.expireLocked(now)
	guard := &Guard{lease: l, publicEndpoint: &endpoint, source: source.Unmap(), stop: stop}
	if l.phase != leaseCurrent || !guard.allowedLocked(now) {
		err := visitortoken.ErrPolicy
		if l.phase == leaseCurrent && l.update.Enabled && now.Before(l.update.View.ValidUntil) &&
			l.update.PublicEndpoint != nil && *l.update.PublicEndpoint == endpoint &&
			l.update.IP != nil && !l.update.IP.Allows(source.Unmap()) {
			err = ErrSourceDenied
		}
		l.mu.Unlock()
		stopGuards(stopped)
		return nil, err
	}
	l.guards[guard] = struct{}{}
	guard.resetLocked()
	l.mu.Unlock()
	stopGuards(stopped)
	return guard, nil
}
