package ingress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

var ErrServiceAdmission = errors.New("ingress: public service admission denied")
var ErrServiceSelectionLimit = errors.New("ingress: service run selection limit reached")

// ServiceForwarder opens an acknowledged, lease-bound internal relay stream.
// ingress writes the original PROXY v2 metadata only after relay acceptance.
type ServiceForwarder interface {
	OpenService(context.Context, ingressv1.ServiceRelay, tunnelv1.ServiceForwardingHeader, func(context.Context) error) (net.Conn, error)
}

func serviceDefaults(config *Config) error {
	if config.Control == nil && config.Forwarder == nil && config.CurrentLease == nil {
		return nil
	}
	if config.Control == nil || config.Forwarder == nil || config.CurrentLease == nil {
		return errors.New("ingress: public services need control, forwarding and a current lease")
	}
	if config.RecheckInterval == 0 {
		config.RecheckInterval = 30 * time.Second
	}
	if config.HardAuthorizationTTL == 0 {
		config.HardAuthorizationTTL = 2 * time.Minute
	}
	if config.RecheckTimeout == 0 {
		config.RecheckTimeout = 5 * time.Second
	}
	if config.RecheckInterval <= 0 || config.RecheckInterval > 30*time.Second ||
		config.HardAuthorizationTTL <= config.RecheckInterval || config.HardAuthorizationTTL > 2*time.Minute ||
		config.RecheckTimeout <= 0 || config.RecheckTimeout > config.RecheckInterval {
		return errors.New("ingress: service rechecks must stay within the hard authorization deadline")
	}
	if config.IngressPoolID == "" {
		config.IngressPoolID = "ingress-a"
	}
	return nil
}

func (s *Server) lease(now time.Time) (ingressv1.IngressLease, error) {
	if s.admissions.Err() != nil {
		return ingressv1.IngressLease{}, ErrServiceAdmission
	}
	lease, err := s.liveLease(now)
	if err != nil || lease.Draining {
		return ingressv1.IngressLease{}, ErrServiceAdmission
	}
	return lease, nil
}

func (s *Server) liveLease(now time.Time) (ingressv1.IngressLease, error) {
	lease := s.config.CurrentLease()
	if lease.IngressId == "" || lease.IngressRunId == "" || lease.IngressLeaseRevision < 1 || !lease.ServingUntil.After(now) {
		return ingressv1.IngressLease{}, ErrServiceAdmission
	}
	return lease, nil
}

func samePrivateLease(a, b ingressv1.IngressLease) bool {
	return a.IngressId == b.IngressId && a.IngressRunId == b.IngressRunId && a.IngressLeaseRevision == b.IngressLeaseRevision
}

func validPrivateSocketPair(source, destination netip.AddrPort) bool {
	return source.IsValid() && destination.IsValid() && source.Port() != 0 && destination.Port() != 0 && source.Addr().Zone() == "" && destination.Addr().Zone() == ""
}

func privateRecheckDelay(interval, timeout time.Duration, deadline time.Time) time.Duration {
	remaining := time.Until(deadline)
	return max(time.Nanosecond, min(interval, remaining-min(timeout, remaining/2)))
}

func privateMinTime(left, right time.Time) time.Time {
	if left.Before(right) {
		return left
	}
	return right
}
