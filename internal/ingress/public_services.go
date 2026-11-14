package ingress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

var ErrServiceAdmission = errors.New("ingress: public service admission denied")

// ServiceForwarder opens an acknowledged, lease-bound internal relay stream.
// ingress writes the original PROXY v2 metadata only after relay acceptance.
type ServiceForwarder interface {
	OpenPrivate(context.Context, ingressv1.ServiceRelay, tunnelv1.ServiceForwardingHeader) (net.Conn, error)
}

type PublicServicesConfig struct {
	AuditSink                                             serviceaudit.Sink
	Metrics                                               Metrics
	Observer                                              OperationObserver
	IngressPoolID                                         string
	Control                                               PublicServiceControl
	Forwarder                                             ServiceForwarder
	CurrentLease                                          func() ingressv1.IngressLease
	PendingTimeout                                        time.Duration
	RecheckInterval, HardAuthorizationTTL, RecheckTimeout time.Duration
}

// PublicServices carries application TLS unchanged from trusted destination
// ports. it has no connector listener, transport TLS, or routing history.
type PublicServices struct {
	config         PublicServicesConfig
	server         *Server
	mu             sync.Mutex
	sessions       int
	streams        int
	connections    map[net.Conn]context.CancelFunc
	admissions     context.Context
	stopAdmissions context.CancelFunc
	changed        chan struct{}
	closed         bool
	nextRelay      atomic.Uint64
}

func NewPublicServices(config PublicServicesConfig) (*PublicServices, error) {
	if config.Control == nil || config.Forwarder == nil || config.CurrentLease == nil {
		return nil, errors.New("ingress: public services need control, forwarding and a current lease")
	}
	if config.PendingTimeout < 0 {
		return nil, errors.New("ingress: public service timeout must be positive")
	}
	if config.PendingTimeout == 0 {
		config.PendingTimeout = 10 * time.Second
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
		return nil, errors.New("ingress: service rechecks must stay within the hard authorization deadline")
	}
	if config.IngressPoolID == "" {
		config.IngressPoolID = "ingress-a"
	}
	admissions, stop := context.WithCancel(context.Background())
	return &PublicServices{config: config, connections: make(map[net.Conn]context.CancelFunc),
		admissions: admissions, stopAdmissions: stop, changed: make(chan struct{})}, nil
}

// the public listener owns one process traffic meter. service forwarding shares
// that meter and its ordinary/pending classes, never a second set of buckets.
func (p *PublicServices) bindServer(server *Server) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.server != nil || p.sessions != 0 {
		return errors.New("ingress: public services already bound to a listener")
	}
	p.server = server
	return nil
}

func (p *PublicServices) lease(now time.Time) (ingressv1.IngressLease, error) {
	if p.admissions.Err() != nil {
		return ingressv1.IngressLease{}, ErrServiceAdmission
	}
	lease, err := p.liveLease(now)
	if err != nil || lease.Draining {
		return ingressv1.IngressLease{}, ErrServiceAdmission
	}
	return lease, nil
}

func (p *PublicServices) liveLease(now time.Time) (ingressv1.IngressLease, error) {
	lease := p.config.CurrentLease()
	if lease.IngressId == "" || lease.IngressRunId == "" || lease.IngressLeaseRevision < 1 || !lease.LeaseExpiresAt.After(now) {
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

func (p *PublicServices) acquireSession(ctx context.Context, connection net.Conn) (context.Context, func(), bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.server == nil || p.closed || p.admissions.Err() != nil {
		return nil, nil, false
	}
	ctx, cancel := context.WithCancel(ctx)
	p.sessions++
	p.connections[connection] = cancel
	return ctx, sync.OnceFunc(func() {
		cancel()
		p.mu.Lock()
		defer p.mu.Unlock()
		delete(p.connections, connection)
		p.sessions--
		close(p.changed)
		p.changed = make(chan struct{})
	}), true
}

func (p *PublicServices) StopAccepting() { p.stopAdmissions() }

func (p *PublicServices) Drain(ctx context.Context) error {
	p.stopAdmissions()
	p.mu.Lock()
	for p.sessions != 0 {
		changed := p.changed
		p.mu.Unlock()
		select {
		case <-ctx.Done():
			_ = p.Close()
			return context.Cause(ctx)
		case <-changed:
		}
		p.mu.Lock()
	}
	p.mu.Unlock()
	return nil
}

func (p *PublicServices) Close() error {
	p.stopAdmissions()
	p.mu.Lock()
	p.closed = true
	connections := make([]net.Conn, 0, len(p.connections))
	for connection, cancel := range p.connections {
		cancel()
		connections = append(connections, connection)
	}
	p.mu.Unlock()
	var result error
	for _, connection := range connections {
		result = errors.Join(result, connection.Close())
	}
	p.mu.Lock()
	for p.sessions != 0 {
		changed := p.changed
		p.mu.Unlock()
		<-changed
		p.mu.Lock()
	}
	p.mu.Unlock()
	return result
}

func (p *PublicServices) Load() int64 { p.mu.Lock(); defer p.mu.Unlock(); return int64(p.sessions) }

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
