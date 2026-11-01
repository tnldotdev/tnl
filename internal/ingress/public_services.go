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
	AuditSink                                                    serviceaudit.Sink
	IngressPoolID                                                string
	Control                                                      PublicServiceControl
	Forwarder                                                    ServiceForwarder
	CurrentLease                                                 func() ingressv1.IngressLease
	MaxSessions, MaxPending, MaxServiceStreams, MaxSourceStreams int
	PendingTimeout                                               time.Duration
	RecheckInterval, HardAuthorizationTTL, RecheckTimeout        time.Duration
}

// PublicServices carries application TLS unchanged from trusted destination
// ports. it has no connector listener, transport TLS, or routing history.
type PublicServices struct {
	config                    PublicServicesConfig
	mu                        sync.Mutex
	sessions, pending, active int
	services                  map[string]int
	sources                   map[netip.Addr]int
	connections               map[net.Conn]context.CancelFunc
	admissions                context.Context
	stopAdmissions            context.CancelFunc
	changed                   chan struct{}
	closed                    bool
	nextRelay                 atomic.Uint64
}

func NewPublicServices(config PublicServicesConfig) (*PublicServices, error) {
	if config.Control == nil || config.Forwarder == nil || config.CurrentLease == nil {
		return nil, errors.New("ingress: public services need control, forwarding and a current lease")
	}
	for _, item := range []struct {
		value        *int
		defaultValue int
	}{
		{&config.MaxSessions, 256}, {&config.MaxPending, 128},
		{&config.MaxServiceStreams, 64}, {&config.MaxSourceStreams, 16},
	} {
		if *item.value < 0 {
			return nil, errors.New("ingress: public service capacity must be positive")
		}
		if *item.value == 0 {
			*item.value = item.defaultValue
		}
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
	return &PublicServices{config: config, services: make(map[string]int), sources: make(map[netip.Addr]int),
		connections: make(map[net.Conn]context.CancelFunc), admissions: admissions, stopAdmissions: stop, changed: make(chan struct{})}, nil
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
	if p.closed || p.admissions.Err() != nil || p.sessions >= p.config.MaxSessions {
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

type privateStreamAdmission struct {
	owner            *PublicServices
	service          string
	source           netip.Addr
	promoted, closed bool
}

func (p *PublicServices) pendingStream(service string, source netip.Addr) (*privateStreamAdmission, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.admissions.Err() != nil || p.pending >= p.config.MaxPending || p.services[service] >= p.config.MaxServiceStreams || p.sources[source] >= p.config.MaxSourceStreams {
		return nil, false
	}
	p.pending++
	p.services[service]++
	p.sources[source]++
	return &privateStreamAdmission{owner: p, service: service, source: source}, true
}

func (a *privateStreamAdmission) promote() bool {
	p := a.owner
	p.mu.Lock()
	defer p.mu.Unlock()
	if a.closed || a.promoted || p.active >= p.config.MaxSessions*4 {
		return false
	}
	a.promoted = true
	p.pending--
	p.active++
	return true
}

func (a *privateStreamAdmission) selectService(service string) bool {
	p := a.owner
	p.mu.Lock()
	defer p.mu.Unlock()
	if a.closed || a.promoted {
		return false
	}
	if a.service == service {
		return true
	}
	if p.services[service] >= p.config.MaxServiceStreams {
		return false
	}
	p.services[a.service]--
	if p.services[a.service] == 0 {
		delete(p.services, a.service)
	}
	p.services[service]++
	a.service = service
	return true
}

func (a *privateStreamAdmission) close() {
	p := a.owner
	p.mu.Lock()
	defer p.mu.Unlock()
	if a.closed {
		return
	}
	a.closed = true
	if a.promoted {
		p.active--
	} else {
		p.pending--
	}
	p.services[a.service]--
	if p.services[a.service] == 0 {
		delete(p.services, a.service)
	}
	p.sources[a.source]--
	if p.sources[a.source] == 0 {
		delete(p.sources, a.source)
	}
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
