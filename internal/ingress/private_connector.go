package ingress

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/proxyproto"
	"github.com/tnldotdev/tnl/internal/serviceaudit"
	"github.com/tnldotdev/tnl/internal/tunnel"
	"github.com/tnldotdev/tnl/internal/visitorsubject"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

var ErrPrivateAdmission = errors.New("ingress: private connector admission denied")

type PrivateControl interface {
	ClaimPrivateConnectorSession(context.Context, string, ingressv1.PrivateConnectorSessionClaim) (ingressv1.PrivateConnectorSessionResult, error)
	AuthorizePrivateServiceStream(context.Context, string, ingressv1.PrivateServiceStreamClaim) (ingressv1.PrivateServiceStreamResult, error)
	ClosePrivateServiceStream(context.Context, string, string, ingressv1.ClosePrivateServiceStreamJSONRequestBody) error
	RecheckPrivateServiceVisitor(context.Context, string, ingressv1.PrivateServiceVisitorRecheck) (ingressv1.PrivateServiceVisitorRecheckResult, error)
	GetPrivateServiceSnapshot(context.Context, string, ingressv1.GetPrivateServiceSnapshotParams) (ingressv1.PrivateServiceSnapshot, error)
	GetPrivateServiceEvents(context.Context, string, ingressv1.GetPrivateServiceEventsParams) (ingressv1.PrivateServiceSnapshot, error)
}

// PrivateForwarder opens an acknowledged, lease-bound internal relay stream.
// it sends the private forwarding sideband to the relay, which must bind the
// publisher stream before returning. ingress alone writes PROXY v2 afterward.
type PrivateForwarder interface {
	OpenPrivate(context.Context, ingressv1.PrivateServiceRelay, tunnelv1.PrivateForwardingHeader) (net.Conn, error)
}

type PrivateConnectorConfig struct {
	AuditSink                                                    serviceaudit.Sink
	Hostname                                                     string
	IngressPoolID                                                string
	TLSConfig                                                    *tls.Config
	Transport                                                    muxsession.TLSYamuxConfig
	Control                                                      PrivateControl
	DirectControl                                                DirectControl
	Forwarder                                                    PrivateForwarder
	Routing                                                      *PrivateRoutingTable
	CurrentLease                                                 func() ingressv1.IngressLease
	MaxSessions, MaxPending, MaxServiceStreams, MaxSourceStreams int
	PendingTimeout                                               time.Duration
	RecheckInterval, HardAuthorizationTTL, RecheckTimeout        time.Duration
}

type PrivateConnector struct {
	config                    PrivateConnectorConfig
	mu                        sync.Mutex
	sessions, pending, active int
	services                  map[string]int
	sources                   map[netip.Addr]int
	refresh                   sync.Mutex
	leaseID                   string
	transports                map[muxsession.Session]struct{}
	admissions                context.Context
	stopAdmissions            context.CancelFunc
	changed                   chan struct{}
	closed                    bool
	nextRelay                 atomic.Uint64
}

func NewPrivateConnector(config PrivateConnectorConfig) (*PrivateConnector, error) {
	canonical, err := naming.CanonicalizeHostname(config.Hostname)
	if err != nil || canonical != config.Hostname || config.TLSConfig == nil ||
		(config.TLSConfig.GetCertificate == nil && len(config.TLSConfig.Certificates) != 1) ||
		len(config.TLSConfig.Certificates) > 1 ||
		config.TLSConfig.GetConfigForClient != nil || config.Control == nil || config.Forwarder == nil ||
		config.Routing == nil || config.CurrentLease == nil {
		return nil, errors.New("ingress: private connector needs one shared hostname, TLS certificate, lease, control and forwarding")
	}
	for _, item := range []struct {
		value        *int
		defaultValue int
	}{
		{&config.MaxSessions, 256}, {&config.MaxPending, 128},
		{&config.MaxServiceStreams, 64}, {&config.MaxSourceStreams, 16},
	} {
		if *item.value < 0 {
			return nil, errors.New("ingress: private connector capacity must be positive")
		}
		if *item.value == 0 {
			*item.value = item.defaultValue
		}
	}
	if config.PendingTimeout < 0 {
		return nil, errors.New("ingress: private connector timeout must be positive")
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
		return nil, errors.New("ingress: private visitor recheck intervals must stay within the hard authorization deadline")
	}
	if config.Transport.MaxIncomingStreams <= 0 || config.Transport.MaxIncomingStreams > config.MaxSourceStreams {
		config.Transport.MaxIncomingStreams = config.MaxSourceStreams
	}
	admissions, stop := context.WithCancel(context.Background())
	if config.IngressPoolID == "" {
		config.IngressPoolID = "ingress-a"
	}
	return &PrivateConnector{config: config, services: make(map[string]int), sources: make(map[netip.Addr]int),
		transports: make(map[muxsession.Session]struct{}), admissions: admissions, stopAdmissions: stop, changed: make(chan struct{})}, nil
}

func (p *PrivateConnector) lease(now time.Time) (ingressv1.IngressLease, error) {
	if p.admissions.Err() != nil {
		return ingressv1.IngressLease{}, ErrPrivateAdmission
	}
	lease, err := p.liveLease(now)
	if err != nil || lease.Draining {
		return ingressv1.IngressLease{}, ErrPrivateAdmission
	}
	return lease, nil
}

func (p *PrivateConnector) liveLease(now time.Time) (ingressv1.IngressLease, error) {
	lease := p.config.CurrentLease()
	if lease.IngressId == "" || lease.IngressRunId == "" || lease.IngressLeaseRevision < 1 ||
		!lease.LeaseExpiresAt.After(now) {
		p.config.Routing.Clear()
		return ingressv1.IngressLease{}, ErrPrivateAdmission
	}
	return lease, nil
}

func samePrivateLease(a, b ingressv1.IngressLease) bool {
	return a.IngressId == b.IngressId && a.IngressRunId == b.IngressRunId &&
		a.IngressLeaseRevision == b.IngressLeaseRevision
}

func (p *PrivateConnector) acquireSession() (func(), bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.admissions.Err() != nil || p.sessions >= p.config.MaxSessions {
		return nil, false
	}
	p.sessions++
	return sync.OnceFunc(func() { p.mu.Lock(); p.sessions--; p.notifyLocked(); p.mu.Unlock() }), true
}

func (p *PrivateConnector) notifyLocked() { close(p.changed); p.changed = make(chan struct{}) }

func (p *PrivateConnector) StopAccepting() { p.stopAdmissions() }

// Drain stops new sessions and admissions while already authorized streams
// remain under their live authorization checks until they finish or time out.
func (p *PrivateConnector) Drain(ctx context.Context) error {
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

func (p *PrivateConnector) Close() error {
	p.stopAdmissions()
	p.mu.Lock()
	p.closed = true
	sessions := make([]muxsession.Session, 0, len(p.transports))
	for session := range p.transports {
		sessions = append(sessions, session)
	}
	p.mu.Unlock()
	var result error
	for _, session := range sessions {
		result = errors.Join(result, session.Close())
	}
	return result
}

func (p *PrivateConnector) Load() int64 { p.mu.Lock(); defer p.mu.Unlock(); return int64(p.sessions) }

type privateStreamAdmission struct {
	owner    *PrivateConnector
	service  string
	source   netip.Addr
	promoted bool
	closed   bool
}

func (p *PrivateConnector) pendingStream(service string, source netip.Addr) (*privateStreamAdmission, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pending >= p.config.MaxPending || p.services[service] >= p.config.MaxServiceStreams ||
		p.sources[source] >= p.config.MaxSourceStreams {
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

// Accept terminates TLS for the infrastructure hostname only. the source and
// destination come from ingress's verified socket/PROXY v2 metadata, not SNI.
func (p *PrivateConnector) Accept(ctx context.Context, connection net.Conn, source, destination netip.AddrPort) error {
	if connection == nil || !validPrivateSocketPair(source, destination) {
		return ErrPrivateAdmission
	}
	setup, cancel := context.WithTimeout(ctx, p.config.PendingTimeout)
	defer cancel()
	if err := connection.SetDeadline(time.Now().Add(p.config.PendingTimeout)); err != nil {
		return err
	}
	transport, err := muxsession.AcceptPrivateMuxTLS(setup, connection, p.TransportTLSConfig(), p.config.Transport)
	if err != nil {
		return err
	}
	defer transport.Close()
	if err = connection.SetDeadline(time.Time{}); err != nil {
		return err
	}
	return p.AcceptSession(ctx, transport, source, destination)
}

func (p *PrivateConnector) TransportTLSConfig() *tls.Config {
	config := p.config.TLSConfig.Clone()
	config.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if hello.ServerName != p.config.Hostname {
			return nil, ErrPrivateAdmission
		}
		return nil, nil
	}
	return config
}

// AcceptQUIC obtains source metadata from the authenticated transport socket.
// the shared infrastructure port is unrelated to a private service's identity.
func (p *PrivateConnector) AcceptQUIC(ctx context.Context, session muxsession.Session) error {
	connection, ok := session.(interface {
		LocalAddr() net.Addr
		RemoteAddr() net.Addr
	})
	if !ok {
		if session != nil {
			_ = session.Close()
		}
		return ErrPrivateAdmission
	}
	source, sourceErr := netip.ParseAddrPort(connection.RemoteAddr().String())
	destination, destinationErr := netip.ParseAddrPort(connection.LocalAddr().String())
	if sourceErr != nil || destinationErr != nil {
		_ = session.Close()
		return ErrPrivateAdmission
	}
	return p.AcceptSession(ctx, session, source, destination)
}

func validPrivateSocketPair(source, destination netip.AddrPort) bool {
	return source.IsValid() && destination.IsValid() && source.Port() != 0 && destination.Port() != 0 && source.Addr().Zone() == "" && destination.Addr().Zone() == ""
}

// AcceptSession authenticates the first mux control stream for either QUIC or
// TLS/TCP. the listener supplies socket/verified-PROXY source metadata; no
// connector frame can supply or replace it.
func (p *PrivateConnector) AcceptSession(ctx context.Context, transport muxsession.Session, source, destination netip.AddrPort) error {
	if transport == nil || !validPrivateSocketPair(source, destination) {
		if transport != nil {
			_ = transport.Close()
		}
		return ErrPrivateAdmission
	}
	defer transport.Close()
	release, ok := p.acquireSession()
	if !ok {
		return ErrPrivateAdmission
	}
	defer release()
	p.mu.Lock()
	if p.closed || p.admissions.Err() != nil {
		p.mu.Unlock()
		return ErrPrivateAdmission
	}
	p.transports[transport] = struct{}{}
	p.mu.Unlock()
	defer func() { p.mu.Lock(); delete(p.transports, transport); p.mu.Unlock() }()
	if _, err := p.lease(time.Now()); err != nil {
		return err
	}
	handshakeCtx, cancel := context.WithTimeout(ctx, p.config.PendingTimeout)
	defer cancel()
	var bound ingressv1.PrivateConnectorSessionResult
	var authenticated ingressv1.IngressLease
	session, err := tunnel.AcceptPrivateConnector(handshakeCtx, transport, func(authCtx context.Context, hello tunnelv1.PrivateConnectorSessionHello) (tunnelv1.PrivateConnectorSessionAccepted, error) {
		lease, err := p.lease(time.Now())
		if err != nil {
			return tunnelv1.PrivateConnectorSessionAccepted{}, err
		}
		bound, err = p.config.Control.ClaimPrivateConnectorSession(authCtx, lease.IngressId, ingressv1.PrivateConnectorSessionClaim{
			IngressRunId: lease.IngressRunId, IngressLeaseRevision: lease.IngressLeaseRevision,
			PrivateServiceId: hello.PrivateServiceID, ConnectorSessionId: hello.SessionID,
			SessionCredential: hello.Credential, ObservedSourceIp: source.Addr().Unmap().String(),
			Subject: visitorsubject.Wire(hello.Subject), Nonce: hex.EncodeToString(hello.Nonce), Signature: base64.RawURLEncoding.EncodeToString(hello.Signature),
		})
		if err != nil {
			return tunnelv1.PrivateConnectorSessionAccepted{}, err
		}
		if bound.ConnectorSessionId != hello.SessionID || bound.PrivateServiceId != hello.PrivateServiceID || !visitorsubject.Equal(bound.Subject, hello.Subject) ||
			bound.ObservedSourceIp != source.Addr().Unmap().String() ||
			!bound.ExpiresAt.After(time.Now()) {
			return tunnelv1.PrivateConnectorSessionAccepted{}, ErrPrivateAdmission
		}
		authenticated = lease
		return tunnelv1.PrivateConnectorSessionAccepted{ProtocolVersion: tunnelv1.Version, Kind: "private_connector_session_accepted", PrivateServiceID: bound.PrivateServiceId,
			SessionID: bound.ConnectorSessionId, Subject: hello.Subject, SourceIP: bound.ObservedSourceIp, ExpiresAt: bound.ExpiresAt}, nil
	})
	if err != nil {
		return err
	}
	ctx, cancelSession := context.WithCancel(ctx)
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		for {
			current, err := p.liveLease(time.Now())
			if err != nil || !samePrivateLease(current, authenticated) || current.Draining && current.DrainDeadline != nil && !current.DrainDeadline.After(time.Now()) {
				cancelSession()
				return
			}
			delay := min(time.Second, time.Until(current.LeaseExpiresAt))
			if current.Draining && current.DrainDeadline != nil {
				delay = min(delay, time.Until(*current.DrainDeadline))
			}
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
	defer func() { cancelSession(); <-watchDone }()
	var workers sync.WaitGroup
	var active atomic.Int64
	var expired atomic.Bool
	cancelDone := make(chan struct{})
	stopClosing := context.AfterFunc(ctx, func() { _ = session.Close(); close(cancelDone) })
	defer func() {
		if !stopClosing() {
			<-cancelDone
		}
	}()
	graceful := false
	defer func() {
		cancelSession()
		if !graceful {
			_ = session.Close()
		}
		workers.Wait()
		_ = session.Close()
	}()
	acceptCtx, stopAccept := context.WithCancel(ctx)
	defer stopAccept()
	newStreamCtx, stopNew := context.WithDeadline(acceptCtx, bound.ExpiresAt)
	defer stopNew()
	stopDrain := context.AfterFunc(p.admissions, stopNew)
	defer stopDrain()
	for {
		if expired.Load() && active.Load() == 0 {
			graceful = true
			return nil
		}
		current, err := p.liveLease(time.Now())
		if err != nil || !samePrivateLease(current, authenticated) {
			return ErrPrivateAdmission
		}
		if current.Draining && !expired.Load() {
			expired.Store(true)
			stopNew()
			continue
		}
		readCtx := acceptCtx
		if !expired.Load() {
			readCtx = newStreamCtx
		}
		stream, err := session.AcceptStream(readCtx)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, muxsession.ErrClosed) {
				return nil
			}
			if newStreamCtx.Err() != nil && !expired.Load() {
				expired.Store(true)
				continue
			}
			if acceptCtx.Err() != nil {
				graceful = true
				return nil
			}
			return err
		}
		if expired.Load() || !bound.ExpiresAt.After(time.Now()) {
			expired.Store(true)
			_ = stream.Reset(0)
			continue
		}
		admission, ok := p.pendingStream("", source.Addr().Unmap())
		if !ok {
			_ = stream.Reset(0)
			continue
		}
		active.Add(1)
		workers.Add(1)
		go func() {
			defer func() {
				if active.Add(-1) == 0 && expired.Load() {
					stopAccept()
				}
				workers.Done()
			}()
			defer admission.close()
			defer stream.Close()
			_ = p.handleStream(ctx, stream, authenticated, bound, source, destination, admission)
		}()
	}
}

func (p *PrivateConnector) refreshRouting(ctx context.Context, lease ingressv1.IngressLease) error {
	p.refresh.Lock()
	defer p.refresh.Unlock()
	key := fmt.Sprintf("%s/%s/%d", lease.IngressId, lease.IngressRunId, lease.IngressLeaseRevision)
	if p.leaseID != key {
		p.config.Routing.Clear()
		p.leaseID = key
	}
	if _, initialized := p.config.Routing.Revision(); !initialized {
		snapshot, err := p.config.Control.GetPrivateServiceSnapshot(ctx, lease.IngressId, ingressv1.GetPrivateServiceSnapshotParams{
			IngressRunId: lease.IngressRunId, IngressLeaseRevision: lease.IngressLeaseRevision,
		})
		if err != nil {
			return err
		}
		if err := p.config.Routing.ApplySnapshot(snapshot, time.Now()); err != nil {
			return err
		}
	}
	for range 4 {
		after, _ := p.config.Routing.Revision()
		page, err := p.config.Control.GetPrivateServiceEvents(ctx, lease.IngressId, ingressv1.GetPrivateServiceEventsParams{
			IngressRunId: lease.IngressRunId, IngressLeaseRevision: lease.IngressLeaseRevision, After: after,
		})
		if err != nil {
			p.config.Routing.Clear()
			return err
		}
		if err := p.config.Routing.ApplyEvents(after, page, time.Now()); err != nil {
			p.config.Routing.Clear()
			return err
		}
		if len(page.Entries) < 256 {
			current, err := p.lease(time.Now())
			if err != nil || !samePrivateLease(current, lease) {
				p.config.Routing.Clear()
				return ErrPrivateAdmission
			}
			return nil
		}
	}
	p.config.Routing.Clear()
	return ErrPrivateRoutingStale
}

func (p *PrivateConnector) handleStream(ctx context.Context, visitor muxsession.Stream, lease ingressv1.IngressLease, bound ingressv1.PrivateConnectorSessionResult,
	source, destination netip.AddrPort, admission *privateStreamAdmission) (retErr error) {
	if !bound.ExpiresAt.After(time.Now()) {
		return ErrPrivateAdmission
	}
	deadline := time.Now().Add(p.config.PendingTimeout)
	if err := visitor.SetDeadline(deadline); err != nil {
		return err
	}
	entry, err := tunnelv1.ReadPrivateVisitorEntry(visitor)
	if err != nil {
		return ErrPrivateAdmission
	}
	ctx = observability.ExtractWireTrace(ctx, entry.TraceContext)
	ctx, finishConnection := observability.Start(ctx, "ingress.private_visitor_connection")
	defer func() { finishConnection(retErr) }()
	visitorID, err := opaqueid.New(opaqueid.VisitorConnectionPrefix)
	if err != nil {
		return err
	}
	audit, auditErr := serviceaudit.NewPrivateSessionDenial(bound, visitorID)
	auditOpened := false
	defer func() {
		if !auditOpened && auditErr == nil {
			// the denial happened after the entry was read, not when its
			// session was bound or its stream admission was requested.
			audit.OccurredAt = time.Time{}
			serviceaudit.Emit(p.config.AuditSink, audit)
		}
	}()
	if !bound.ExpiresAt.After(time.Now()) || entry.RunNumber > uint64(^uint64(0)>>1) {
		return ErrPrivateAdmission
	}
	if !admission.selectService(entry.PrivateServiceID) {
		audit.Reason = "capacity"
		return ErrPrivateAdmission
	}
	current, err := p.lease(time.Now())
	if err != nil || !samePrivateLease(current, lease) {
		return ErrPrivateAdmission
	}
	streamCtx, stop := context.WithDeadline(ctx, deadline)
	defer stop()
	claimed, err := p.config.Control.AuthorizePrivateServiceStream(streamCtx, lease.IngressId, ingressv1.PrivateServiceStreamClaim{
		IngressRunId: lease.IngressRunId, IngressLeaseRevision: lease.IngressLeaseRevision,
		PrivateServiceId: entry.PrivateServiceID, PrivateRunId: entry.PrivateRunID, RunNumber: int64(entry.RunNumber),
		ConnectorSessionId: bound.ConnectorSessionId, ObservedSourceIp: source.Addr().Unmap().String(), VisitorConnectionId: visitorID,
	})
	if err != nil {
		return err
	}
	claimedAt := time.Now()
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), p.config.RecheckTimeout)
		defer cancel()
		_ = p.config.Control.ClosePrivateServiceStream(closeCtx, lease.IngressId, visitorID, ingressv1.ClosePrivateServiceStreamJSONRequestBody{
			IngressRunId: lease.IngressRunId, IngressLeaseRevision: lease.IngressLeaseRevision, ConnectorSessionId: bound.ConnectorSessionId})
	}()
	if claimed.PrivateServiceId != entry.PrivateServiceID || claimed.PrivateRunId != entry.PrivateRunID || !visitorsubject.Same(claimed.Subject, bound.Subject) || claimed.GrantRevision < 1 ||
		claimed.RunNumber != int64(entry.RunNumber) || claimed.ConnectorSessionId != bound.ConnectorSessionId ||
		claimed.ObservedSourceIp != source.Addr().Unmap().String() ||
		claimed.VisitorConnectionId != visitorID || !claimed.ExpiresAt.After(time.Now()) ||
		!claimed.ValidUntil.After(time.Now()) || claimed.ValidUntil.After(claimedAt.Add(2*time.Minute+time.Second)) {
		return ErrPrivateAdmission
	}
	audit, auditErr = serviceaudit.NewPrivateStreamObservation(bound, claimed, "connection.open", "denied", "authorization")
	if err := p.refreshRouting(streamCtx, lease); err != nil {
		audit.Outcome, audit.Reason = "failed", "unavailable"
		return err
	}
	projection, ok := p.config.Routing.Lookup(entry.PrivateServiceID, entry.PrivateRunID, int64(entry.RunNumber), time.Now())
	if !ok {
		return ErrPrivateAdmission
	}
	if !bound.ExpiresAt.After(time.Now()) || !admission.promote() {
		audit.Reason = "capacity"
		return ErrPrivateAdmission
	}
	accepted := tunnelv1.PrivateVisitorAccepted{ProtocolVersion: tunnelv1.Version, Kind: "private_visitor_accepted",
		ConnectorSessionID: bound.ConnectorSessionId,
		SourceIP:           claimed.ObservedSourceIp, VisitorConnectionID: visitorID}
	accepted.Subject, _ = visitorsubject.Parse(claimed.Subject)
	accepted.GrantRevision = uint64(claimed.GrantRevision)
	proxy, err := proxyproto.Encode(proxyproto.Header{Source: source, Destination: destination})
	if err != nil {
		return err
	}
	first := int((p.nextRelay.Add(1) - 1) % uint64(len(*projection.ConnectedRelays)))
	for attempt := range *projection.ConnectedRelays {
		relay := (*projection.ConnectedRelays)[(first+attempt)%len(*projection.ConnectedRelays)]
		if !relay.LeaseExpiresAt.After(time.Now()) || !claimed.ExpiresAt.After(time.Now()) {
			continue
		}
		header := tunnelv1.PrivateForwardingHeader{PrivateStreamHeader: tunnelv1.PrivateStreamHeader{
			ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.PrivateForwardingStream,
			PrivateServiceID: entry.PrivateServiceID, PrivateRunID: entry.PrivateRunID, RunNumber: entry.RunNumber,
			Connector: &tunnelv1.ConnectorAdmission{SessionID: bound.ConnectorSessionId, Subject: accepted.Subject, GrantRevision: uint64(claimed.GrantRevision)}, SourceIP: claimed.ObservedSourceIp,
			VisitorConnectionID: visitorID, PublisherConnectionID: relay.PublisherConnectionId,
			ConnectionAssignmentRevision: uint64(relay.ConnectionAssignmentRevision),
			ExpiresAt:                    claimed.ExpiresAt,
		}, ConnectionSlot: uint8(relay.ConnectionSlot), RelayServiceID: relay.RelayServiceId,
			RelayID: relay.RelayId, RelayRunID: relay.RelayRunId, RelayLeaseRevision: uint64(relay.RelayLeaseRevision), LeaseExpiresAt: relay.LeaseExpiresAt}
		if err := header.Validate(); err != nil {
			return err
		}
		candidate, err := p.openPrivateRelay(streamCtx, relay, header, proxy, deadline)
		if err != nil {
			continue
		}
		if !claimed.ValidUntil.After(time.Now()) {
			_ = candidate.Close()
			return ErrPrivateAdmission
		}
		accepted.PublisherConnectionID, accepted.ConnectionAssignmentRevision = relay.PublisherConnectionId, uint64(relay.ConnectionAssignmentRevision)
		if err := tunnelv1.WritePrivateVisitorAccepted(visitor, accepted); err != nil {
			_ = candidate.Close()
			return err
		}
		if err := visitor.SetDeadline(time.Time{}); err != nil {
			_ = candidate.Close()
			return err
		}
		if err := candidate.SetDeadline(time.Time{}); err != nil {
			_ = candidate.Close()
			return err
		}
		defer candidate.Close()
		// after the first inner-TLS visitor byte reaches a relay, copy errors
		// terminate this stream. never try another relay or replay its admission.
		auditOpened = true
		audit.Outcome, audit.Reason = "allowed", ""
		audit.OccurredAt = time.Time{}
		if auditErr == nil {
			serviceaudit.Emit(p.config.AuditSink, audit)
		}
		err = p.copyLivePrivateVisitor(ctx, visitor, candidate, lease, bound, claimed, source, claimedAt)
		outcome, reason := "closed", "closed"
		if err != nil {
			outcome, reason = "failed", "authorization"
		}
		if closed, auditErr := serviceaudit.NewPrivateStreamObservation(bound, claimed, "connection.close", outcome, reason); auditErr == nil {
			serviceaudit.Emit(p.config.AuditSink, closed)
		}
		return err
	}
	audit.Outcome, audit.Reason = "failed", "forwarding"
	return ErrPrivateAdmission
}

func writePrivateProxy(conn net.Conn, header []byte) error {
	for len(header) != 0 {
		n, err := conn.Write(header)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(header) {
			return io.ErrShortWrite
		}
		header = header[n:]
	}
	return nil
}
