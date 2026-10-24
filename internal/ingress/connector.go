package ingress

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/policy/visitorsubject"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

var ErrServiceAdmission = errors.New("ingress: private connector admission denied")

type PrivateControl interface {
	ClaimConnectorSession(context.Context, string, ingressv1.ConnectorSessionClaim) (ingressv1.ConnectorSessionResult, error)
	GetServiceSnapshot(context.Context, string, ingressv1.GetServiceSnapshotParams) (ingressv1.ServiceSnapshot, error)
	GetServiceEvents(context.Context, string, ingressv1.GetServiceEventsParams) (ingressv1.ServiceSnapshot, error)
}

// ServiceForwarder opens an acknowledged, lease-bound internal relay stream.
// it sends the private forwarding sideband to the relay, which must bind the
// publisher stream before returning. ingress alone writes PROXY v2 afterward.
type ServiceForwarder interface {
	OpenPrivate(context.Context, ingressv1.ServiceRelay, tunnelv1.ServiceForwardingHeader, *tunnel.ReturnEvents) (net.Conn, error)
}

type ConnectorConfig struct {
	Report                                                       func(error)
	AuditSink                                                    serviceaudit.Sink
	Hostname                                                     string
	IngressPoolID                                                string
	TLSConfig                                                    *tls.Config
	Transport                                                    muxsession.TLSYamuxConfig
	Control                                                      PrivateControl
	VisitorControl                                               VisitorPreparationControl
	Forwarder                                                    ServiceForwarder
	Routing                                                      *ServiceRoutingTable
	CurrentLease                                                 func() ingressv1.IngressLease
	MaxSessions, MaxPending, MaxServiceStreams, MaxSourceStreams int
	PendingTimeout                                               time.Duration
}

type Connector struct {
	config                    ConnectorConfig
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
	prepared                  map[string]*preparedVisitorRun
	lastPreparationReport     time.Time
	preparationStarted        bool
	stopPreparation           context.CancelFunc
	preparationDone           chan struct{}
}

func NewConnector(config ConnectorConfig) (*Connector, error) {
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
	if config.Transport.MaxIncomingStreams <= 0 || config.Transport.MaxIncomingStreams > config.MaxSourceStreams {
		config.Transport.MaxIncomingStreams = config.MaxSourceStreams
	}
	admissions, stop := context.WithCancel(context.Background())
	if config.IngressPoolID == "" {
		config.IngressPoolID = "ingress-a"
	}
	return &Connector{config: config, services: make(map[string]int), sources: make(map[netip.Addr]int),
		transports: make(map[muxsession.Session]struct{}), prepared: make(map[string]*preparedVisitorRun), admissions: admissions, stopAdmissions: stop, changed: make(chan struct{})}, nil
}

func (p *Connector) lease(now time.Time) (ingressv1.IngressLease, error) {
	if p.admissions.Err() != nil {
		return ingressv1.IngressLease{}, ErrServiceAdmission
	}
	lease, err := p.liveLease(now)
	if err != nil || lease.Draining {
		return ingressv1.IngressLease{}, ErrServiceAdmission
	}
	return lease, nil
}

func (p *Connector) liveLease(now time.Time) (ingressv1.IngressLease, error) {
	lease := p.config.CurrentLease()
	if lease.IngressId == "" || lease.IngressRunId == "" || lease.IngressLeaseRevision < 1 ||
		!lease.LeaseExpiresAt.After(now) {
		p.config.Routing.Clear()
		return ingressv1.IngressLease{}, ErrServiceAdmission
	}
	return lease, nil
}

func samePrivateLease(a, b ingressv1.IngressLease) bool {
	return a.IngressId == b.IngressId && a.IngressRunId == b.IngressRunId &&
		a.IngressLeaseRevision == b.IngressLeaseRevision
}

func (p *Connector) acquireSession() (func(), bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.admissions.Err() != nil || p.sessions >= p.config.MaxSessions {
		return nil, false
	}
	p.sessions++
	return sync.OnceFunc(func() { p.mu.Lock(); p.sessions--; p.notifyLocked(); p.mu.Unlock() }), true
}

func (p *Connector) notifyLocked() { close(p.changed); p.changed = make(chan struct{}) }

func (p *Connector) StopAccepting() { p.stopAdmissions() }

// Drain stops new sessions and admissions while already authorized streams
// remain under their live authorization checks until they finish or time out.
func (p *Connector) Drain(ctx context.Context) error {
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

func (p *Connector) Close() error {
	p.stopAdmissions()
	p.mu.Lock()
	p.closed = true
	stopPreparation, preparationDone := p.stopPreparation, p.preparationDone
	sessions := make([]muxsession.Session, 0, len(p.transports))
	for session := range p.transports {
		sessions = append(sessions, session)
	}
	p.mu.Unlock()
	if stopPreparation != nil {
		stopPreparation()
	}
	var result error
	for _, session := range sessions {
		result = errors.Join(result, session.Close())
	}
	if preparationDone != nil {
		<-preparationDone
	}
	return result
}

func (p *Connector) Load() int64 { p.mu.Lock(); defer p.mu.Unlock(); return int64(p.sessions) }

type privateStreamAdmission struct {
	owner    *Connector
	service  string
	source   netip.Addr
	promoted bool
	closed   bool
}

func (p *Connector) pendingStream(service string, source netip.Addr) (*privateStreamAdmission, bool) {
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
func (p *Connector) Accept(ctx context.Context, connection net.Conn, source, destination netip.AddrPort) error {
	if connection == nil || !validPrivateSocketPair(source, destination) {
		return ErrServiceAdmission
	}
	setup, cancel := context.WithTimeout(ctx, p.config.PendingTimeout)
	defer cancel()
	if err := connection.SetDeadline(time.Now().Add(p.config.PendingTimeout)); err != nil {
		return err
	}
	transport, err := muxsession.AcceptConnectorMuxTLS(setup, connection, p.TransportTLSConfig(), p.config.Transport)
	if err != nil {
		return err
	}
	defer transport.Close()
	if err = connection.SetDeadline(time.Time{}); err != nil {
		return err
	}
	return p.AcceptSession(ctx, transport, source, destination)
}

func (p *Connector) TransportTLSConfig() *tls.Config {
	config := p.config.TLSConfig.Clone()
	config.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if hello.ServerName != p.config.Hostname {
			return nil, ErrServiceAdmission
		}
		return nil, nil
	}
	return config
}

// AcceptQUIC obtains source metadata from the authenticated transport socket.
// the shared infrastructure port is unrelated to a service's identity.
func (p *Connector) AcceptQUIC(ctx context.Context, session muxsession.Session) error {
	connection, ok := session.(muxsession.AcceptedPeer)
	if !ok {
		if session != nil {
			_ = session.Close()
		}
		return ErrServiceAdmission
	}
	source, sourceErr := netip.ParseAddrPort(connection.RemoteAddr().String())
	destination, destinationErr := netip.ParseAddrPort(connection.LocalAddr().String())
	if sourceErr != nil || destinationErr != nil {
		_ = session.Close()
		return ErrServiceAdmission
	}
	return p.AcceptSession(ctx, session, source, destination)
}

func validPrivateSocketPair(source, destination netip.AddrPort) bool {
	return source.IsValid() && destination.IsValid() && source.Port() != 0 && destination.Port() != 0 && source.Addr().Zone() == "" && destination.Addr().Zone() == ""
}

// AcceptSession authenticates the first mux control stream for either QUIC or
// TLS/TCP. the listener supplies socket/verified-PROXY source metadata; no
// connector frame can supply or replace it.
func (p *Connector) AcceptSession(ctx context.Context, transport muxsession.Session, source, destination netip.AddrPort) error {
	if transport == nil || !validPrivateSocketPair(source, destination) {
		if transport != nil {
			_ = transport.Close()
		}
		return ErrServiceAdmission
	}
	defer transport.Close()
	release, ok := p.acquireSession()
	if !ok {
		return ErrServiceAdmission
	}
	defer release()
	p.mu.Lock()
	if p.closed || p.admissions.Err() != nil {
		p.mu.Unlock()
		return ErrServiceAdmission
	}
	p.transports[transport] = struct{}{}
	p.mu.Unlock()
	defer func() { p.mu.Lock(); delete(p.transports, transport); p.mu.Unlock() }()
	if _, err := p.lease(time.Now()); err != nil {
		return err
	}
	handshakeCtx, cancel := context.WithTimeout(ctx, p.config.PendingTimeout)
	defer cancel()
	var bound ingressv1.ConnectorSessionResult
	var authenticated ingressv1.IngressLease
	session, err := tunnel.AcceptConnector(handshakeCtx, transport, func(authCtx context.Context, hello tunnelv1.ConnectorSessionHello) (tunnelv1.ConnectorSessionAccepted, error) {
		lease, err := p.lease(time.Now())
		if err != nil {
			return tunnelv1.ConnectorSessionAccepted{}, err
		}
		bound, err = p.config.Control.ClaimConnectorSession(authCtx, lease.IngressId, ingressv1.ConnectorSessionClaim{
			IngressRunId: lease.IngressRunId, IngressLeaseRevision: lease.IngressLeaseRevision,
			ServiceId: hello.ServiceID, ConnectorSessionId: hello.SessionID,
			SessionCredential: hello.Credential, ObservedSourceIp: source.Addr().Unmap().String(),
			Subject: visitorsubject.Wire(hello.Subject), Nonce: hex.EncodeToString(hello.Nonce), Signature: base64.RawURLEncoding.EncodeToString(hello.Signature),
		})
		if err != nil {
			return tunnelv1.ConnectorSessionAccepted{}, err
		}
		if bound.ConnectorSessionId != hello.SessionID || bound.ServiceId != hello.ServiceID || !visitorsubject.Equal(bound.Subject, hello.Subject) ||
			bound.ObservedSourceIp != source.Addr().Unmap().String() ||
			!bound.ExpiresAt.After(time.Now()) {
			return tunnelv1.ConnectorSessionAccepted{}, ErrServiceAdmission
		}
		// the background owner is already discovering service runs. session
		// startup may wait for it, but stream arrivals cannot initiate fetching.
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for !p.servicePolicyReady(bound.ServiceId, hello.Subject) {
			select {
			case <-authCtx.Done():
				return tunnelv1.ConnectorSessionAccepted{}, context.Cause(authCtx)
			case <-ticker.C:
			}
		}
		authenticated = lease
		return tunnelv1.ConnectorSessionAccepted{ProtocolVersion: tunnelv1.Version, Kind: "connector_session_accepted", ServiceID: bound.ServiceId,
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
			return ErrServiceAdmission
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

func (p *Connector) refreshRouting(ctx context.Context, lease ingressv1.IngressLease) error {
	p.refresh.Lock()
	defer p.refresh.Unlock()
	key := fmt.Sprintf("%s/%s/%d", lease.IngressId, lease.IngressRunId, lease.IngressLeaseRevision)
	if p.leaseID != key {
		p.config.Routing.Clear()
		p.leaseID = key
	}
	if _, initialized := p.config.Routing.Revision(); !initialized {
		snapshot, err := p.config.Control.GetServiceSnapshot(ctx, lease.IngressId, ingressv1.GetServiceSnapshotParams{
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
		page, err := p.config.Control.GetServiceEvents(ctx, lease.IngressId, ingressv1.GetServiceEventsParams{
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
				return ErrServiceAdmission
			}
			return nil
		}
	}
	p.config.Routing.Clear()
	return ErrPrivateRoutingStale
}

func (p *Connector) handleStream(ctx context.Context, visitor muxsession.Stream, lease ingressv1.IngressLease, bound ingressv1.ConnectorSessionResult,
	source, destination netip.AddrPort, admission *privateStreamAdmission) (retErr error) {
	if !bound.ExpiresAt.After(time.Now()) {
		return ErrServiceAdmission
	}
	deadline := time.Now().Add(p.config.PendingTimeout)
	if err := visitor.SetDeadline(deadline); err != nil {
		return err
	}
	entry, initial, err := tunnelv1.ReadConnectorVisitorOpening(visitor)
	if err != nil {
		return ErrServiceAdmission
	}
	ctx = observability.ExtractWireTrace(ctx, entry.TraceContext)
	ctx, finishConnection := observability.Start(ctx, "ingress.connector_visitor_connection")
	defer func() { finishConnection(retErr) }()
	visitorID := entry.VisitorConnectionID
	ctx = observability.WithVisitor(ctx, visitorID)
	observability.Visitor(ctx, visitorID)
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
		return ErrServiceAdmission
	}
	if entry.ServiceID != bound.ServiceId {
		return ErrServiceAdmission
	}
	p.mu.Lock()
	prepared := p.prepared[entry.ServiceRunID]
	p.mu.Unlock()
	if prepared == nil {
		return ErrServiceAdmission
	}
	view, enabled, _ := prepared.policy.lease.Current()
	subject, subjectErr := visitorsubject.Parse(bound.Subject)
	public, keyErr := base64.RawURLEncoding.Strict().DecodeString(entry.Permission.PublicKey)
	signature, signatureErr := base64.RawURLEncoding.Strict().DecodeString(entry.Permission.Signature)
	if !enabled || view.Scope.ID != entry.ServiceID || subjectErr != nil || keyErr != nil || signatureErr != nil {
		return ErrServiceAdmission
	}
	permission, err := visitortoken.VerifyNativeSession(visitortoken.Token(entry.Permission.Token), view, subject, bound.ConnectorSessionId, visitorID, entry.MetadataRevision, initial, public, signature, time.Now())
	if err != nil {
		return ErrServiceAdmission
	}
	ctx, stopNative := context.WithCancel(ctx)
	defer stopNative()
	guard, err := prepared.policy.lease.BindNative(permission, source.Addr().Unmap(), int64(entry.MetadataRevision), stopNative)
	if err != nil {
		return ErrServiceAdmission
	}
	defer guard.Close()
	if err := guard.AllowRenewal(); err != nil {
		return ErrServiceAdmission
	}
	var backendRequests *tunnel.NativeRequestWriter
	request := tunnel.NewNativeRequestReader(visitor, nil, func(proof tunnelv1.NativeVisitorPermission) error {
		view, enabled, _ := prepared.policy.lease.Current()
		public, keyErr := base64.RawURLEncoding.Strict().DecodeString(proof.PublicKey)
		signature, signatureErr := base64.RawURLEncoding.Strict().DecodeString(proof.Signature)
		if !enabled || keyErr != nil || signatureErr != nil {
			return ErrServiceAdmission
		}
		next, err := visitortoken.VerifyNativeRenewalProof(visitortoken.Token(proof.Token), view, subject, bound.ConnectorSessionId, visitorID, entry.MetadataRevision, nil, public, signature, time.Now())
		if err != nil || next.Subject != permission.Subject {
			return ErrServiceAdmission
		}
		if err := guard.Renew(next); err != nil {
			return err
		}
		if backendRequests == nil {
			return ErrServiceAdmission
		}
		return backendRequests.Renew(proof)
	})
	reservation, reservationGuard, err := prepared.reserve(visitorID, source.Addr().Unmap(), stopNative)
	if err != nil {
		return ErrServiceAdmission
	}
	defer reservation.Close()
	defer reservationGuard.Close()
	if !admission.selectService(entry.ServiceID) {
		audit.Reason = "capacity"
		return ErrServiceAdmission
	}
	current, err := p.lease(time.Now())
	if err != nil || !samePrivateLease(current, lease) {
		return ErrServiceAdmission
	}
	streamCtx, stop := context.WithDeadline(ctx, deadline)
	defer stop()
	audit, auditErr = serviceaudit.NewNativeStreamObservation(bound, entry, reservation.header, permission, "connection.open", "denied", "authorization")
	current, err = p.lease(time.Now())
	if err != nil || !samePrivateLease(current, lease) {
		return ErrServiceAdmission
	}
	projection, ok := p.ServiceRoute(entry.ServiceID, entry.ServiceRunID, int64(entry.RunNumber), time.Now())
	if !ok {
		return ErrServiceAdmission
	}
	validUntil, err := guard.Deadline()
	if err != nil {
		return ErrServiceAdmission
	}
	validUntil = privateMinTime(validUntil, projection.ExpiresAt)
	if !bound.ExpiresAt.After(time.Now()) || !admission.promote() {
		audit.Reason = "capacity"
		return ErrServiceAdmission
	}
	proxy, err := proxyproto.Encode(proxyproto.Header{Source: source, Destination: destination})
	if err != nil {
		return err
	}
	first := int((p.nextRelay.Add(1) - 1) % uint64(len(*projection.ConnectedRelays)))
	for attempt := range *projection.ConnectedRelays {
		relay := (*projection.ConnectedRelays)[(first+attempt)%len(*projection.ConnectedRelays)]
		if !relay.LeaseExpiresAt.After(time.Now()) || !validUntil.After(time.Now()) {
			continue
		}
		header := tunnelv1.ServiceForwardingHeader{ServiceStreamHeader: tunnelv1.ServiceStreamHeader{
			ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.ServiceForwardingStream,
			ServiceID: entry.ServiceID, ServiceRunID: entry.ServiceRunID, RunNumber: entry.RunNumber,
			Connector: &tunnelv1.ConnectorAdmission{SessionID: bound.ConnectorSessionId, Subject: subject, GrantRevision: uint64(permission.VisitorPolicyRevision)}, SourceIP: bound.ObservedSourceIp,
			VisitorConnectionID: visitorID, PublisherConnectionID: relay.PublisherConnectionId,
			ConnectionAssignmentRevision: uint64(relay.ConnectionAssignmentRevision),
			ExpiresAt:                    validUntil,
			Reservation:                  reservation.header,
		}, ConnectionSlot: uint8(relay.ConnectionSlot), RelayServiceID: relay.RelayServiceId,
			RelayID: relay.RelayId, RelayRunID: relay.RelayRunId, RelayLeaseRevision: uint64(relay.RelayLeaseRevision), LeaseExpiresAt: relay.LeaseExpiresAt}
		if err := header.Validate(); err != nil {
			return err
		}
		attemptCtx, stopAttempt := backendAttemptContext(streamCtx, len(*projection.ConnectedRelays)-attempt)
		candidate, err := p.openPrivateRelay(attemptCtx, relay, header, proxy, deadline, nil)
		stopAttempt()
		if err != nil {
			continue
		}
		if !validUntil.After(time.Now()) {
			_ = candidate.Close()
			return ErrServiceAdmission
		}
		// the exact signed opening reaches the publisher unchanged. native
		// renewals and data stay framed after it until publisher verification.
		var opening bytes.Buffer
		if _, err := tunnelv1.WriteConnectorVisitorOpening(&opening, entry, initial); err != nil {
			_ = candidate.Close()
			return err
		}
		_, openingErr := writeSetup(streamCtx, candidate, opening.Bytes(), nil)
		clear(opening.Bytes())
		if openingErr != nil {
			_ = candidate.Close()
			return openingErr
		}
		backendRequests = tunnel.NewNativeRequestWriter(candidate)
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
		err = copyLiveNativeVisitor(ctx, request, backendRequests)
		outcome, reason := "closed", "closed"
		if err != nil {
			outcome, reason = "failed", "authorization"
		}
		if closed, auditErr := serviceaudit.NewNativeStreamObservation(bound, entry, reservation.header, permission, "connection.close", outcome, reason); auditErr == nil {
			serviceaudit.Emit(p.config.AuditSink, closed)
		}
		return err
	}
	audit.Outcome, audit.Reason = "failed", "forwarding"
	return ErrServiceAdmission
}
