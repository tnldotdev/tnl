package ingress

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
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
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/proxyproto"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

var ErrPrivateAdmission = errors.New("ingress: private connector admission denied")

type PrivateControl interface {
	ClaimPrivateConnectorSession(context.Context, string, ingressv1.PrivateConnectorSessionClaim) (ingressv1.PrivateConnectorSessionResult, error)
	ClaimPrivateServiceTicket(context.Context, string, ingressv1.PrivateServiceTicketClaim) (ingressv1.PrivateServiceTicketResult, error)
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
	Hostname                                                     string
	TLSConfig                                                    *tls.Config
	Transport                                                    muxsession.TLSYamuxConfig
	Control                                                      PrivateControl
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
	return &PrivateConnector{config: config, services: make(map[string]int), sources: make(map[netip.Addr]int)}, nil
}

func (p *PrivateConnector) lease(now time.Time) (ingressv1.IngressLease, error) {
	lease := p.config.CurrentLease()
	if lease.IngressId == "" || lease.IngressRunId == "" || lease.IngressLeaseRevision < 1 ||
		lease.Draining || !lease.LeaseExpiresAt.After(now) {
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
	if p.sessions >= p.config.MaxSessions {
		return nil, false
	}
	p.sessions++
	return sync.OnceFunc(func() { p.mu.Lock(); p.sessions--; p.mu.Unlock() }), true
}

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
	if connection == nil || !source.Addr().IsValid() || source.Addr().Zone() != "" || !destination.Addr().IsValid() || destination.Port() != 443 {
		return ErrPrivateAdmission
	}
	release, ok := p.acquireSession()
	if !ok {
		return ErrPrivateAdmission
	}
	defer release()
	if _, err := p.lease(time.Now()); err != nil {
		return err
	}
	handshakeCtx, cancel := context.WithTimeout(ctx, p.config.PendingTimeout)
	defer cancel()
	if err := connection.SetDeadline(time.Now().Add(p.config.PendingTimeout)); err != nil {
		return err
	}
	var bound ingressv1.PrivateConnectorSessionResult
	var authenticated ingressv1.IngressLease
	session, err := muxsession.AcceptPrivateTLSYamux(handshakeCtx, connection, p.config.TLSConfig, p.config.Transport, func(reader io.Reader) error {
		secure, ok := reader.(*tls.Conn)
		if !ok || secure.ConnectionState().ServerName != p.config.Hostname {
			return ErrPrivateAdmission
		}
		hello, err := tunnelv1.ReadPrivateConnectorSessionHello(reader)
		if err != nil {
			return err
		}
		lease, err := p.lease(time.Now())
		if err != nil {
			return err
		}
		bound, err = p.config.Control.ClaimPrivateConnectorSession(handshakeCtx, lease.IngressId, ingressv1.PrivateConnectorSessionClaim{
			IngressRunId: lease.IngressRunId, IngressLeaseRevision: lease.IngressLeaseRevision,
			PrivateServiceId: hello.PrivateServiceID, ConnectorSessionId: hello.SessionID,
			SessionCredential: hello.Credential, ObservedSourceIp: source.Addr().Unmap().String(),
		})
		if err != nil {
			return err
		}
		if bound.ConnectorSessionId != hello.SessionID || bound.PrivateServiceId != hello.PrivateServiceID ||
			!opaqueid.Valid(bound.IdentityId, opaqueid.IdentityPrefix) || bound.ObservedSourceIp != source.Addr().Unmap().String() ||
			!bound.ExpiresAt.After(time.Now()) {
			return ErrPrivateAdmission
		}
		authenticated = lease
		return nil
	})
	if err != nil {
		return err
	}
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
		if !graceful {
			_ = session.Close()
		}
		workers.Wait()
		_ = session.Close()
	}()
	if err := connection.SetDeadline(time.Time{}); err != nil {
		return err
	}
	acceptCtx, stopAccept := context.WithCancel(ctx)
	defer stopAccept()
	newStreamCtx, stopNew := context.WithDeadline(acceptCtx, bound.ExpiresAt)
	defer stopNew()
	for {
		if expired.Load() && active.Load() == 0 {
			graceful = true
			return nil
		}
		if current, err := p.lease(time.Now()); err != nil || !samePrivateLease(current, authenticated) {
			return ErrPrivateAdmission
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
		if !bound.ExpiresAt.After(time.Now()) {
			expired.Store(true)
			_ = stream.Reset(0)
			continue
		}
		admission, ok := p.pendingStream(bound.PrivateServiceId, source.Addr().Unmap())
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
	source, destination netip.AddrPort, admission *privateStreamAdmission) error {
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
	if !bound.ExpiresAt.After(time.Now()) || entry.PrivateServiceID != bound.PrivateServiceId || entry.RunNumber > uint64(^uint64(0)>>1) {
		return ErrPrivateAdmission
	}
	current, err := p.lease(time.Now())
	if err != nil || !samePrivateLease(current, lease) {
		return ErrPrivateAdmission
	}
	streamCtx, stop := context.WithDeadline(ctx, deadline)
	defer stop()
	visitorID, err := opaqueid.New(opaqueid.VisitorConnectionPrefix)
	if err != nil {
		return err
	}
	claimed, err := p.config.Control.ClaimPrivateServiceTicket(streamCtx, lease.IngressId, ingressv1.PrivateServiceTicketClaim{
		IngressRunId: lease.IngressRunId, IngressLeaseRevision: lease.IngressLeaseRevision,
		PrivateServiceId: bound.PrivateServiceId, PrivateRunId: entry.PrivateRunID, RunNumber: int64(entry.RunNumber),
		ConnectorSessionId: bound.ConnectorSessionId, Ticket: entry.Ticket, ObservedSourceIp: source.Addr().Unmap().String(), VisitorConnectionId: visitorID,
	})
	if err != nil {
		return err
	}
	claimedAt := time.Now()
	if claimed.PrivateServiceId != bound.PrivateServiceId || claimed.PrivateRunId != entry.PrivateRunID ||
		claimed.RunNumber != int64(entry.RunNumber) || claimed.ConnectorSessionId != bound.ConnectorSessionId ||
		claimed.IdentityId != bound.IdentityId || claimed.ObservedSourceIp != source.Addr().Unmap().String() ||
		claimed.VisitorConnectionId != visitorID || !claimed.ExpiresAt.After(time.Now()) ||
		!claimed.ValidUntil.After(time.Now()) || claimed.ValidUntil.After(claimedAt.Add(2*time.Minute+time.Second)) {
		return ErrPrivateAdmission
	}
	if err := p.refreshRouting(streamCtx, lease); err != nil {
		return err
	}
	projection, ok := p.config.Routing.Lookup(bound.PrivateServiceId, entry.PrivateRunID, int64(entry.RunNumber), time.Now())
	if !ok {
		return ErrPrivateAdmission
	}
	if !bound.ExpiresAt.After(time.Now()) || !admission.promote() {
		return ErrPrivateAdmission
	}
	accepted := tunnelv1.PrivateVisitorAccepted{ProtocolVersion: tunnelv1.Version, Kind: "private_visitor_accepted",
		ConnectorSessionID: bound.ConnectorSessionId, IdentityID: claimed.IdentityId,
		SourceIP: claimed.ObservedSourceIp, VisitorConnectionID: visitorID}
	proxy, err := proxyproto.Encode(proxyproto.Header{Source: source, Destination: destination})
	if err != nil {
		return err
	}
	ticketDigest := sha256.Sum256([]byte(entry.Ticket))
	first := int(time.Now().UnixNano() % int64(len(*projection.ConnectedRelays)))
	for attempt := range *projection.ConnectedRelays {
		relay := (*projection.ConnectedRelays)[(first+attempt)%len(*projection.ConnectedRelays)]
		if !relay.LeaseExpiresAt.After(time.Now()) || !claimed.ExpiresAt.After(time.Now()) {
			continue
		}
		header := tunnelv1.PrivateForwardingHeader{PrivateStreamHeader: tunnelv1.PrivateStreamHeader{
			ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.PrivateForwardingStream,
			PrivateServiceID: bound.PrivateServiceId, PrivateRunID: entry.PrivateRunID, RunNumber: entry.RunNumber,
			ConnectorSessionID: bound.ConnectorSessionId, IdentityID: claimed.IdentityId, SourceIP: claimed.ObservedSourceIp,
			VisitorConnectionID: visitorID, PublisherConnectionID: relay.PublisherConnectionId,
			ConnectionAssignmentRevision: uint64(relay.ConnectionAssignmentRevision), TicketDigest: ticketDigest[:], Nonce: entry.Nonce,
			ExpiresAt: claimed.ExpiresAt,
		}, ConnectionSlot: uint8(relay.ConnectionSlot), RelayServiceID: relay.RelayServiceId,
			RelayID: relay.RelayId, RelayRunID: relay.RelayRunId, RelayLeaseRevision: uint64(relay.RelayLeaseRevision), LeaseExpiresAt: relay.LeaseExpiresAt}
		if err := header.Validate(); err != nil {
			return err
		}
		candidate, err := p.config.Forwarder.OpenPrivate(streamCtx, relay, header)
		if err != nil {
			continue
		}
		if err := candidate.SetDeadline(deadline); err != nil {
			_ = candidate.Close()
			continue
		}
		if err := writePrivateProxy(candidate, proxy); err != nil {
			_ = candidate.Close()
			continue
		}
		if !claimed.ValidUntil.After(time.Now()) {
			_ = candidate.Close()
			return ErrPrivateAdmission
		}
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
		// terminate this stream. never try another relay or reuse its ticket.
		return p.copyLivePrivateVisitor(ctx, visitor, candidate, lease, bound, claimed, source, claimedAt)
	}
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
