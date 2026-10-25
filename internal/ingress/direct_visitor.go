package ingress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"sync/atomic"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// directCandidates uses the trusted socket destination and prepared facts only.
// conflicting live port owners fail closed while background state catches up.
func (p *Connector) directCandidates(port uint16) []*preparedVisitorRun {
	p.mu.Lock()
	runs := make([]*preparedVisitorRun, 0, len(p.prepared))
	for _, run := range p.prepared {
		runs = append(runs, run)
	}
	p.mu.Unlock()
	var candidates []*preparedVisitorRun
	service := ""
	for _, run := range runs {
		view, enabled, _ := run.policy.lease.Current()
		if !enabled || !view.Public || view.Port != port {
			continue
		}
		if service != "" && service != view.Scope.ID {
			return nil
		}
		service = view.Scope.ID
		if _, ready := p.ServiceRoute(service, run.capacity.body.RunId, run.capacity.body.RunNumber, time.Now()); ready {
			candidates = append(candidates, run)
		}
	}
	// stable run ordering does not reserve anything. capacity below chooses an
	// available local allocation without moving an already committed connection.
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].capacity.body.RunNumber < candidates[j].capacity.body.RunNumber
	})
	return candidates
}

// DirectServiceReady reports locally prepared direct transport capacity. it
// grants no permission and never starts preparation on behalf of a visitor.
func (p *Connector) DirectServiceReady(port uint16) bool {
	for _, run := range p.directCandidates(port) {
		run.capacity.mu.Lock()
		ready := run.capacity.ready
		run.capacity.mu.Unlock()
		if ready {
			return true
		}
	}
	return false
}

// AcceptDirect selects by the trusted destination port and carries visitor TLS
// unchanged. a verified publisher notification promotes bounded pending work.
func (p *Connector) AcceptDirect(ctx context.Context, connection net.Conn, source, destination netip.AddrPort) (retErr error) {
	ctx, finishConnection := observability.Start(ctx, "ingress.direct_visitor_connection")
	defer func() { finishConnection(retErr) }()
	if connection == nil || !validPrivateSocketPair(source, destination) {
		return ErrServiceAdmission
	}
	release, ok := p.acquireSession()
	if !ok {
		return ErrServiceAdmission
	}
	defer release()
	admission, ok := p.pendingStream("", source.Addr().Unmap())
	if !ok {
		return ErrServiceAdmission
	}
	defer admission.close()
	lease, err := p.lease(time.Now())
	if err != nil {
		return err
	}
	visitor, err := opaqueid.New(opaqueid.VisitorConnectionPrefix)
	if err != nil {
		return err
	}
	ctx = observability.WithVisitor(ctx, visitor)
	live, cancel := context.WithCancel(ctx)
	defer cancel()
	pending := &pendingDirectConn{Conn: connection, ctx: live, promoted: make(chan struct{})}
	pending.upload.Store(64 << 10)
	pending.download.Store(128 << 10)
	deadline := time.Now().Add(p.config.PendingTimeout)
	timer := time.AfterFunc(time.Until(deadline), cancel)
	defer timer.Stop()
	closed := make(chan struct{})
	stop := context.AfterFunc(live, func() { _ = connection.Close(); close(closed) })
	defer func() {
		if !stop() {
			<-closed
		}
	}()
	for _, run := range p.directCandidates(destination.Port()) {
		reservation, guard, err := run.reserve(visitor, source.Addr().Unmap(), cancel)
		if err != nil {
			continue
		}
		defer reservation.Close()
		defer guard.Close()
		view, enabled, _ := run.policy.lease.Current()
		projection, ready := p.ServiceRoute(view.Scope.ID, run.capacity.body.RunId, run.capacity.body.RunNumber, time.Now())
		if !enabled || !view.Public || view.Port != destination.Port() || !ready || !admission.selectService(view.Scope.ID) {
			return ErrServiceAdmission
		}
		audit := serviceaudit.Observation{ServiceID: projection.ServiceId, ServiceKind: "service", RunID: *projection.ServiceRunId, RunNumber: *projection.RunNumber, StreamAllocationID: reservation.header.AllocationID,
			VisitorConnectionID: visitor, SourceIP: source.Addr().Unmap().String(), EventType: "connection.open", Outcome: "denied", Reason: "authorization"}
		defer func() {
			if pending.authorized.Load() {
				audit.EventType, audit.Outcome, audit.Reason = "connection.close", "closed", "closed"
				if retErr != nil {
					audit.Outcome, audit.Reason = "failed", "forwarding"
				}
			}
			serviceaudit.Emit(p.config.AuditSink, audit)
		}()
		proxy, err := proxyproto.Encode(proxyproto.Header{Source: source, Destination: destination})
		if err != nil {
			return err
		}
		setup, finish := context.WithDeadline(live, deadline)
		defer finish()
		until := privateMinTime(view.ValidUntil, privateMinTime(projection.ExpiresAt, lease.LeaseExpiresAt))
		relays := *projection.ConnectedRelays
		first := int((p.nextRelay.Add(1) - 1) % uint64(len(relays)))
		for attempt := range relays {
			relay := relays[(first+attempt)%len(relays)]
			header := tunnelv1.ServiceForwardingHeader{ServiceStreamHeader: tunnelv1.ServiceStreamHeader{
				ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.ServiceForwardingStream, ServiceID: projection.ServiceId, ServiceRunID: *projection.ServiceRunId, RunNumber: uint64(*projection.RunNumber),
				Direct:   &tunnelv1.DirectAdmission{IngressID: lease.IngressId, IngressRunID: lease.IngressRunId, IngressLeaseRevision: uint64(lease.IngressLeaseRevision), DestinationPort: destination.Port()},
				SourceIP: source.Addr().Unmap().String(), VisitorConnectionID: visitor, PublisherConnectionID: relay.PublisherConnectionId, ConnectionAssignmentRevision: uint64(relay.ConnectionAssignmentRevision), ExpiresAt: until, Reservation: reservation.header,
			}, IngressRegion: lease.Region, ConnectionSlot: uint8(relay.ConnectionSlot), RelayServiceID: relay.RelayServiceId, RelayID: relay.RelayId, RelayRunID: relay.RelayRunId, RelayLeaseRevision: uint64(relay.RelayLeaseRevision), LeaseExpiresAt: relay.LeaseExpiresAt}
			events := &tunnel.ReturnEvents{Promoted: func(promoted tunnelv1.AdmissionHeader) error {
				current, err := p.liveLease(time.Now())
				fresh, enabled, _ := run.policy.lease.Current()
				want := header.Admission()
				want.Visitor = promoted.Visitor
				if err != nil || !samePrivateLease(current, lease) || live.Err() != nil || !promoted.Visitor.Valid() || promoted != want || pending.authorized.Load() ||
					!enabled || !fresh.Public || fresh.Port != destination.Port() || fresh.MetadataRevision != view.MetadataRevision || !timer.Stop() || !admission.promote() {
					return ErrServiceAdmission
				}
				pending.authorized.Store(true)
				close(pending.promoted)
				audit.VisitorReference = promoted.Visitor
				allowed := audit
				allowed.Outcome, allowed.Reason = "allowed", ""
				serviceaudit.Emit(p.config.AuditSink, allowed)
				return nil
			}}
			attemptCtx, stopAttempt := backendAttemptContext(setup, len(relays)-attempt)
			backend, err := p.openPrivateRelay(attemptCtx, relay, header, proxy, deadline, events)
			stopAttempt()
			if err != nil {
				var opening *tunnel.OpeningError
				if errors.As(err, &opening) && opening.Committed {
					return err
				}
				continue
			}
			defer backend.Close()
			if err := backend.SetDeadline(time.Time{}); err != nil {
				return err
			}
			if err := connection.SetDeadline(time.Time{}); err != nil {
				return err
			}
			// native server-first bytes also commit to this exact target. copy errors
			// never select another run or replay the original visitor connection.
			return copyLiveNativeVisitor(live, pending, backend)
		}
		return ErrServiceAdmission
	}
	return ErrServiceAdmission
}

func (p *Connector) openPrivateRelay(ctx context.Context, relay ingressv1.ServiceRelay, header tunnelv1.ServiceForwardingHeader, proxy []byte, deadline time.Time, events *tunnel.ReturnEvents) (net.Conn, error) {
	if header.Validate() != nil {
		return nil, ErrServiceAdmission
	}
	connection, err := p.config.Forwarder.OpenPrivate(ctx, relay, header, events)
	if err != nil {
		return nil, err
	}
	setup, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	var written int64
	if header.Direct != nil {
		// a complete direct PROXY header can start server-first target work.
		// an uncertain completion cannot open a second target through another relay.
		written, err = writeSetup(setup, connection, nil, proxy)
	} else {
		_, err = writeSetup(setup, connection, proxy, nil)
	}
	if err != nil {
		failure := errors.Join(err, connection.Close())
		if header.Direct != nil && written == int64(len(proxy)) {
			failure = &tunnel.OpeningError{Committed: true, Err: failure}
		}
		return nil, failure
	}
	return connection, nil
}

type pendingDirectConn struct {
	net.Conn
	ctx              context.Context
	promoted         chan struct{}
	authorized       atomic.Bool
	upload, download atomic.Int64
}

func (c *pendingDirectConn) CloseWrite() error {
	if closer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return errors.ErrUnsupported
}

func (c *pendingDirectConn) Read(b []byte) (int, error) {
	if !c.authorized.Load() {
		remaining := c.upload.Load()
		if remaining <= 0 {
			if err := c.waitPromotion(); err != nil {
				return 0, err
			}
		} else {
			b = b[:min(int64(len(b)), remaining)]
		}
	}
	n, err := c.Conn.Read(b)
	c.upload.Add(-int64(n))
	return n, err
}

func (c *pendingDirectConn) Write(b []byte) (int, error) {
	written := 0
	for len(b) > 0 {
		part := b
		if !c.authorized.Load() {
			remaining := c.download.Load()
			if remaining <= 0 {
				if err := c.waitPromotion(); err != nil {
					return written, err
				}
			} else {
				part = b[:min(int64(len(b)), remaining)]
			}
		}
		n, err := c.Conn.Write(part)
		c.download.Add(-int64(n))
		written += n
		b = b[n:]
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

func (c *pendingDirectConn) waitPromotion() error {
	select {
	case <-c.promoted:
		return nil
	case <-c.ctx.Done():
		return context.Cause(c.ctx)
	}
}
