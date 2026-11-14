package ingress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/policy/serviceendpoint"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/internal/transport/streamcopy"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// AcceptPublic selects HTTP by inspected hostname on 443 and other protocols by
// trusted destination port. initial contains already-inspected visitor bytes,
// absent from connection. publisher authentication promotes a bounded connection.
func (p *PublicServices) AcceptPublic(ctx context.Context, connection net.Conn, source, destination netip.AddrPort, hostname string, initial []byte) (retErr error) {
	ctx, finishConnection := observability.Start(ctx, "ingress.public_service_visitor_connection")
	defer func() { finishConnection(retErr) }()
	outcome := observability.VisitorLookupMissing
	if p.config.Metrics != nil {
		defer func() { p.config.Metrics.ObserveVisitor(outcome) }()
	}
	control := p.config.Control
	if control == nil || connection == nil || !validPrivateSocketPair(source, destination) {
		return ErrServiceAdmission
	}
	if destination.Port() == 443 {
		if !serviceendpoint.Valid("http", hostname, 443, true) {
			return ErrServiceAdmission
		}
	} else if destination.Port() < 1024 || hostname != "" {
		return ErrServiceAdmission
	}
	ctx, release, ok := p.acquireSession(ctx, connection)
	if !ok {
		outcome = observability.VisitorCapacityDenied
		return ErrServiceAdmission
	}
	defer release()
	admission, ok := p.pendingStream("", source.Addr().Unmap())
	if !ok {
		outcome = observability.VisitorCapacityDenied
		return ErrServiceAdmission
	}
	defer admission.close()
	lease, err := p.lease(time.Now())
	if err != nil {
		outcome = observability.VisitorLookupUnavailable
		return err
	}
	visitor, err := opaqueid.New(opaqueid.VisitorConnectionPrefix)
	if err != nil {
		return err
	}
	lookup := ingressv1.PublicServiceVisitorLookup{IngressRunId: lease.IngressRunId, IngressLeaseRevision: lease.IngressLeaseRevision, VisitorConnectionId: visitor}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = control.ClosePublicServiceVisitor(cleanup, lease.IngressId, lookup)
	}()
	setup, finish := context.WithTimeout(ctx, p.config.PendingTimeout)
	defer finish()
	stopSetup := context.AfterFunc(p.admissions, finish)
	defer stopSetup()
	claim := ingressv1.PublicServiceVisitorClaim{IngressRunId: lease.IngressRunId, IngressLeaseRevision: lease.IngressLeaseRevision, IngressPoolId: p.config.IngressPoolID, DestinationPort: int(destination.Port()), ObservedSourceIp: source.Addr().Unmap().String(), VisitorConnectionId: visitor}
	if hostname != "" {
		claim.Hostname = &hostname
	}
	claimed, err := control.AdmitPublicServiceVisitor(setup, lease.IngressId, claim)
	if err != nil {
		return err
	}
	current, leaseErr := p.lease(time.Now())
	if leaseErr != nil || !samePrivateLease(current, lease) || claimed.VisitorConnectionId != visitor || validatePublicServiceAdmission(claimed, time.Now()) != nil || !admission.selectService(claimed.ServiceId) {
		outcome = observability.VisitorInvalidProjection
		return ErrServiceAdmission
	}
	outcome = observability.VisitorOpenFailed
	audit := serviceaudit.Observation{ServiceID: claimed.ServiceId, ServiceKind: "service", RunID: claimed.ServiceRunId, RunNumber: claimed.RunNumber, VisitorConnectionID: visitor, SourceIP: source.Addr().Unmap().String(), EventType: "connection.open", Outcome: "denied", Reason: "authorization"}
	var opened atomic.Bool
	defer func() {
		if opened.Load() {
			audit.EventType, audit.Outcome, audit.Reason = "connection.close", "closed", "closed"
			if retErr != nil {
				audit.Outcome, audit.Reason = "failed", "forwarding"
			}
			if errors.Is(retErr, ErrServiceAdmission) {
				audit.Outcome, audit.Reason = "denied", "authorization"
			}
		}
		serviceaudit.Emit(p.config.AuditSink, audit)
	}()
	onAuthorized := func() {
		allowed := audit
		allowed.Outcome, allowed.Reason = "allowed", ""
		serviceaudit.Emit(p.config.AuditSink, allowed)
		opened.Store(true)
	}
	proxy, err := proxyproto.Encode(proxyproto.Header{Source: source, Destination: destination})
	if err != nil {
		return err
	}
	deadline, _ := setup.Deadline()
	deadline = privateMinTime(deadline, claimed.ExpiresAt)
	first := int((p.nextRelay.Add(1) - 1) % uint64(len(claimed.ConnectedRelays)))
	var openingErr error
	openingStarted := time.Now()
	openingObserved := false
	defer func() {
		if !openingObserved && p.config.Metrics != nil {
			p.config.Metrics.ObserveVisitorOpen(false, time.Since(openingStarted))
		}
	}()
	for attempt := range claimed.ConnectedRelays {
		relay := claimed.ConnectedRelays[(first+attempt)%len(claimed.ConnectedRelays)]
		header := tunnelv1.ServiceForwardingHeader{ServiceStreamHeader: tunnelv1.ServiceStreamHeader{
			ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.ServiceForwardingStream, ServiceID: claimed.ServiceId, ServiceRunID: claimed.ServiceRunId, RunNumber: uint64(claimed.RunNumber),
			PublicService: &tunnelv1.PublicServiceAdmission{IngressID: lease.IngressId, IngressRunID: lease.IngressRunId, IngressLeaseRevision: uint64(lease.IngressLeaseRevision), DestinationPort: destination.Port()},
			SourceIP:      source.Addr().Unmap().String(), VisitorConnectionID: visitor, PublisherConnectionID: relay.PublisherConnectionId, ConnectionAssignmentRevision: uint64(relay.ConnectionAssignmentRevision), ExpiresAt: claimed.ExpiresAt,
		}, ConnectionSlot: uint8(relay.ConnectionSlot), RelayServiceID: relay.RelayServiceId, RelayID: relay.RelayId, RelayRunID: relay.RelayRunId, RelayLeaseRevision: uint64(relay.RelayLeaseRevision), LeaseExpiresAt: relay.LeaseExpiresAt}
		attemptCtx, stopAttempt := backendAttemptContext(setup, len(claimed.ConnectedRelays)-attempt)
		attemptStarted := time.Now()
		backend, err := p.openPrivateRelay(attemptCtx, relay, header, proxy, initial, deadline)
		stopAttempt()
		if p.config.Observer != nil {
			duration := time.Since(attemptStarted)
			p.config.Observer.ObserveOperationContext(ctx, observability.OpIngressBackendAttempt, err, duration)
			if attempt != 0 {
				p.config.Observer.ObserveOperationContext(ctx, observability.OpIngressFallback, err, duration)
			}
		}
		if err != nil {
			openingErr = err
			var opening *tunnel.OpeningError
			if errors.As(err, &opening) && opening.Committed {
				outcome = observability.VisitorCommittedFailed
				if p.config.Metrics != nil {
					p.config.Metrics.ObserveRelayAttempt(strconv.Itoa(relay.ConnectionSlot), observability.RelayAttemptCommittedFailed)
					p.config.Metrics.AddForwardedBytes("visitor_to_publisher", opening.VisitorBytes)
				}
				return err
			}
			if p.config.Metrics != nil {
				p.config.Metrics.ObserveRelayAttempt(strconv.Itoa(relay.ConnectionSlot), observability.RelayAttemptOpenFailed)
			}
			continue
		}
		if p.config.Metrics != nil {
			p.config.Metrics.ObserveRelayAttempt(strconv.Itoa(relay.ConnectionSlot), observability.RelayAttemptCommitted)
			p.config.Metrics.AddForwardedBytes("visitor_to_publisher", int64(len(initial)))
		}
		if len(initial) != 0 {
			outcome = observability.VisitorCommittedFailed
		}
		if err = backend.SetDeadline(time.Time{}); err != nil {
			return errors.Join(err, backend.Close())
		}
		if err = connection.SetDeadline(time.Time{}); err != nil {
			return errors.Join(err, backend.Close())
		}
		openingObserved = true
		if p.config.Metrics != nil {
			p.config.Metrics.ObserveVisitorOpen(true, time.Since(openingStarted))
		}
		// copying the first application protocol byte commits to this run. failures
		// after this point close the connection, including server-first MySQL.
		live, cancel := context.WithCancel(ctx)
		defer cancel()
		pending := &pendingPublicServiceConn{Conn: connection, ctx: live, promoted: make(chan struct{})}
		pending.upload.Store((64 << 10) - int64(len(initial)))
		pending.download.Store(128 << 10)
		done := make(chan struct{})
		var guardErr error
		go func() {
			defer close(done)
			defer cancel()
			guardErr = p.guardPublicServiceVisitor(live, control, lease, lookup, claimed.ExpiresAt, pending, admission, onAuthorized)
			guardErr = errors.Join(guardErr, connection.Close(), backend.Close())
		}()
		_, finishForward := observability.Start(ctx, "ingress.forward_connector_visitor")
		copied, err := streamcopy.Copy(pending, backend)
		finishForward(err)
		cancel()
		<-done
		if p.config.Metrics != nil {
			p.config.Metrics.AddForwardedBytes("visitor_to_publisher", copied.LeftToRight)
			p.config.Metrics.AddForwardedBytes("publisher_to_visitor", copied.RightToLeft)
		}
		if failure.Only(guardErr, context.Canceled) {
			guardErr = nil
		}
		result := errors.Join(err, guardErr)
		outcome = observability.VisitorForwarded
		if result != nil {
			outcome = observability.VisitorCommittedFailed
		}
		return result
	}
	return errors.Join(ErrServiceAdmission, openingErr)
}

// public service admission uses the claim immediately, rather than installing history.
// every included relay and the claim itself must still be current.
func validatePublicServiceAdmission(p ingressv1.PublicServiceVisitorAdmission, now time.Time) error {
	if !opaqueid.Valid(p.ServiceId, opaqueid.ServicePrefix) || !opaqueid.Valid(p.ServiceRunId, opaqueid.ServiceRunPrefix) || p.RunNumber < 1 || !p.ExpiresAt.After(now) || len(p.ConnectedRelays) < 1 || len(p.ConnectedRelays) > 2 {
		return ErrServiceAdmission
	}
	services, slots := make(map[string]bool, 2), make(map[int]bool, 2)
	for _, relay := range p.ConnectedRelays {
		if !opaqueid.Valid(relay.PublisherConnectionId, opaqueid.PublisherConnectionPrefix) || relay.ConnectionSlot < 0 || relay.ConnectionSlot > 1 || relay.ConnectionAssignmentRevision < 1 || relay.RelayLeaseRevision < 1 || relay.RelayServiceId == "" || relay.RelayId == "" || !opaqueid.Valid(relay.RelayRunId, opaqueid.RelayRunPrefix) || !relay.LeaseExpiresAt.After(now) || services[relay.RelayServiceId] || slots[relay.ConnectionSlot] {
			return ErrServiceAdmission
		}
		if _, _, err := net.SplitHostPort(relay.InternalRelayAddress); err != nil {
			return ErrServiceAdmission
		}
		services[relay.RelayServiceId], slots[relay.ConnectionSlot] = true, true
	}
	return nil
}

func (p *PublicServices) openPrivateRelay(ctx context.Context, relay ingressv1.ServiceRelay, header tunnelv1.ServiceForwardingHeader, proxy, initial []byte, deadline time.Time) (net.Conn, error) {
	if header.Validate() != nil {
		return nil, ErrServiceAdmission
	}
	connection, err := p.config.Forwarder.OpenPrivate(ctx, relay, header)
	if err != nil {
		return nil, err
	}
	connection = p.observeBackend(ctx, connection)
	setup, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	// metadata is retryable, but any inspected visitor byte commits this relay.
	// join setup cancellation before the successful stream enters live copying.
	written, err := writeSetup(setup, connection, proxy, initial)
	if err != nil {
		return nil, &tunnel.OpeningError{Committed: written > 0, VisitorBytes: written, Err: errors.Join(err, connection.Close())}
	}
	return connection, nil
}

func (p *PublicServices) guardPublicServiceVisitor(ctx context.Context, control PublicServiceControl, lease ingressv1.IngressLease, lookup ingressv1.PublicServiceVisitorLookup, deadline time.Time, connection *pendingPublicServiceConn, admission *privateStreamAdmission, onAuthorized func()) error {
	reserved := false
	for {
		current, err := p.liveLease(time.Now())
		if err != nil || !samePrivateLease(current, lease) || !deadline.After(time.Now()) {
			return ErrServiceAdmission
		}
		if current.Draining && current.DrainDeadline != nil {
			deadline = privateMinTime(deadline, *current.DrainDeadline)
		}
		check, finish := context.WithTimeout(ctx, min(p.config.RecheckTimeout, time.Until(deadline)))
		status, err := control.PublicServiceVisitorStatus(check, lease.IngressId, lookup)
		finish()
		if err == nil {
			switch status.State {
			case ingressv1.PublicServiceVisitorPending:
				if connection.authorized.Load() {
					return ErrServiceAdmission
				}
				deadline = privateMinTime(deadline, status.ValidUntil)
			case ingressv1.PublicServiceVisitorAuthenticated, ingressv1.PublicServiceVisitorAllowed:
				if !status.ValidUntil.After(time.Now()) {
					return ErrServiceAdmission
				}
				if !reserved {
					if !admission.promote() {
						return ErrServiceAdmission
					}
					reserved = true
				}
				if status.State == ingressv1.PublicServiceVisitorAuthenticated {
					promote, cancel := context.WithTimeout(ctx, min(p.config.RecheckTimeout, time.Until(deadline)))
					err = control.PromotePublicServiceVisitor(promote, lease.IngressId, lookup)
					cancel()
					if err != nil {
						break
					}
				}
				if !connection.authorized.Swap(true) {
					onAuthorized()
					close(connection.promoted)
				}
				deadline = privateMinTime(status.ValidUntil, time.Now().Add(p.config.HardAuthorizationTTL))
			default:
				return ErrServiceAdmission
			}
		}
		interval := 100 * time.Millisecond
		if connection.authorized.Load() {
			interval = p.config.RecheckInterval
		}
		timer := time.NewTimer(privateRecheckDelay(interval, p.config.RecheckTimeout, deadline))
		select {
		case <-ctx.Done():
			timer.Stop()
			return context.Cause(ctx)
		case <-timer.C:
		}
	}
}

type pendingPublicServiceConn struct {
	net.Conn
	ctx              context.Context
	promoted         chan struct{}
	authorized       atomic.Bool
	upload, download atomic.Int64
}

func (c *pendingPublicServiceConn) CloseWrite() error {
	if closer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return errors.ErrUnsupported
}

func (c *pendingPublicServiceConn) Read(b []byte) (int, error) {
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

func (c *pendingPublicServiceConn) Write(b []byte) (int, error) {
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

func (c *pendingPublicServiceConn) waitPromotion() error {
	select {
	case <-c.promoted:
		return nil
	case <-c.ctx.Done():
		return context.Cause(c.ctx)
	}
}
