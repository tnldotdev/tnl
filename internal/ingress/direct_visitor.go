package ingress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/internal/transport/streamcopy"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// AcceptDirect selects by the trusted destination port and carries application TLS
// unchanged. publisher authentication promotes a bounded pending connection.
func (p *DirectServices) AcceptDirect(ctx context.Context, connection net.Conn, source, destination netip.AddrPort) (retErr error) {
	ctx, finishConnection := observability.Start(ctx, "ingress.direct_visitor_connection")
	defer func() { finishConnection(retErr) }()
	control := p.config.Control
	if control == nil || connection == nil || !validPrivateSocketPair(source, destination) {
		return ErrServiceAdmission
	}
	ctx, release, ok := p.acquireSession(ctx, connection)
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
	lookup := ingressv1.DirectServiceVisitorLookup{IngressRunId: lease.IngressRunId, IngressLeaseRevision: lease.IngressLeaseRevision, VisitorConnectionId: visitor}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = control.CloseDirectServiceVisitor(cleanup, lease.IngressId, lookup)
	}()
	setup, finish := context.WithTimeout(ctx, p.config.PendingTimeout)
	defer finish()
	stopSetup := context.AfterFunc(p.admissions, finish)
	defer stopSetup()
	claimed, err := control.AdmitDirectServiceVisitor(setup, lease.IngressId, ingressv1.DirectServiceVisitorClaim{IngressRunId: lease.IngressRunId, IngressLeaseRevision: lease.IngressLeaseRevision, IngressPoolId: p.config.IngressPoolID, DestinationPort: int(destination.Port()), ObservedSourceIp: source.Addr().Unmap().String(), VisitorConnectionId: visitor})
	if err != nil {
		return err
	}
	current, leaseErr := p.lease(time.Now())
	if leaseErr != nil || !samePrivateLease(current, lease) || claimed.VisitorConnectionId != visitor || validateDirectAdmission(claimed, time.Now()) != nil || !admission.selectService(claimed.ServiceId) {
		return ErrServiceAdmission
	}
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
	for attempt := range claimed.ConnectedRelays {
		relay := claimed.ConnectedRelays[(first+attempt)%len(claimed.ConnectedRelays)]
		header := tunnelv1.ServiceForwardingHeader{ServiceStreamHeader: tunnelv1.ServiceStreamHeader{
			ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.ServiceForwardingStream, ServiceID: claimed.ServiceId, ServiceRunID: claimed.ServiceRunId, RunNumber: uint64(claimed.RunNumber),
			Direct:   &tunnelv1.DirectAdmission{IngressID: lease.IngressId, IngressRunID: lease.IngressRunId, IngressLeaseRevision: uint64(lease.IngressLeaseRevision), DestinationPort: destination.Port()},
			SourceIP: source.Addr().Unmap().String(), VisitorConnectionID: visitor, PublisherConnectionID: relay.PublisherConnectionId, ConnectionAssignmentRevision: uint64(relay.ConnectionAssignmentRevision), ExpiresAt: claimed.ExpiresAt,
		}, ConnectionSlot: uint8(relay.ConnectionSlot), RelayServiceID: relay.RelayServiceId, RelayID: relay.RelayId, RelayRunID: relay.RelayRunId, RelayLeaseRevision: uint64(relay.RelayLeaseRevision), LeaseExpiresAt: relay.LeaseExpiresAt}
		attemptCtx, stopAttempt := backendAttemptContext(setup, len(claimed.ConnectedRelays)-attempt)
		backend, err := p.openPrivateRelay(attemptCtx, relay, header, proxy, deadline)
		stopAttempt()
		if err != nil {
			continue
		}
		defer backend.Close()
		if err = backend.SetDeadline(time.Time{}); err != nil {
			return err
		}
		if err = connection.SetDeadline(time.Time{}); err != nil {
			return err
		}
		// copying the first application protocol byte commits to this run. failures
		// after this point close the connection, including server-first MySQL.
		live, cancel := context.WithCancel(ctx)
		defer cancel()
		pending := &pendingDirectConn{Conn: connection, ctx: live, promoted: make(chan struct{})}
		pending.upload.Store(64 << 10)
		pending.download.Store(128 << 10)
		done := make(chan struct{})
		var guardErr error
		go func() {
			defer close(done)
			defer cancel()
			defer connection.Close()
			defer backend.Close()
			guardErr = p.guardDirectVisitor(live, control, lease, lookup, claimed.ExpiresAt, pending, admission, onAuthorized)
		}()
		_, finishForward := observability.Start(ctx, "ingress.forward_connector_visitor")
		_, err = streamcopy.Copy(pending, backend)
		finishForward(err)
		cancel()
		<-done
		if errors.Is(guardErr, ErrServiceAdmission) {
			return ErrServiceAdmission
		}
		return err
	}
	return ErrServiceAdmission
}

// direct admission uses the claim immediately, rather than installing history.
// every included relay and the claim itself must still be current.
func validateDirectAdmission(p ingressv1.DirectServiceVisitorAdmission, now time.Time) error {
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

func (p *DirectServices) openPrivateRelay(ctx context.Context, relay ingressv1.ServiceRelay, header tunnelv1.ServiceForwardingHeader, proxy []byte, deadline time.Time) (net.Conn, error) {
	if header.Validate() != nil {
		return nil, ErrServiceAdmission
	}
	connection, err := p.config.Forwarder.OpenPrivate(ctx, relay, header)
	if err != nil {
		return nil, err
	}
	setup, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	// PROXY metadata is retryable; use the same joined cancellation/deadline
	// handling as public setup, without sending any visitor bytes.
	_, err = writeSetup(setup, connection, proxy, nil)
	if err != nil {
		return nil, errors.Join(err, connection.Close())
	}
	return connection, nil
}

func (p *DirectServices) guardDirectVisitor(ctx context.Context, control DirectControl, lease ingressv1.IngressLease, lookup ingressv1.DirectServiceVisitorLookup, deadline time.Time, connection *pendingDirectConn, admission *privateStreamAdmission, onAuthorized func()) error {
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
		status, err := control.DirectServiceVisitorStatus(check, lease.IngressId, lookup)
		finish()
		if err == nil {
			switch status.State {
			case ingressv1.DirectVisitorPending:
				if connection.authorized.Load() {
					return ErrServiceAdmission
				}
				deadline = privateMinTime(deadline, status.ValidUntil)
			case ingressv1.DirectVisitorAuthenticated, ingressv1.DirectVisitorAllowed:
				if !status.ValidUntil.After(time.Now()) {
					return ErrServiceAdmission
				}
				if !reserved {
					if !admission.promote() {
						return ErrServiceAdmission
					}
					reserved = true
				}
				if status.State == ingressv1.DirectVisitorAuthenticated {
					promote, cancel := context.WithTimeout(ctx, min(p.config.RecheckTimeout, time.Until(deadline)))
					err = control.PromoteDirectServiceVisitor(promote, lease.IngressId, lookup)
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
