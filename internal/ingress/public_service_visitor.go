package ingress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/ingress/clienthello"
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
// absent from connection. anonymous accounting never grants target permission.
func (p *Server) AcceptPublic(ctx context.Context, connection net.Conn, source, destination netip.AddrPort, hostname string, initial []byte) (retErr error) {
	if connection == nil {
		return ErrServiceAdmission
	}
	connection = onceCloseConn(connection)
	if !p.admit(connection) {
		return errors.Join(ErrServiceAdmission, connection.Close())
	}
	defer p.active.Done()
	defer func() { retErr = errors.Join(retErr, p.release(connection)) }()
	finishInspection := sync.OnceFunc(p.finishInspection)
	defer finishInspection()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopped := make(chan struct{})
	stop := context.AfterFunc(p.openContext, func() { defer close(stopped); cancel() })
	defer func() {
		if !stop() {
			<-stopped
		}
	}()
	release, reason := p.traffic.source(source.Addr())
	if release == nil {
		p.rejectCapacity(reason)
		return ErrServiceAdmission
	}
	defer release()
	finishInspection()
	p.markVisitor(connection)
	return p.forwardService(ctx, connection, source, destination, hostname, initial)
}

func (p *Server) acceptPublic(ctx context.Context, connection net.Conn, source, destination netip.AddrPort, hostname string, initial []byte) (retErr error) {
	ctx, finishConnection := observability.Start(ctx, "ingress.public_service_visitor_connection")
	defer func() { finishConnection(retErr) }()
	outcome := observability.VisitorLookupMissing
	if p.config.Metrics != nil {
		defer func() { p.config.Metrics.ObserveVisitor(outcome) }()
	}
	control := p.config.Control
	if control == nil || connection == nil || !validPrivateSocketPair(source, destination) || len(initial) > clienthello.MaxClientHelloBytes {
		return ErrServiceAdmission
	}
	if destination.Port() == 443 {
		if !serviceendpoint.Valid("http", hostname, 443, true) {
			return ErrServiceAdmission
		}
	} else if destination.Port() < 1024 || hostname != "" {
		return ErrServiceAdmission
	}
	admission, reason := p.admitPendingService()
	if admission == nil {
		p.rejectCapacity(reason)
		outcome = observability.VisitorCapacityDenied
		return ErrServiceAdmission
	}
	defer admission.close()
	lease, err := p.lease(time.Now())
	if err != nil {
		outcome = observability.VisitorLookupUnavailable
		return err
	}
	lookup := ingressv1.PublicServiceVisitorLookup{IngressRunId: lease.IngressRunId, IngressLeaseRevision: lease.IngressLeaseRevision}
	defer func() {
		if lookup.VisitorConnectionId == "" {
			return
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = control.ClosePublicServiceVisitor(cleanup, lease.IngressId, lookup)
	}()
	setupDeadline := privateMinTime(time.Now().Add(p.config.OpenTimeout), privateMinTime(admission.deadline, lease.LeaseExpiresAt))
	admission.deadline = setupDeadline
	setup, finish := context.WithDeadline(ctx, setupDeadline)
	defer finish()
	stopSetup := context.AfterFunc(p.admissions, finish)
	defer stopSetup()
	claim := ingressv1.PublicServiceVisitorClaim{IngressRunId: lease.IngressRunId, IngressLeaseRevision: lease.IngressLeaseRevision, IngressPoolId: p.config.IngressPoolID, DestinationPort: int(destination.Port()), ObservedSourceIp: source.Addr().Unmap().String()}
	if hostname != "" {
		claim.Hostname = &hostname
	}
	var claimed ingressv1.PublicServiceVisitorAdmission
	var serviceID, serviceVisitor string
	selected, selectionReason := false, "unavailable"
	defer func() {
		if !selected && serviceID != "" {
			serviceaudit.Emit(p.config.AuditSink, serviceaudit.Observation{ServiceID: serviceID, ServiceKind: "service",
				VisitorConnectionID: serviceVisitor, SourceIP: source.Addr().Unmap().String(), EventType: "connection.open", Outcome: "denied", Reason: selectionReason})
		}
	}()
	for attempt := range 8 {
		if err := setup.Err(); err != nil {
			return err
		}
		current, leaseErr := p.lease(time.Now())
		if leaseErr != nil || !samePrivateLease(current, lease) || !setupDeadline.After(time.Now()) {
			return ErrServiceAdmission
		}
		claim.VisitorConnectionId, err = opaqueid.New(opaqueid.VisitorConnectionPrefix)
		if err != nil {
			return err
		}
		lookup.VisitorConnectionId = claim.VisitorConnectionId
		selectionReason = "unavailable"
		claimed, err = control.AdmitPublicServiceVisitor(setup, lease.IngressId, claim)
		if err != nil {
			// an ambiguous response may have created this exact reservation.
			// final cleanup closes it; never turn a transport error into reselection.
			return err
		}
		current, leaseErr = p.lease(time.Now())
		valid := claimed.VisitorConnectionId == claim.VisitorConnectionId && (!claimed.Anonymous || destination.Port() == 443) &&
			validatePublicServiceAdmission(claimed, time.Now()) == nil && (serviceID == "" || claimed.ServiceId == serviceID)
		for _, excluded := range claim.ExcludedRuns {
			if claimed.ServiceRunId == excluded.ServiceRunId || claimed.RunNumber == excluded.RunNumber {
				valid = false
			}
		}
		if leaseErr != nil || !samePrivateLease(current, lease) || !valid || setup.Err() != nil || !setupDeadline.After(time.Now()) {
			outcome, selectionReason = observability.VisitorInvalidProjection, "invalid_request"
			return ErrServiceAdmission
		}
		serviceID, serviceVisitor = claimed.ServiceId, claimed.VisitorConnectionId
		p.retireClosedTrafficRuns(setup, lease)
		if err := setup.Err(); err != nil {
			return err
		}
		limits, err := routingTraffic(claimed.Traffic)
		if err != nil {
			return ErrServiceAdmission
		}
		stage := "pending"
		if claimed.Anonymous {
			stage = "ordinary"
		}
		if reason := admission.selectRun(trafficKey{service: serviceID, id: claimed.ServiceRunId, run: uint64(claimed.RunNumber)}, limits, source.Addr().Unmap(), claimed.Anonymous); reason != "" {
			p.rejectCapacity(reason)
			p.observeTraffic(stage, "capacity")
			outcome, selectionReason = observability.VisitorCapacityDenied, "capacity"
			if !retryServiceRunSelection(reason) {
				if reason == "invalid_traffic_projection" {
					outcome, selectionReason = observability.VisitorInvalidProjection, "invalid_request"
				}
				return ErrServiceAdmission
			}
			// rejected candidates have no local reservation and no relay bytes.
			// confirm their durable reservation is closed before selecting another.
			if err := control.ClosePublicServiceVisitor(setup, lease.IngressId, lookup); err != nil {
				return err
			}
			lookup.VisitorConnectionId = ""
			if err := setup.Err(); err != nil {
				return err
			}
			if attempt == 7 {
				return errors.Join(ErrServiceAdmission, ErrServiceSelectionLimit)
			}
			claim.ExcludedRuns = append(claim.ExcludedRuns, ingressv1.ServiceRunReference{ServiceId: serviceID, ServiceRunId: claimed.ServiceRunId, RunNumber: claimed.RunNumber})
			continue
		}
		selected = true
		p.observeTraffic(stage, "accepted")
		break
	}
	outcome = observability.VisitorOpenFailed
	audit := serviceaudit.Observation{ServiceID: claimed.ServiceId, ServiceKind: "service", RunID: claimed.ServiceRunId, RunNumber: claimed.RunNumber, VisitorConnectionID: claimed.VisitorConnectionId, SourceIP: source.Addr().Unmap().String(), EventType: "connection.open", Outcome: "denied", Reason: "authorization"}
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
	// inspected bytes are absent from connection. charge them once across relay
	// attempts, independently of retryable PROXY and tunnel metadata.
	if len(initial) != 0 {
		if err := admission.beforeWrite(setup, true, len(initial)); err != nil {
			outcome = observability.VisitorCapacityDenied
			return err
		}
	}
	first := int((p.nextBackend.Add(1) - 1) % uint64(len(claimed.ConnectedRelays)))
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
			SourceIP:      source.Addr().Unmap().String(), VisitorConnectionID: claimed.VisitorConnectionId, PublisherConnectionID: relay.PublisherConnectionId, ConnectionAssignmentRevision: uint64(relay.ConnectionAssignmentRevision), ExpiresAt: claimed.ExpiresAt,
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
		public := &budgetConn{Conn: connection, beforeWrite: func(size int) error {
			return admission.beforeWrite(live, false, size)
		}}
		upstream := &budgetConn{Conn: backend, beforeWrite: func(size int) error {
			return admission.beforeWrite(live, true, size)
		}}
		done := make(chan struct{})
		var guardErr error
		go func() {
			defer close(done)
			defer cancel()
			guardErr = p.guardPublicServiceVisitor(live, control, lease, lookup, deadline, admission, onAuthorized)
			guardErr = errors.Join(guardErr, connection.Close(), backend.Close())
		}()
		_, finishForward := observability.Start(ctx, "ingress.forward_connector_visitor")
		copied, err := streamcopy.Copy(public, upstream)
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

func retryServiceRunSelection(reason string) bool {
	switch reason {
	case "service_connections", "service_connection_total", "service_connection_rate", "pending_service_connections", "pending_service_rate":
		return true
	}
	return false
}

func (p *Server) retireClosedTrafficRuns(ctx context.Context, lease ingressv1.IngressLease) {
	candidates := p.traffic.terminalCandidates(time.Now())
	if len(candidates) == 0 {
		return
	}
	request := ingressv1.ServiceRunClosureLookup{IngressRunId: lease.IngressRunId, IngressLeaseRevision: lease.IngressLeaseRevision, ServiceRuns: candidates}
	requested := make(map[ingressv1.ServiceRunReference]bool, len(candidates))
	for _, ref := range candidates {
		requested[ref] = true
	}
	check, cancel := context.WithTimeout(ctx, p.config.RecheckTimeout)
	defer cancel()
	closed, err := p.config.Control.ClosedServiceRuns(check, lease.IngressId, request)
	if err != nil || len(closed.Closed) > len(candidates) {
		return
	}
	for _, ref := range closed.Closed {
		if !requested[ref] {
			return
		}
		delete(requested, ref)
	}
	p.traffic.retireTerminal(closed.Closed)
}

// public service admission uses the claim immediately, rather than installing history.
// every included relay and the claim itself must still be current.
func validatePublicServiceAdmission(p ingressv1.PublicServiceVisitorAdmission, now time.Time) error {
	if !opaqueid.Valid(p.ServiceId, opaqueid.ServicePrefix) || !opaqueid.Valid(p.ServiceRunId, opaqueid.ServiceRunPrefix) || p.RunNumber < 1 || !p.ExpiresAt.After(now) || len(p.ConnectedRelays) < 1 || len(p.ConnectedRelays) > 2 {
		return ErrServiceAdmission
	}
	if _, err := routingTraffic(p.Traffic); err != nil {
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

func (p *Server) openPrivateRelay(ctx context.Context, relay ingressv1.ServiceRelay, header tunnelv1.ServiceForwardingHeader, proxy, initial []byte, deadline time.Time) (net.Conn, error) {
	if header.Validate() != nil {
		return nil, ErrServiceAdmission
	}
	connection, err := p.config.Forwarder.OpenPrivate(ctx, relay, header)
	if err != nil {
		return nil, err
	}
	connection, err = p.observeBackend(ctx, connection)
	if err != nil {
		return nil, err
	}
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

func (p *Server) guardPublicServiceVisitor(ctx context.Context, control PublicServiceControl, lease ingressv1.IngressLease, lookup ingressv1.PublicServiceVisitorLookup, deadline time.Time, admission *visitorAdmission, onAuthorized func()) error {
	reserved, authorized := admission.ordinary, false
	for {
		current, err := p.liveLease(time.Now())
		if err != nil || !samePrivateLease(current, lease) {
			return ErrServiceAdmission
		}
		deadline = privateMinTime(deadline, current.LeaseExpiresAt)
		if current.Draining && current.DrainDeadline != nil {
			deadline = privateMinTime(deadline, *current.DrainDeadline)
		}
		if !deadline.After(time.Now()) {
			return ErrServiceAdmission
		}
		check, finish := context.WithTimeout(ctx, min(p.config.RecheckTimeout, time.Until(deadline)))
		checkDeadline, _ := check.Deadline()
		status, err := control.PublicServiceVisitorStatus(check, lease.IngressId, lookup)
		if cause := context.Cause(check); cause != nil {
			err = errors.Join(err, cause)
		} else if !checkDeadline.After(time.Now()) {
			err = errors.Join(err, context.DeadlineExceeded)
		}
		finish()
		if ctx.Err() != nil {
			return errors.Join(context.Cause(ctx), err)
		}
		current, leaseErr := p.liveLease(time.Now())
		if leaseErr != nil || !samePrivateLease(current, lease) {
			return ErrServiceAdmission
		}
		deadline = privateMinTime(deadline, current.LeaseExpiresAt)
		if current.Draining && current.DrainDeadline != nil {
			deadline = privateMinTime(deadline, *current.DrainDeadline)
		}
		if !deadline.After(time.Now()) {
			return ErrServiceAdmission
		}
		if err == nil {
			switch status.State {
			case ingressv1.PublicServiceVisitorPending:
				if authorized {
					return ErrServiceAdmission
				}
				deadline = privateMinTime(deadline, status.ValidUntil)
			case ingressv1.PublicServiceVisitorAuthenticated, ingressv1.PublicServiceVisitorAllowed:
				if !status.ValidUntil.After(time.Now()) {
					return ErrServiceAdmission
				}
				if !reserved {
					if reason := admission.reserve(admission.limits); reason != "" {
						p.rejectCapacity(reason)
						p.observeTraffic("promotion", "capacity")
						return ErrServiceAdmission
					}
					p.observeTraffic("promotion", "accepted")
					reserved = true
				}
				if status.State == ingressv1.PublicServiceVisitorAuthenticated {
					promote, cancel := context.WithTimeout(ctx, min(p.config.RecheckTimeout, time.Until(deadline)))
					promoteDeadline, _ := promote.Deadline()
					err = control.PromotePublicServiceVisitor(promote, lease.IngressId, lookup)
					if cause := context.Cause(promote); cause != nil {
						err = errors.Join(err, cause)
					} else if !promoteDeadline.After(time.Now()) {
						err = errors.Join(err, context.DeadlineExceeded)
					}
					cancel()
				}
				// reservation and promotion may wait. neither can replace the
				// deadline or lease facts that authorized entering this attempt.
				if ctx.Err() != nil {
					return errors.Join(context.Cause(ctx), err)
				}
				current, leaseErr = p.liveLease(time.Now())
				if leaseErr != nil || !samePrivateLease(current, lease) {
					return errors.Join(ErrServiceAdmission, err)
				}
				deadline = privateMinTime(deadline, current.LeaseExpiresAt)
				if current.Draining && current.DrainDeadline != nil {
					deadline = privateMinTime(deadline, *current.DrainDeadline)
				}
				if !deadline.After(time.Now()) || !status.ValidUntil.After(time.Now()) {
					return errors.Join(ErrServiceAdmission, err)
				}
				if err != nil {
					// a lost acknowledgment retains both its original deadline
					// and its once-only quota reservation until a fresh check.
					break
				}
				if !authorized {
					authorized = true
					admission.meterOrdinaryBytes()
					onAuthorized()
				}
				deadline = privateMinTime(status.ValidUntil, privateMinTime(time.Now().Add(p.config.HardAuthorizationTTL), current.LeaseExpiresAt))
				if current.Draining && current.DrainDeadline != nil {
					deadline = privateMinTime(deadline, *current.DrainDeadline)
				}
			default:
				return ErrServiceAdmission
			}
		}
		interval := 100 * time.Millisecond
		if authorized {
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
