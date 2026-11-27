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
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/internal/transport/streamcopy"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
	"go.opentelemetry.io/otel/trace"
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
	diagnostic := &visitorDiagnostic{VisitorError: VisitorError{phase: "inspection"}}
	ctx = context.WithValue(ctx, visitorDiagnosticKey{}, diagnostic)
	defer func() { retErr = diagnostic.finish(retErr, p.release(connection)) }()
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
	var admission *visitorAdmission
	if destination.Port() == 443 {
		admission = p.newServiceAdmission()
	} else {
		var reason string
		admission, reason = p.admitPendingService()
		if admission == nil {
			p.rejectCapacity(reason)
			outcome = observability.VisitorCapacityDenied
			return ErrServiceAdmission
		}
	}
	defer admission.close()
	lease, err := p.lease(time.Now())
	if err != nil {
		outcome = observability.VisitorLookupUnavailable
		return err
	}
	diagnostic := visitorDiagnosticFrom(ctx)
	if diagnostic != nil {
		diagnostic.span = trace.SpanContextFromContext(ctx)
		diagnostic.ingressRun = lease.IngressRunId
	}
	setupDeadline := privateMinTime(time.Now().Add(p.config.OpenTimeout), privateMinTime(admission.deadline, lease.ServingUntil))
	admission.deadline = setupDeadline
	setup, finish := context.WithDeadline(ctx, setupDeadline)
	defer finish()
	stopSetup := context.AfterFunc(p.admissions, finish)
	defer stopSetup()
	selected, err := p.selectPublicRun(setup, lease, source, destination, hostname, admission)
	if diagnostic != nil {
		diagnostic.service, diagnostic.visitor = selected.serviceID, selected.visitorID
		diagnostic.phase, diagnostic.denial = "selection", string(selected.denialReason)
		if err != nil {
			diagnostic.candidate, diagnostic.candidateNumber = selected.runID, uint64(selected.number)
		} else {
			diagnostic.run, diagnostic.number, diagnostic.phase = selected.runID, uint64(selected.number), "opening"
			diagnostic.denial = ""
		}
	}
	defer func() {
		if selected.certificate != nil && selected.certificate.VisitorConnectionId != "" {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			retErr = errors.Join(retErr, control.ClosePublicServiceVisitor(cleanup, lease.IngressId, *selected.certificate))
		}
	}()
	if err != nil {
		if selected.denialReason == controlv1.ObservationCapacity {
			outcome = observability.VisitorCapacityDenied
		}
		if selected.serviceID != "" {
			reason := string(selected.denialReason)
			if reason == "" {
				reason = "unavailable"
			}
			var routingAuthority []byte
			var occurredAt time.Time
			if selected.http != nil {
				routingAuthority, _ = selected.http.source.MarshalBinary()
				occurredAt = selected.http.authorityTime(time.Now()).UTC()
			}
			serviceaudit.Emit(p.config.AuditSink, serviceaudit.Observation{ServiceID: selected.serviceID, ServiceKind: "service",
				VisitorConnectionID: selected.visitorID, SourceIP: source.Addr().Unmap().String(), EventType: "connection.open", Outcome: "denied", Reason: reason,
				RoutingAuthority: routingAuthority, OccurredAt: occurredAt})
		}
		return err
	}
	setupDeadline = privateMinTime(setupDeadline, selected.expiresAt)
	admission.deadline = setupDeadline
	setup, finishSelected := context.WithDeadline(setup, setupDeadline)
	defer finishSelected()
	current, err := p.lease(time.Now())
	if err != nil || !samePrivateLease(current, lease) || setup.Err() != nil || !setupDeadline.After(time.Now()) {
		return ErrServiceAdmission
	}
	stage := "pending"
	if selected.anonymous {
		stage = "ordinary"
	}
	p.observeTraffic(stage, "accepted")
	outcome = observability.VisitorOpenFailed
	audit := serviceaudit.Observation{ServiceID: selected.serviceID, ServiceKind: "service", RunID: selected.runID, RunNumber: selected.number, VisitorConnectionID: selected.visitorID, SourceIP: source.Addr().Unmap().String(), EventType: "connection.open", Outcome: "denied", Reason: "authorization"}
	var opened atomic.Bool
	defer func() {
		if selected.access == httpRequestAccess {
			return
		}
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
	onCapacityReserved := func() {
		if diagnostic != nil {
			diagnostic.admitted.Store(true)
		}
		if selected.access == clientCertificateAccess {
			allowed := audit
			allowed.Outcome, allowed.Reason = "allowed", ""
			serviceaudit.Emit(p.config.AuditSink, allowed)
		}
		opened.Store(true)
	}
	capacityDone := make(chan struct{})
	var capacityOnce sync.Once
	var capacityErr error
	reserveCapacity := func(call context.Context, relay ingressv1.ServiceRelay) (result error) {
		defer func() {
			capacityOnce.Do(func() {
				capacityErr = result
				if result == nil {
					onCapacityReserved()
				}
				close(capacityDone)
			})
		}()
		current, err := p.lease(time.Now())
		if err != nil || !samePrivateLease(current, lease) || ctx.Err() != nil || call.Err() != nil || !setupDeadline.After(time.Now()) {
			return ErrServiceAdmission
		}
		reserve := func() error {
			if reason := admission.reserveForVisitor(); reason != "" {
				p.rejectCapacity(reason)
				p.observeTraffic("capacity", "denied")
				return &tunnel.ProtocolError{Code: tunnelv1.CapacityExceeded}
			}
			if selected.access == clientCertificateAccess {
				if err := p.acknowledgeCertificateCapacity(call, control, lease, *selected.certificate); err != nil {
					return err
				}
			}
			current, err = p.lease(time.Now())
			if err != nil || !samePrivateLease(current, lease) || ctx.Err() != nil || call.Err() != nil || !setupDeadline.After(time.Now()) {
				return ErrServiceAdmission
			}
			admission.meterOrdinaryBytes()
			return nil
		}
		if selected.access == httpRequestAccess {
			return p.services.reserveHTTP(selected.http, relay, lease, source.Addr().Unmap(), reserve)
		}
		return reserve()
	}
	metadata := proxyproto.Header{Source: source, Destination: destination}
	if route := selected.http; selected.access == httpRequestAccess {
		sequence := route.sequence.next.Add(1)
		proof, err := visitortoken.SignVisitorSource(route.sourceKey, route.source, sequence, tunnelv1.VisitorSourceBinding{
			ServiceID: selected.serviceID, ServiceRunID: selected.runID, RunNumber: uint64(selected.number),
			VisitorConnectionID: selected.visitorID, Source: source, Destination: destination,
		}, route.authorityTime(time.Now()))
		if err != nil {
			return err
		}
		wire, err := proof.MarshalBinary()
		if err != nil {
			return err
		}
		metadata.VisitorSourceProof = string(wire)
	}
	proxy, err := proxyproto.Encode(metadata)
	if err != nil {
		return err
	}
	deadline, _ := setup.Deadline()
	deadline = privateMinTime(deadline, selected.expiresAt)
	// inspected bytes are absent from connection. charge them once across relay
	// attempts, independently of retryable PROXY and tunnel metadata.
	if len(initial) != 0 {
		if err := admission.beforeWrite(setup, true, len(initial)); err != nil {
			outcome = observability.VisitorCapacityDenied
			return err
		}
	}
	first := int((p.nextBackend.Add(1) - 1) % uint64(len(selected.relays)))
	relays := make([]ingressv1.ServiceRelay, len(selected.relays))
	for index := range relays {
		relays[index] = selected.relays[(first+index)%len(selected.relays)]
	}
	refreshedRelays := false
	var openingErr error
	openingStarted := time.Now()
	openingObserved := false
	defer func() {
		if !openingObserved && p.config.Metrics != nil {
			p.config.Metrics.ObserveVisitorOpen(false, time.Since(openingStarted))
		}
	}()
	for attempt := 0; attempt < len(relays); attempt++ {
		relay := relays[attempt]
		header := tunnelv1.ServiceForwardingHeader{ServiceStreamHeader: tunnelv1.ServiceStreamHeader{
			ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.ServiceForwardingStream, ServiceID: selected.serviceID, ServiceRunID: selected.runID, RunNumber: uint64(selected.number),
			PublicService: &tunnelv1.PublicServiceAdmission{IngressID: lease.IngressId, IngressRunID: lease.IngressRunId, IngressLeaseRevision: uint64(lease.IngressLeaseRevision), DestinationPort: destination.Port()},
			SourceIP:      source.Addr().Unmap().String(), VisitorConnectionID: selected.visitorID, PublisherConnectionID: relay.PublisherConnectionId, ConnectionAssignmentRevision: uint64(relay.ConnectionAssignmentRevision), ExpiresAt: deadline,
		}, ConnectionSlot: uint8(relay.ConnectionSlot), RelayServiceID: relay.RelayServiceId, RelayID: relay.RelayId, RelayRunID: relay.RelayRunId, RelayLeaseRevision: uint64(relay.RelayLeaseRevision), ServingUntil: relay.ServingUntil}
		attemptCtx, stopAttempt := backendAttemptContext(setup, len(relays)-attempt)
		attemptStarted := time.Now()
		attemptUntil, _ := attemptCtx.Deadline()
		backend, err := p.openPrivateRelay(attemptCtx, relay, header, proxy, initial, deadline, func(call context.Context) error {
			return reserveCapacity(call, relay)
		})
		stopAttempt()
		if diagnostic != nil {
			a := RelayAttempt{RelayID: relay.RelayId, RelayRunID: relay.RelayRunId, PublisherConnectionID: relay.PublisherConnectionId, Slot: relay.ConnectionSlot,
				AssignmentRevision: relay.ConnectionAssignmentRevision,
				Elapsed:            time.Since(attemptStarted), Budget: attemptUntil.Sub(attemptStarted), Err: err, Step: "open_relay", Committed: err == nil && len(initial) > 0}
			var opening *tunnel.OpeningError
			if errors.As(err, &opening) {
				a.Committed = opening.Committed
				diagnostic.sent = opening.VisitorBytes
				if opening.Step != "" {
					a.Step = opening.Step
				}
			} else if err == nil {
				a.Step = "opened"
				diagnostic.sent = int64(len(initial))
			}
			if diagnostic.last.Step != "" {
				diagnostic.previous = append(diagnostic.previous, diagnostic.last)
			}
			diagnostic.last = a
		}
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
			if attempt+1 == len(relays) && !refreshedRelays && selected.access == httpRequestAccess {
				refreshedRelays = true
				replacement, refreshErr := p.services.waitForRelayReplacement(setup, selected.http, lease, source.Addr().Unmap())
				if refreshErr != nil {
					return errors.Join(ErrServiceAdmission, openingErr, refreshErr)
				}
				relays = append(relays, replacementRelays(selected.relays, replacement.run.ConnectedRelays)...)
				replacementUntil := replacement.hostnameUntil(selected.http.selectedHostname)
				deadline = privateMinTime(deadline, replacementUntil)
				selected.expiresAt = privateMinTime(selected.expiresAt, replacementUntil)
				selected.recoveryEpisodeID = replacement.run.RecoveryEpisodeId
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
		if selected.access == httpRequestAccess {
			release, err := p.services.bind(selected.http, source.Addr().Unmap(), func() {
				if diagnostic != nil {
					diagnostic.routingStopped.Store(true)
				}
				cancel()
			})
			if err != nil {
				return errors.Join(err, backend.Close())
			}
			defer release()
			connection = httpCopyConn(connection, cancel)
			backend = httpCopyConn(backend, cancel)
		}
		reserveWrite := func(upload bool, size int) (int, error) {
			if selected.access == httpRequestAccess {
				return admission.reserveHTTPCopy(live, upload, size)
			}
			return size, admission.beforeWrite(live, upload, size)
		}
		public := &budgetConn{Conn: connection, reserveWrite: func(size int) (int, error) {
			return reserveWrite(false, size)
		}}
		upstream := &budgetConn{Conn: backend, reserveWrite: func(size int) (int, error) {
			return reserveWrite(true, size)
		}}
		done := make(chan struct{})
		var guardErr error
		var guardCleanup error
		go func() {
			defer close(done)
			defer cancel()
			guardErr = waitCopyCapacity(live, setupDeadline, capacityDone, &capacityErr)
			if guardErr == nil {
				switch selected.access {
				case clientCertificateAccess:
					guardErr = p.watchCertificateAccess(live, control, lease, *selected.certificate, selected.expiresAt)
				case httpRequestAccess:
					<-live.Done()
					guardErr = context.Cause(live)
				default:
					guardErr = ErrServiceAdmission
				}
			}
			guardCleanup = errors.Join(connection.Close(), backend.Close())
			guardErr = errors.Join(guardErr, guardCleanup)
		}()
		_, finishForward := observability.Start(ctx, "ingress.forward_connector_visitor")
		var observePublisherWrite func(int64)
		if selected.recoveryEpisodeID != nil && p.config.ObserveRecovery != nil {
			var firstPublisherByte sync.Once
			ref := ingressv1.ServiceRunReference{ServiceId: selected.serviceID, ServiceRunId: selected.runID, RunNumber: selected.number}
			var evidence []byte
			if selected.access == httpRequestAccess {
				evidence = proxy
			}
			observePublisherWrite = func(int64) {
				firstPublisherByte.Do(func() {
					at := time.Now().UTC()
					if selected.access == httpRequestAccess {
						at = selected.http.authorityTime(at).UTC()
					}
					p.config.ObserveRecovery(ref, selected.visitorID, uint64(*selected.recoveryEpisodeID), at, evidence)
				})
			}
		}
		if diagnostic != nil {
			diagnostic.phase = "copy"
		}
		var leftDoneFirst bool
		copied, err := streamcopy.CopyWithProgress(public, upstream, nil, observePublisherWrite, func(left bool) { leftDoneFirst = left })
		finishForward(err)
		cancel()
		<-done
		if diagnostic != nil {
			diagnostic.copyResult, diagnostic.cleanup = err, guardCleanup
			diagnostic.sent, diagnostic.returned = int64(len(initial))+copied.LeftToRight, copied.RightToLeft
		}
		if p.config.Metrics != nil {
			p.config.Metrics.AddForwardedBytes("visitor_to_publisher", copied.LeftToRight)
			p.config.Metrics.AddForwardedBytes("publisher_to_visitor", copied.RightToLeft)
		}
		if failure.Only(guardErr, context.Canceled) {
			guardErr = nil
		}
		result := errors.Join(err, guardErr)
		if diagnostic != nil {
			diagnostic.lastProgress = "relay_ack"
			if diagnostic.sent > 0 {
				diagnostic.lastProgress = "visitor_bytes_forwarded"
			}
			if diagnostic.returned > 0 {
				diagnostic.lastProgress = "publisher_bytes_forwarded"
			}
			switch {
			case ctx.Err() != nil:
				diagnostic.closeTrigger = "ingress_stopped"
			case diagnostic.routingStopped.Load():
				diagnostic.closeTrigger = "routing_stopped"
			case !diagnostic.admitted.Load() && guardErr != nil:
				diagnostic.closeTrigger = "capacity_guard"
			case guardErr != nil && err == nil:
				diagnostic.closeTrigger = "authorization_guard"
			case leftDoneFirst:
				diagnostic.closeTrigger = "visitor_to_relay_copy_ended"
			default:
				diagnostic.closeTrigger = "relay_to_visitor_copy_ended"
			}
			// A clean transport close may still leave a visitor with no TLS
			// response. observe it without changing forwarding or its result.
			if result == nil && ctx.Err() == nil && selected.access == httpRequestAccess && diagnostic.sent > 0 && diagnostic.returned == 0 && p.config.ObserveVisitorClose != nil {
				p.config.ObserveVisitorClose(&diagnostic.VisitorError)
			}
		}
		outcome = observability.VisitorForwarded
		if result != nil {
			outcome = observability.VisitorCommittedFailed
		}
		return result
	}
	return errors.Join(ErrServiceAdmission, openingErr)
}

// a full close must wake channel- and bandwidth-blocked http copies before
// physical cleanup. admission capacity remains owned until both copies join.
func httpCopyConn(connection net.Conn, cancel context.CancelFunc) net.Conn {
	return &ownedConn{Conn: connection, close: sync.OnceValue(func() error {
		cancel()
		return connection.Close()
	})}
}

// prefer a completed decision over an obsolete setup timer, but never treat a
// failed decision as permission. done publishes result before it is read here.
// after success the guard watches live, not this pending-only deadline.
func waitCopyCapacity(ctx context.Context, deadline time.Time, done <-chan struct{}, result *error) error {
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-done:
	case <-ctx.Done():
		select {
		case <-done:
		default:
			return context.Cause(ctx)
		}
	case <-timer.C:
		select {
		case <-done:
		default:
			return ErrServiceAdmission
		}
	}
	if *result != nil {
		return errors.Join(ErrServiceAdmission, *result)
	}
	return nil
}

// a native publisher already checked certificate access before asking for
// capacity. an ambiguous control acknowledgment needs a fresh receipt, never a
// longer deadline or another local capacity debit. prepared HTTP skips this RPC.
func (p *Server) acknowledgeCertificateCapacity(ctx context.Context, control PublicServiceControl, lease ingressv1.IngressLease, lookup ingressv1.PublicServiceVisitorLookup) error {
	for {
		check, cancel := context.WithTimeout(ctx, p.config.RecheckTimeout)
		deadline, _ := check.Deadline()
		err := control.PromotePublicServiceVisitor(check, lease.IngressId, lookup)
		err = errors.Join(err, context.Cause(check))
		if !time.Now().Before(deadline) {
			err = errors.Join(err, context.DeadlineExceeded)
		}
		cancel()
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return errors.Join(ErrServiceAdmission, err, context.Cause(ctx))
		}
		check, cancel = context.WithTimeout(ctx, p.config.RecheckTimeout)
		deadline, _ = check.Deadline()
		status, statusErr := control.PublicServiceVisitorStatus(check, lease.IngressId, lookup)
		statusErr = errors.Join(statusErr, context.Cause(check))
		if !time.Now().Before(deadline) {
			statusErr = errors.Join(statusErr, context.DeadlineExceeded)
		}
		cancel()
		if ctx.Err() != nil {
			return errors.Join(ErrServiceAdmission, err, statusErr, context.Cause(ctx))
		}
		if statusErr == nil {
			if !status.ValidUntil.After(time.Now()) {
				return ErrServiceAdmission
			}
			switch status.State {
			case ingressv1.PublicServiceVisitorAllowed:
				return nil
			case ingressv1.PublicServiceVisitorAuthenticated:
			default:
				return ErrServiceAdmission
			}
		}
		// only an ambiguous native acknowledgment retries. ordinary HTTP
		// never enters this control path or polls pending access.
		timer := time.NewTimer(min(p.config.RecheckInterval, 100*time.Millisecond))
		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.Join(ErrServiceAdmission, err, statusErr, context.Cause(ctx))
		case <-timer.C:
		}
	}
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
	current := p.config.CurrentLease()
	deadline, _ := check.Deadline()
	if err != nil || check.Err() != nil || !deadline.After(time.Now()) || !samePrivateLease(current, lease) ||
		!current.ServingUntil.After(time.Now()) || current.Draining || len(closed.Closed) > len(candidates) {
		return
	}
	for _, ref := range closed.Closed {
		if !requested[ref] {
			return
		}
		delete(requested, ref)
	}
	lease.ServingUntil = privateMinTime(lease.ServingUntil, current.ServingUntil)
	if len(closed.Closed) != 0 && p.services.retireTerminal(lease, closed.Closed) {
		p.traffic.retireTerminal(closed.Closed)
	}
}

// public service admission uses the claim immediately, rather than installing history.
// every included relay and the claim itself must still be current.
func validatePublicServiceAdmission(p ingressv1.PublicServiceVisitorAdmission, now time.Time) error {
	if p.RecoveryEpisodeId != nil && *p.RecoveryEpisodeId <= 0 {
		return ErrServiceAdmission
	}
	if !opaqueid.Valid(p.ServiceId, opaqueid.ServicePrefix) || !opaqueid.Valid(p.ServiceRunId, opaqueid.ServiceRunPrefix) || p.RunNumber < 1 || !p.ExpiresAt.After(now) || len(p.ConnectedRelays) < 1 || len(p.ConnectedRelays) > 2 {
		return ErrServiceAdmission
	}
	if _, err := routingTraffic(p.Traffic); err != nil {
		return ErrServiceAdmission
	}
	return validateServiceRelays(p.ConnectedRelays, now)
}

func validateServiceRelays(relays []ingressv1.ServiceRelay, now time.Time) error {
	if len(relays) == 0 || len(relays) > 2 {
		return ErrServiceAdmission
	}
	services, slots := make(map[string]bool, 2), make(map[int]bool, 2)
	for _, relay := range relays {
		if !opaqueid.Valid(relay.PublisherConnectionId, opaqueid.PublisherConnectionPrefix) || relay.ConnectionSlot < 0 || relay.ConnectionSlot > 1 || relay.ConnectionAssignmentRevision < 1 || relay.RelayLeaseRevision < 1 || relay.RelayServiceId == "" || relay.RelayId == "" || !opaqueid.Valid(relay.RelayRunId, opaqueid.RelayRunPrefix) || !relay.ServingUntil.After(now) || services[relay.RelayServiceId] || slots[relay.ConnectionSlot] {
			return ErrServiceAdmission
		}
		if _, _, err := net.SplitHostPort(relay.InternalRelayAddress); err != nil {
			return ErrServiceAdmission
		}
		services[relay.RelayServiceId], slots[relay.ConnectionSlot] = true, true
	}
	return nil
}

func (p *Server) openPrivateRelay(ctx context.Context, relay ingressv1.ServiceRelay, header tunnelv1.ServiceForwardingHeader, proxy, initial []byte, deadline time.Time, reserveCapacity func(context.Context) error) (net.Conn, error) {
	if header.Validate() != nil {
		return nil, ErrServiceAdmission
	}
	connection, err := p.config.Forwarder.OpenService(ctx, relay, header, reserveCapacity)
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
		return nil, &tunnel.OpeningError{Step: "write_visitor_setup", Committed: written > 0, VisitorBytes: written, Err: errors.Join(err, connection.Close())}
	}
	return connection, nil
}

func (p *Server) watchCertificateAccess(ctx context.Context, control PublicServiceControl, lease ingressv1.IngressLease, lookup ingressv1.PublicServiceVisitorLookup, deadline time.Time) error {
	for {
		current, err := p.liveLease(time.Now())
		if err != nil || !samePrivateLease(current, lease) {
			return ErrServiceAdmission
		}
		deadline = privateMinTime(deadline, current.ServingUntil)
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
		deadline = privateMinTime(deadline, current.ServingUntil)
		if current.Draining && current.DrainDeadline != nil {
			deadline = privateMinTime(deadline, *current.DrainDeadline)
		}
		if !deadline.After(time.Now()) {
			return ErrServiceAdmission
		}
		if err == nil {
			if status.State != ingressv1.PublicServiceVisitorAllowed || !status.ValidUntil.After(time.Now()) {
				return ErrServiceAdmission
			}
			deadline = privateMinTime(status.ValidUntil, privateMinTime(time.Now().Add(p.config.HardAuthorizationTTL), current.ServingUntil))
			if current.Draining && current.DrainDeadline != nil {
				deadline = privateMinTime(deadline, *current.DrainDeadline)
			}
		}
		timer := time.NewTimer(privateRecheckDelay(p.config.RecheckInterval, p.config.RecheckTimeout, deadline))
		select {
		case <-ctx.Done():
			timer.Stop()
			return context.Cause(ctx)
		case <-timer.C:
		}
	}
}
