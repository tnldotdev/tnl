package ingress

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/proxyproto"
	"github.com/tnldotdev/tnl/internal/routebackend"
	"github.com/tnldotdev/tnl/internal/router"
	"github.com/tnldotdev/tnl/internal/serviceaudit"
	"github.com/tnldotdev/tnl/internal/streamcopy"
)

type committedVisitorStream struct {
	connection net.Conn
	bytes      int64
	setupErr   error
}

var errBackendTrackingClosed = errors.New("ingress: backend tracking closed")

// forward resolves policy and admission before attempting a publisher stream.
func (s *Server) forward(public net.Conn, source, destination netip.AddrPort, hello router.ClientHello) error {
	var route PublicURL
	var backends []routebackend.Backend
	var ok bool
	visitorOutcome := observability.VisitorLookupMissing
	visitorStarted := time.Now()
	visitorID := ""
	auditReason, auditOutcome := "unavailable", "denied"
	auditOpened := false
	defer func() {
		if route.ID != "" && visitorID != "" && !auditOpened {
			serviceaudit.Emit(s.config.AuditSink, serviceaudit.Observation{ServiceID: route.ID, ServiceKind: "public_url", RunID: route.PublishRunID, RunNumber: int64(route.PublishRunNumber), VisitorConnectionID: visitorID, SourceIP: source.Addr().Unmap().String(), EventType: "connection.open", Outcome: auditOutcome, Reason: auditReason})
		}
	}()
	if s.config.Metrics != nil {
		defer func() { s.config.Metrics.ObserveVisitor(visitorOutcome) }()
	}
	{
		var reason LookupReason
		if s.config.LookupPool != nil {
			var candidates []PublicURL
			candidates, reason = s.config.LookupPool(hello.ServerName)
			if reason == LookupCurrent {
				var release func()
				route, release, reason = s.selectPoolRun(candidates)
				if release != nil {
					defer release()
				}
				if reason != LookupCurrent && len(candidates) > 0 {
					// no run was selected. retain only the service identity so a
					// full/unavailable pool does not disappear from its audit.
					route = PublicURL{ID: candidates[0].ID}
				}
			}
		} else {
			route, reason = s.config.Lookup(hello.ServerName)
		}
		ok = reason == LookupCurrent
		switch reason {
		case LookupIngressUnavailable:
			visitorOutcome = observability.VisitorLookupUnavailable
		case LookupInvalidProjection:
			visitorOutcome = observability.VisitorInvalidProjection
		}
		backends = route.Backends
	}
	if route.ID != "" {
		var err error
		visitorID, err = opaqueid.New(visitorConnectionIDPrefix)
		if err != nil {
			return err
		}
	}
	if !ok || len(backends) == 0 {
		if ok {
			visitorOutcome = observability.VisitorLookupUnavailable
		}
		return nil
	}
	var usage UsageConnection
	if s.config.OpenUsage != nil {
		usage = s.config.OpenUsage(route.ID, route.PublishRunNumber, source.Addr(), time.Now().UTC())
		if usage != nil {
			defer func() { usage.Close(time.Now().UTC()) }()
		}
	}
	if !route.allowsIP(source.Addr()) {
		auditReason = "ip_policy"
		visitorOutcome = observability.VisitorPolicyDenied
		if usage != nil {
			usage.PolicyDenied(time.Now().UTC())
		}
		return nil
	}
	// ingress cannot inspect a visitor credential inside TLS. restricted
	// HTTP connections remain bounded until the
	// publisher checks it.
	denied := route.AccessMode != "anonymous"
	kind := visitorConnection
	if denied {
		kind = pendingConnection
	}
	var admission *visitorAdmission
	var release func()
	var rejected string
	{
		admission, rejected = s.admitVisitor(route, source.Addr(), denied)
		if admission != nil {
			release = admission.close
		}
	}
	if release == nil {
		auditReason = "capacity"
		if rejected == "draining" {
			auditReason = "draining"
		}
		s.rejectCapacity(rejected)
		if !denied {
			visitorOutcome = observability.VisitorCapacityDenied
			if rejected == "draining" {
				visitorOutcome = observability.VisitorDraining
			}
		}
		if usage != nil {
			usage.CapacityDenied(time.Now().UTC())
		}
		return nil
	}
	defer release()

	if usage != nil {
		usage.VisitorStreamOpening(time.Now().UTC())
	}
	streamCommitted := false
	if usage != nil {
		defer func() {
			if !streamCommitted {
				usage.VisitorStreamOpenFailed(time.Now().UTC())
			}
		}()
	}
	header, err := proxyproto.Encode(proxyproto.Header{Source: source, Destination: destination})
	if err != nil {
		return fmt.Errorf("ingress: encode proxy header: %w", err)
	}
	if visitorID == "" {
		visitorID, err = opaqueid.New(visitorConnectionIDPrefix)
		if err != nil {
			return fmt.Errorf("ingress: create visitor connection ID: %w", err)
		}
	}
	if admission != nil && denied {
		admission.hostname = hello.ServerName
		remove := s.registerPendingVisitor(visitorID, admission, public)
		defer remove()
	}
	if admission != nil {
		if err := admission.beforeWrite(s.openContext, true, len(hello.Prefix)); err != nil {
			return err
		}
	}
	openTimeout := s.config.OpenTimeout
	if denied {
		openTimeout = min(openTimeout, 2*time.Second, time.Until(admission.deadline))
	}
	openCtx, cancel := context.WithTimeout(s.openContext, openTimeout)
	opened, openErr := s.openVisitorStream(openCtx, backends, visitorID, kind, header, hello.Prefix, usage)
	cancel()
	if errors.Is(openErr, errBackendTrackingClosed) {
		return net.ErrClosed
	}
	if s.config.Metrics != nil {
		s.config.Metrics.ObserveVisitorOpen(opened.connection != nil && opened.setupErr == nil, time.Since(visitorStarted))
	}
	if openErr != nil {
		auditOutcome, auditReason = "failed", "forwarding"
		if !denied {
			visitorOutcome = observability.VisitorOpenFailed
		}
		s.reportForwardingFailure(route, visitorID, ForwardingNoBackend, len(backends))
		return openErr
	}
	defer s.releaseBackend(opened.connection)
	if admission != nil {
		admission.mu.Lock()
		admission.upstream = opened.connection
		admission.mu.Unlock()
	}
	if usage != nil {
		usage.StreamOpened(time.Now().UTC())
		usage.AddIngress(opened.bytes, time.Now().UTC())
		streamCommitted = true
	}
	if s.config.Metrics != nil {
		s.config.Metrics.AddForwardedBytes("visitor_to_publisher", opened.bytes)
	}
	if opened.setupErr != nil {
		auditOutcome, auditReason = "failed", "forwarding"
		if !denied {
			visitorOutcome = observability.VisitorCommittedFailed
		}
		s.reportForwardingFailure(route, visitorID, ForwardingCommittedWrite, len(backends))
		return fmt.Errorf("ingress: write visitor setup after %d bytes: %w", opened.bytes, opened.setupErr)
	}
	upstream := opened.connection
	if admission != nil {
		ctx, cancel := context.WithCancel(s.openContext)
		defer cancel()
		public = &budgetConn{Conn: public, beforeWrite: func(n int) error { return admission.beforeWrite(ctx, false, n) }}
		upstream = &budgetConn{Conn: upstream, beforeWrite: func(n int) error { return admission.beforeWrite(ctx, true, n) }}
	}
	{
		auditOpened = true
		serviceaudit.Emit(s.config.AuditSink, serviceaudit.Observation{ServiceID: route.ID, ServiceKind: "public_url", RunID: route.PublishRunID, RunNumber: int64(route.PublishRunNumber), VisitorConnectionID: visitorID, SourceIP: source.Addr().Unmap().String(), EventType: "connection.open", Outcome: "forwarded"})
	}
	err = s.copyVisitor(public, upstream, hello.Remainder, route, denied, usage)
	{
		outcome, reason := "closed", "closed"
		if err != nil {
			outcome, reason = "failed", "forwarding"
		}
		serviceaudit.Emit(s.config.AuditSink, serviceaudit.Observation{ServiceID: route.ID, ServiceKind: "public_url", RunID: route.PublishRunID, RunNumber: int64(route.PublishRunNumber), VisitorConnectionID: visitorID, SourceIP: source.Addr().Unmap().String(), EventType: "connection.close", Outcome: outcome, Reason: reason})
	}
	if !denied {
		visitorOutcome = observability.VisitorForwarded
		if err != nil {
			visitorOutcome = observability.VisitorCommittedFailed
		}
	}
	return err
}

// reserve the selected run before opening a relay stream. only new connections
// enter this selection; releasing capacity never migrates an established one.
func (s *Server) selectPoolRun(candidates []PublicURL) (PublicURL, func(), LookupReason) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return PublicURL{}, nil, LookupIngressUnavailable
	}
	if s.poolRuns == nil {
		s.poolRuns = map[string]int{}
	}
	selected := -1
	var load, capacity int64
	start := 0
	if len(candidates) > 0 {
		start = int(s.nextBackend.Add(1) % uint64(len(candidates)))
	}
	for offset := range candidates {
		index := (start + offset) % len(candidates)
		candidate := candidates[index]
		limits, valid := s.selectedTraffic(candidate)
		if !valid || len(candidate.Backends) == 0 || candidate.PublishRunID == "" {
			continue
		}
		used := int64(s.poolRuns[candidate.PublishRunID])
		limit := int64(limits.Connections)
		if used >= limit {
			continue
		}
		if selected < 0 || used*capacity < load*limit {
			selected, load, capacity = index, used, limit
		}
	}
	if selected < 0 {
		return PublicURL{}, nil, LookupNoBackends
	}
	route := candidates[selected]
	s.poolRuns[route.PublishRunID]++
	return route, sync.OnceFunc(func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.poolRuns[route.PublishRunID]--
		if s.poolRuns[route.PublishRunID] == 0 {
			delete(s.poolRuns, route.PublishRunID)
		}
	}), LookupCurrent
}

// openVisitorStream retries only before a visitor byte reaches a relay. the
// returned connection is owned by the caller even when its setup write failed.
func (s *Server) openVisitorStream(ctx context.Context, backends []routebackend.Backend, visitorID string, kind connectionKind, header, prefix []byte, usage UsageConnection) (committedVisitorStream, error) {
	opened := false
	// rotate visitors across connected relays before committing bytes.
	firstBackend := 0
	if len(backends) > 1 {
		firstBackend = int((s.nextBackend.Add(1) - 1) % uint64(len(backends)))
	}
	var lastErr error
	for attempt := range backends {
		backend := backends[(firstBackend+attempt)%len(backends)]
		if err := ctx.Err(); err != nil {
			lastErr = errors.Join(lastErr, err)
			break
		}
		if backend == nil {
			lastErr = errors.New("ingress: route backend is nil")
			continue
		}
		attemptCtx, stopAttempt := backendAttemptContext(ctx, len(backends)-attempt)
		started := time.Now()
		var candidate net.Conn
		var openErr error
		if kind == pendingConnection {
			if pendingBackend, ok := backend.(routebackend.PendingBackend); ok {
				candidate, openErr = pendingBackend.OpenPending(attemptCtx, visitorID)
			} else {
				openErr = errors.New("ingress: backend does not support pending authorization")
			}
		} else {
			candidate, openErr = backend.Open(attemptCtx, visitorID)
		}
		if openErr != nil {
			stopAttempt()
			s.observeAttempt(attempt, openErr, started)
			s.observeRelayAttempt(backend, observability.RelayAttemptOpenFailed)
			lastErr = fmt.Errorf("ingress: open public_url: %w", openErr)
			continue
		}
		if usage != nil && !opened {
			usage.VisitorStreamOpened(time.Now().UTC())
			opened = true
		}
		if !s.trackBackend(candidate) {
			_ = candidate.Close()
			stopAttempt()
			return committedVisitorStream{}, errBackendTrackingClosed
		}
		// a partial ClientHello write crosses the retry boundary even on error.
		written, writeErr := writeSetup(attemptCtx, candidate, header, prefix)
		stopAttempt()
		s.observeAttempt(attempt, writeErr, started)
		if writeErr != nil && written == 0 {
			s.observeRelayAttempt(backend, observability.RelayAttemptSetupFailed)
			lastErr = errors.Join(writeErr, s.releaseBackend(candidate))
			continue
		}
		if writeErr != nil {
			s.observeRelayAttempt(backend, observability.RelayAttemptCommittedFailed)
		} else {
			s.observeRelayAttempt(backend, observability.RelayAttemptCommitted)
		}
		return committedVisitorStream{connection: candidate, bytes: written, setupErr: writeErr}, nil
	}
	if lastErr == nil {
		lastErr = errors.New("ingress: route has no usable backend")
	}
	return committedVisitorStream{}, lastErr
}

func (s *Server) copyVisitor(public, upstream net.Conn, remainder io.Reader, route PublicURL, denied bool, usage UsageConnection) error {
	replayed := &readerConn{Conn: public, reader: remainder}
	var observeIngress, observeEgress func(int64)
	if usage != nil {
		observeIngress = func(bytes int64) { usage.AddIngress(bytes, time.Now().UTC()) }
	}
	if usage != nil || !denied && route.RecoveryEpisodeID != 0 && s.config.ObserveRecovery != nil {
		var recoveryOnce sync.Once
		observeEgress = func(bytes int64) {
			now := time.Now().UTC()
			if usage != nil {
				usage.AddEgress(bytes, now)
			}
			if !denied && route.RecoveryEpisodeID != 0 && s.config.ObserveRecovery != nil {
				recoveryOnce.Do(func() {
					s.config.ObserveRecovery(route.ID, route.PublishRunNumber, route.RecoveryEpisodeID, now)
				})
			}
		}
	}
	result, err := streamcopy.CopyObserved(replayed, upstream, observeIngress, observeEgress)
	if s.config.Metrics != nil {
		s.config.Metrics.AddForwardedBytes("visitor_to_publisher", result.LeftToRight)
		s.config.Metrics.AddForwardedBytes("publisher_to_visitor", result.RightToLeft)
	}
	return err
}

func (s *Server) observeRelayAttempt(backend routebackend.Backend, outcome observability.RelayAttemptOutcome) {
	if s.config.Metrics == nil {
		return
	}
	slot := "unknown"
	if selected, ok := backend.(interface{ connectionSlot() string }); ok {
		slot = selected.connectionSlot()
	}
	s.config.Metrics.ObserveRelayAttempt(slot, outcome)
}

func (s *Server) reportForwardingFailure(route PublicURL, visitorID string, reason ForwardingFailureReason, attempts int) {
	if s.config.OnForwardingFailure != nil {
		s.config.OnForwardingFailure(route.ID, route.PublishRunNumber, visitorID, reason, attempts)
	}
}

func backendAttemptContext(ctx context.Context, remaining int) (context.Context, context.CancelFunc) {
	if remaining <= 1 {
		return context.WithCancel(ctx)
	}
	deadline, _ := ctx.Deadline()
	// reserve a share for each alternate even under a short overall deadline.
	return context.WithTimeout(ctx, min(alternateAttemptTimeout, time.Until(deadline)/time.Duration(remaining)))
}

func (s *Server) observeAttempt(index int, err error, started time.Time) {
	if s.config.Observer == nil {
		return
	}
	s.config.Observer.ObserveOperation("IngressBackendAttempt", err, time.Since(started))
	if index != 0 {
		s.config.Observer.ObserveOperation("IngressFallback", err, time.Since(started))
	}
}

// writeSetup counts visitor bytes separately from PROXY v2 metadata. a failed
// metadata write or a ClientHello failure before any visitor byte can be retried.
// join the cancellation callback before clearing the live stream's deadline.
func writeSetup(ctx context.Context, connection net.Conn, header, prefix []byte) (written int64, err error) {
	deadline, _ := ctx.Deadline()
	if err = connection.SetDeadline(deadline); err != nil {
		return
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = connection.SetDeadline(time.Now()); close(done) })
	defer func() {
		if !stop() {
			<-done
		}
		err = errors.Join(err, ctx.Err(), connection.SetDeadline(time.Time{}))
	}()
	if err = writeAll(connection, header); err != nil {
		return 0, fmt.Errorf("ingress: write proxy header: %w", err)
	}
	written, err = writeAllCount(connection, prefix)
	if err != nil {
		err = fmt.Errorf("ingress: write ClientHello: %w", err)
	}
	return
}

func writeAll(writer io.Writer, data []byte) error {
	_, err := writeAllCount(writer, data)
	return err
}

func writeAllCount(writer io.Writer, data []byte) (int64, error) {
	return io.Copy(writer, bytes.NewReader(data))
}
