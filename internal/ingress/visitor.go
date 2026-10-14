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
	"github.com/tnldotdev/tnl/internal/streamcopy"
)

type committedVisitorStream struct {
	connection net.Conn
	bytes      int64
	setupErr   error
}

type visitorSelection uint8

const (
	hostnameSelection visitorSelection = iota
	portSelection
	challengeSelection
)

var errBackendTrackingClosed = errors.New("ingress: backend tracking closed")

// forward resolves policy and admission before attempting a publisher stream.
// challenges use their own lookup and capacity; denied visitors retain their
// bounded publisher path for an HTTPS 403.
func (s *Server) forward(public net.Conn, source, destination netip.AddrPort, hello router.ClientHello) error {
	selection := hostnameSelection
	if hello.ACMETLSALPN {
		selection = challengeSelection
	}
	return s.forwardSelected(public, source, destination, hello, selection)
}

func (s *Server) forwardPort(public net.Conn, source, destination netip.AddrPort, reader io.Reader) error {
	return s.forwardSelected(public, source, destination, router.ClientHello{Remainder: reader}, portSelection)
}

func (s *Server) forwardSelected(public net.Conn, source, destination netip.AddrPort, hello router.ClientHello, selection visitorSelection) error {
	var route PublicURL
	var backends []routebackend.Backend
	var ok bool
	var challengeReason LookupReason
	challenge, byPort := selection == challengeSelection, selection == portSelection
	visitorOutcome := observability.VisitorLookupMissing
	visitorStarted := time.Now()
	if !challenge && s.config.Metrics != nil {
		defer func() { s.config.Metrics.ObserveVisitor(visitorOutcome) }()
	}
	// an ALPN claim alone cannot authorize challenge forwarding. require an
	// exact, currently live challenge from control; never fall back to a public URL.
	if challenge {
		if s.config.LookupChallenge == nil {
			if s.config.Metrics != nil {
				s.config.Metrics.IncChallengeRejection("unconfigured")
			}
			return nil
		}
		backends, challengeReason = s.config.LookupChallenge(hello.ServerName)
	} else {
		var reason LookupReason
		if byPort {
			route, reason = s.config.LookupPort(destination.Port())
		} else {
			route, reason = s.config.Lookup(hello.ServerName)
		}
		if reason == LookupCurrent && (byPort && (route.PublicPort == nil || *route.PublicPort != destination.Port()) ||
			!byPort && route.PublicPort != nil) {
			reason = LookupInvalidProjection
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
	if challengeReason != LookupCurrent || (!challenge && !ok) || len(backends) == 0 {
		if !challenge && ok {
			visitorOutcome = observability.VisitorLookupUnavailable
		}
		if challenge && s.config.Metrics != nil {
			if challengeReason == LookupCurrent {
				challengeReason = LookupNoBackends
			}
			s.config.Metrics.IncChallengeRejection(string(challengeReason))
		}
		return nil
	}
	var usage UsageConnection
	if !challenge && s.config.OpenUsage != nil {
		usage = s.config.OpenUsage(route.ID, route.PublishRunNumber, source.Addr(), time.Now().UTC())
		if usage != nil {
			defer func() { usage.Close(time.Now().UTC()) }()
		}
	}
	denied := !challenge && !route.allowsIP(source.Addr())
	if denied {
		visitorOutcome = observability.VisitorPolicyDenied
		// database visitors have no HTTPS denial response. do not send their
		// startup bytes to the publisher when ingress has denied the source.
		if byPort {
			if usage != nil {
				usage.PolicyDenied(time.Now().UTC())
			}
			return nil
		}
	}
	trafficLimits := s.config.Traffic.Default
	if route.Traffic != nil {
		if !route.Traffic.Within(s.config.Traffic.Ceiling) {
			visitorOutcome = observability.VisitorInvalidProjection
			return nil
		}
		trafficLimits = *route.Traffic
	}
	kind, key := visitorConnection, route.ID
	if challenge {
		kind, key = challengeConnection, hello.ServerName
	} else if denied {
		kind = deniedConnection
	}
	trafficKey := trafficKey{url: route.ID, run: route.PublishRunNumber}
	if denied {
		if allowed, reason := s.traffic.allowPendingAttempt(trafficKey, source.Addr(), s.config.PendingURLRate, s.config.PendingURLBurst,
			s.config.PendingSourceRate, s.config.PendingSourceBurst); !allowed {
			s.rejectCapacity(reason)
			visitorOutcome = observability.VisitorCapacityDenied
			if usage != nil {
				usage.CapacityDenied(time.Now().UTC())
			}
			return nil
		}
	}
	var release func()
	var rejected string
	if denied {
		release, rejected = s.admitPending(key, pendingSourceNetwork(source.Addr()), trafficLimits.Connections)
	} else {
		release, rejected = s.admitClass(kind, key, trafficLimits.Connections)
	}
	if release == nil {
		s.rejectCapacity(rejected)
		if !challenge && !denied {
			visitorOutcome = observability.VisitorCapacityDenied
			if rejected == "draining" {
				visitorOutcome = observability.VisitorDraining
			}
		}
		if usage != nil {
			if denied {
				usage.PolicyDenied(time.Now().UTC())
			}
			usage.CapacityDenied(time.Now().UTC())
		}
		return nil
	}
	ticket := &classTicket{release: release}
	if denied {
		ticket.deadline = time.Now().Add(pendingAuthorizationTimeout)
		ticket.pendingByteLimit = s.config.PendingConnectionBytes
		if usage != nil {
			defer func() {
				if !ticket.isPromoted() {
					usage.PolicyDenied(time.Now().UTC())
				}
			}()
		}
	}
	defer ticket.close()
	if kind == visitorConnection && !s.traffic.allowConnection(trafficKey, trafficLimits) {
		s.rejectCapacity("public_url_connection_rate")
		visitorOutcome = observability.VisitorCapacityDenied
		if usage != nil {
			usage.CapacityDenied(time.Now().UTC())
		}
		return nil
	}
	var challengeDeadline time.Time
	if challenge {
		challengeDeadline = time.Now().Add(challengeConnectionTimeout)
		if err := public.SetDeadline(challengeDeadline); err != nil {
			return err
		}
	}

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
	visitorID, err := opaqueid.New(visitorConnectionIDPrefix)
	if err != nil {
		return fmt.Errorf("ingress: create visitor connection ID: %w", err)
	}
	if denied {
		unregister := s.registerPendingVisitor(visitorID, &pendingVisitorState{
			ticket: ticket, urlID: route.ID, run: route.PublishRunNumber,
			hostname: hello.ServerName, port: destination.Port(), byPort: byPort,
			deadline: ticket.deadline,
		})
		defer unregister()
	}
	openTimeout := s.config.OpenTimeout
	if challenge {
		openTimeout = min(openTimeout, time.Until(challengeDeadline))
	} else if denied {
		openTimeout = min(openTimeout, 2*time.Second)
	}
	openCtx, cancel := context.WithTimeout(s.openContext, openTimeout)
	if kind == visitorConnection {
		if err := s.traffic.waitBytes(openCtx, trafficKey, true, len(hello.Prefix), trafficLimits); err != nil {
			cancel()
			if errors.Is(err, errProcessBandwidth) || errors.Is(err, errPublicURLBandwidth) {
				reason := "public_url_upload_rate"
				if errors.Is(err, errProcessBandwidth) {
					reason = "process_upload_rate"
				}
				s.rejectCapacity(reason)
			}
			visitorOutcome = observability.VisitorCapacityDenied
			if usage != nil {
				usage.CapacityDenied(time.Now().UTC())
			}
			return nil
		}
	}
	opened, openErr := s.openVisitorStream(openCtx, backends, visitorID, kind, header, hello.Prefix, usage)
	cancel()
	if errors.Is(openErr, errBackendTrackingClosed) {
		return net.ErrClosed
	}
	if !challenge && s.config.Metrics != nil {
		s.config.Metrics.ObserveVisitorOpen(opened.connection != nil && opened.setupErr == nil, time.Since(visitorStarted))
	}
	if openErr != nil {
		if !denied {
			visitorOutcome = observability.VisitorOpenFailed
		}
		s.reportForwardingFailure(challenge, route, visitorID, ForwardingNoBackend, len(backends))
		return openErr
	}
	defer s.releaseBackend(opened.connection)
	if usage != nil {
		usage.StreamOpened(time.Now().UTC())
		usage.AddIngress(opened.bytes, time.Now().UTC())
		streamCommitted = true
	}
	if s.config.Metrics != nil {
		s.config.Metrics.AddForwardedBytes("visitor_to_publisher", opened.bytes)
	}
	if opened.setupErr != nil {
		if !denied {
			visitorOutcome = observability.VisitorCommittedFailed
		}
		s.reportForwardingFailure(challenge, route, visitorID, ForwardingCommittedWrite, len(backends))
		return fmt.Errorf("ingress: write visitor setup after %d bytes: %w", opened.bytes, opened.setupErr)
	}
	if challenge {
		if err := opened.connection.SetDeadline(challengeDeadline); err != nil {
			return err
		}
	}
	if denied {
		if err := ticket.setPendingDeadline(public, opened.connection); err != nil {
			return err
		}
	}
	err = s.copyVisitor(public, opened.connection, hello.Remainder, route, denied, ticket, usage)
	if !denied || ticket.isPromoted() {
		visitorOutcome = observability.VisitorForwarded
		if err != nil {
			visitorOutcome = observability.VisitorCommittedFailed
		}
	}
	return err
}

// openVisitorStream retries only before a visitor byte reaches a relay. the
// returned connection is owned by the caller even when its setup write failed.
func (s *Server) openVisitorStream(ctx context.Context, backends []routebackend.Backend, visitorID string, kind connectionKind, header, prefix []byte, usage UsageConnection) (committedVisitorStream, error) {
	opened := false
	// rotate ordinary visitors across connected relays. challenge forwarding
	// keeps control's order and uses the same bounded retry path.
	firstBackend := 0
	if kind != challengeConnection && len(backends) > 1 {
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
		if kind == deniedConnection {
			if denialBackend, ok := backend.(routebackend.DenialBackend); ok {
				candidate, openErr = denialBackend.OpenDenied(attemptCtx, visitorID)
			} else {
				openErr = errors.New("ingress: backend does not support denied connections")
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

func (s *Server) copyVisitor(public, upstream net.Conn, remainder io.Reader, route PublicURL, denied bool, ticket *classTicket, usage UsageConnection) error {
	replayed := &readerConn{Conn: public, reader: remainder}
	var left, right net.Conn = replayed, upstream
	if route.ID != "" {
		key := trafficKey{url: route.ID, run: route.PublishRunNumber}
		limits := s.config.Traffic.Default
		if route.Traffic != nil {
			limits = *route.Traffic
		}
		left = &budgetConn{Conn: replayed, ctx: s.openContext, beforeWrite: func(ctx context.Context, size int) error {
			if denied {
				if err := ticket.pendingBytesAllowed(size); err != nil {
					if errors.Is(err, errPendingBytes) {
						s.rejectCapacity("pending_bytes")
					}
					return err
				}
				if !ticket.isPromoted() {
					return nil
				}
			}
			err := s.traffic.waitBytes(ctx, key, false, size, limits)
			if errors.Is(err, errProcessBandwidth) || errors.Is(err, errPublicURLBandwidth) {
				reason := "public_url_download_rate"
				if errors.Is(err, errProcessBandwidth) {
					reason = "process_download_rate"
				}
				s.rejectCapacity(reason)
			}
			return err
		}}
		right = &budgetConn{Conn: upstream, ctx: s.openContext, beforeWrite: func(ctx context.Context, size int) error {
			if denied {
				if err := ticket.pendingBytesAllowed(size); err != nil {
					if errors.Is(err, errPendingBytes) {
						s.rejectCapacity("pending_bytes")
					}
					return err
				}
				if !ticket.isPromoted() {
					return nil
				}
			}
			err := s.traffic.waitBytes(ctx, key, true, size, limits)
			if errors.Is(err, errProcessBandwidth) || errors.Is(err, errPublicURLBandwidth) {
				reason := "public_url_upload_rate"
				if errors.Is(err, errProcessBandwidth) {
					reason = "process_upload_rate"
				}
				s.rejectCapacity(reason)
			}
			return err
		}}
	}
	var observeIngress, observeEgress func(int64)
	if usage != nil {
		observeIngress = func(bytes int64) { usage.AddIngress(bytes, time.Now().UTC()) }
	}
	if usage != nil || route.RecoveryEpisodeID != 0 && s.config.ObserveRecovery != nil {
		var recoveryOnce sync.Once
		observeEgress = func(bytes int64) {
			now := time.Now().UTC()
			if usage != nil {
				usage.AddEgress(bytes, now)
			}
			if (!denied || ticket.isPromoted()) && route.RecoveryEpisodeID != 0 && s.config.ObserveRecovery != nil {
				recoveryOnce.Do(func() {
					s.config.ObserveRecovery(route.ID, route.PublishRunNumber, route.RecoveryEpisodeID, now)
				})
			}
		}
	}
	result, err := streamcopy.CopyObserved(left, right, observeIngress, observeEgress)
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

func (s *Server) reportForwardingFailure(challenge bool, route PublicURL, visitorID string, reason ForwardingFailureReason, attempts int) {
	if !challenge && s.config.OnForwardingFailure != nil {
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
