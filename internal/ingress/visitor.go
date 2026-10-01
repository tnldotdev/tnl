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

var errBackendTrackingClosed = errors.New("ingress: backend tracking closed")

// forward resolves policy and admission before attempting a publisher stream.
// challenges use their own lookup and capacity; denied visitors retain their
// bounded publisher path for an HTTPS 403.
func (s *Server) forward(public net.Conn, source, destination netip.AddrPort, hello router.ClientHello) error {
	var route PublicURL
	var backends []routebackend.Backend
	var ok bool
	var challengeReason string
	challenge := hello.ACMETLSALPN
	visitorOutcome := "lookup_missing"
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
		var reason string
		route, reason = s.config.Lookup(hello.ServerName)
		ok = reason == ""
		switch reason {
		case "ingress_unavailable":
			visitorOutcome = "lookup_unavailable"
		case "invalid_projection":
			visitorOutcome = "invalid_projection"
		}
		backends = route.Backends
	}
	if challengeReason != "" || (!challenge && !ok) || len(backends) == 0 {
		if !challenge && ok {
			visitorOutcome = "lookup_unavailable"
		}
		if challenge && s.config.Metrics != nil {
			if challengeReason == "" {
				challengeReason = "unavailable"
			}
			s.config.Metrics.IncChallengeRejection(challengeReason)
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
	denied := !challenge && !ipAllowed(source.Addr(), route.AllowedIPPrefixes)
	if denied {
		visitorOutcome = "policy_denied"
		if usage != nil {
			usage.PolicyDenied(time.Now().UTC())
		}
	}
	kind, key := visitorConnection, route.ID
	if challenge {
		kind, key = challengeConnection, hello.ServerName
	} else if denied {
		kind = deniedConnection
	}
	release, rejected := s.admitClass(kind, key)
	if release == nil {
		s.rejectCapacity(rejected)
		if !challenge && !denied {
			visitorOutcome = "capacity_denied"
			if rejected == "draining" {
				visitorOutcome = "draining"
			}
		}
		if usage != nil {
			usage.CapacityDenied(time.Now().UTC())
		}
		return nil
	}
	defer release()
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
	openTimeout := s.config.OpenTimeout
	if challenge {
		openTimeout = min(openTimeout, time.Until(challengeDeadline))
	} else if denied {
		openTimeout = min(openTimeout, 2*time.Second)
	}
	openCtx, cancel := context.WithTimeout(s.openContext, openTimeout)
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
			visitorOutcome = "open_failed"
		}
		s.reportForwardingFailure(challenge, route, visitorID, "no_backend", len(backends))
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
			visitorOutcome = "committed_failed"
		}
		s.reportForwardingFailure(challenge, route, visitorID, "committed_write", len(backends))
		return fmt.Errorf("ingress: write ClientHello after %d bytes: %w", opened.bytes, opened.setupErr)
	}
	if challenge {
		if err := opened.connection.SetDeadline(challengeDeadline); err != nil {
			return err
		}
	}
	err = s.copyVisitor(public, opened.connection, hello.Remainder, route, denied, usage)
	if !denied {
		visitorOutcome = "forwarded"
		if err != nil {
			visitorOutcome = "committed_failed"
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
			s.observeRelayAttempt(backend, "open_failed")
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
			s.observeRelayAttempt(backend, "setup_failed")
			lastErr = errors.Join(writeErr, s.releaseBackend(candidate))
			continue
		}
		if writeErr != nil {
			s.observeRelayAttempt(backend, "committed_failed")
		} else {
			s.observeRelayAttempt(backend, "committed")
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

func (s *Server) observeRelayAttempt(backend routebackend.Backend, outcome string) {
	if s.config.Metrics == nil {
		return
	}
	slot := "unknown"
	if selected, ok := backend.(interface{ connectionSlot() string }); ok {
		slot = selected.connectionSlot()
	}
	s.config.Metrics.ObserveRelayAttempt(slot, outcome)
}

func (s *Server) reportForwardingFailure(challenge bool, route PublicURL, visitorID, reason string, attempts int) {
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
