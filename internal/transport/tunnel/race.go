package tunnel

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
	"go.opentelemetry.io/otel/trace"
)

// Candidate is one way to connect to a relay address.
type Candidate struct {
	Connector muxsession.Connector
	Endpoint  muxsession.Endpoint
	Transport Transport
}

// Transport identifies one publisher connection transport.
type Transport string

const (
	TransportQUIC   Transport = "quic"
	TransportTLSTCP Transport = "tls-tcp"
)

type candidateResult struct {
	session    *Session
	transport  Transport
	err        error
	cleanupErr error
	terminal   bool
}

// Race starts the primary candidate, then the fallback after fallbackDelay.
// the first authenticated publisher connection wins, not the first TLS handshake.
// a duplicate claim waits for a running sibling; other permanent rejections
// stop both attempts. Race cancels and joins every started candidate, including
// handshake cleanup and observations, before returning. it never retries streams.
func Race(
	ctx context.Context,
	primary Candidate,
	fallback Candidate,
	fallbackDelay time.Duration,
	hello tunnelv1.Message,
) (session *Session, transport Transport, retErr error) {
	ctx, finish := observability.Start(ctx, "tunnel.transport_race", trace.WithAttributes(observability.TransportPreference.Value(boundedTransport(primary.Transport))))
	defer func() {
		if transport == TransportQUIC || transport == TransportTLSTCP {
			trace.SpanFromContext(ctx).SetAttributes(observability.Transport.Value(boundedTransport(transport)))
		}
		finish(retErr)
	}()
	if primary.Connector == nil || fallback.Connector == nil || primary.Transport == "" || fallback.Transport == "" || fallbackDelay < 0 {
		return nil, "", errors.New("tunnel: two candidates and a non-negative fallback delay are required")
	}
	if cause := context.Cause(ctx); cause != nil {
		return nil, "", errors.Join(ctx.Err(), cause)
	}
	raceCtx, cancel := context.WithCancel(ctx)
	results := make(chan candidateResult, 2)
	var workers sync.WaitGroup
	remaining := 0
	var failures []error
	var cleanupErr error
	defer func() {
		cancel()
		for range remaining {
			result := <-results
			failures = append(failures, result.err)
			cleanupErr = errors.Join(cleanupErr, result.cleanupErr)
			if result.session != nil {
				cleanupErr = errors.Join(cleanupErr, result.session.Close())
			}
		}
		workers.Wait()
		if cause := context.Cause(ctx); cause != nil {
			retErr = errors.Join(retErr, ctx.Err(), cause)
		}
		if session != nil && (retErr != nil || cleanupErr != nil) {
			cleanupErr = errors.Join(cleanupErr, session.Close())
			session, transport = nil, ""
		}
		if cleanupErr != nil {
			retErr = &SessionCleanupError{Err: errors.Join(retErr, errors.Join(failures...), cleanupErr)}
		}
	}()
	start := func(candidate Candidate) {
		remaining++
		workers.Go(func() { results <- dialCandidate(raceCtx, candidate, hello) })
	}
	start(primary)
	timer := time.NewTimer(fallbackDelay)
	defer timer.Stop()
	fallbackStarted := false
	var duplicateFailure error
	for remaining > 0 {
		select {
		case <-ctx.Done():
			return nil, "", context.Cause(ctx)
		case <-timer.C:
			if !fallbackStarted {
				fallbackStarted = true
				start(fallback)
			}
		case result := <-results:
			remaining--
			cleanupErr = errors.Join(cleanupErr, result.cleanupErr)
			if result.session != nil {
				return result.session, result.transport, nil
			}
			failures = append(failures, result.err)
			if result.terminal {
				var protocolError *ProtocolError
				if errors.As(result.err, &protocolError) && protocolError.Code == tunnelv1.DuplicatePublisherConnection && remaining > 0 {
					duplicateFailure = result.err
					continue
				}
				return nil, "", result.err
			}
			if !fallbackStarted {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				fallbackStarted = true
				start(fallback)
			}
		}
	}
	if duplicateFailure != nil {
		return nil, "", duplicateFailure
	}
	return nil, "", fmt.Errorf("tunnel: all transport candidates failed: %w", errors.Join(failures...))
}

func dialCandidate(ctx context.Context, candidate Candidate, hello tunnelv1.Message) (result candidateResult) {
	ctx, finish := observability.Start(ctx, "tunnel.transport_candidate", trace.WithAttributes(observability.Transport.Value(boundedTransport(candidate.Transport))))
	started := time.Now()
	defer func() {
		err := errors.Join(result.err, result.cleanupErr)
		finish(err)
		observability.PublisherTransportCandidate(ctx, string(candidate.Transport), time.Since(started), err)
	}()
	setupCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	if cause := context.Cause(setupCtx); cause != nil {
		return candidateResult{err: errors.Join(setupCtx.Err(), cause)}
	}
	transport, err := candidate.Connector.Connect(setupCtx, candidate.Endpoint)
	if err != nil {
		var cleanup *muxsession.QUICTransportCloseError
		var cleanupErr error
		if errors.As(err, &cleanup) {
			cleanupErr = err
		}
		return candidateResult{err: err, cleanupErr: cleanupErr}
	}
	if peer, ok := transport.(muxsession.AcceptedPeer); ok {
		trace.SpanFromContext(ctx).SetAttributes(observability.TLSAttributes(peer.TLSConnectionState())...)
	}
	dialed := dial(setupCtx, transport, hello, "", false)
	return candidateResult{session: dialed.session, transport: candidate.Transport,
		err: dialed.err, cleanupErr: dialed.cleanupErr, terminal: IsTerminalHandshakeError(dialed.err)}
}

func boundedTransport(transport Transport) observability.TransportValue {
	value, _ := observability.ParseTransport(string(transport))
	return value
}

// IsTerminalHandshakeError reports whether a protocol rejection must stop both
// attempts for this connection assignment. network failures and temporary server
// errors can use the other transport. this result does not allow a claimed
// connection to reconnect.
func IsTerminalHandshakeError(err error) bool {
	var protocolError *ProtocolError
	return errors.As(err, &protocolError) && protocolError.Code != tunnelv1.Unavailable &&
		protocolError.Code != tunnelv1.CapacityExceeded && protocolError.Code != tunnelv1.DrainingPublisherConnection &&
		protocolError.Code != tunnelv1.Internal
}
