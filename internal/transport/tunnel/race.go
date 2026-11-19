package tunnel

import (
	"context"
	"errors"
	"fmt"
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
	Observe   func(context.Context, Transport, time.Duration, error)
}

// Transport identifies one publisher connection transport.
type Transport string

const (
	TransportQUIC Transport = "quic"
	TransportWSS  Transport = "wss"
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
		if transport == TransportQUIC || transport == TransportWSS {
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
	attempt := func(candidate Candidate) func(context.Context) AttemptResult[candidateResult] {
		return func(raceCtx context.Context) AttemptResult[candidateResult] {
			started := time.Now()
			result := dialCandidate(raceCtx, candidate, hello)
			if candidate.Observe != nil {
				candidate.Observe(raceCtx, candidate.Transport, time.Since(started), result.err)
			}
			var protocolError *ProtocolError
			duplicate := errors.As(result.err, &protocolError) && protocolError.Code == tunnelv1.DuplicatePublisherConnection
			return AttemptResult[candidateResult]{Value: result, Accepted: result.session != nil,
				Err: result.err, CleanupErr: result.cleanupErr, Terminal: result.terminal, WaitForSibling: duplicate}
		}
	}
	winner, failures, err := RaceAttempts(ctx, fallbackDelay, attempt(primary), attempt(fallback), func(result candidateResult) error { return result.session.Close() })
	var cleanupErr, failed error
	for _, failure := range failures {
		cleanupErr = errors.Join(cleanupErr, failure.CleanupErr)
		failed = errors.Join(failed, failure.Err)
	}
	if winner.Accepted && (err != nil || cleanupErr != nil) {
		cleanupErr = errors.Join(cleanupErr, winner.Value.session.Close())
		winner.Accepted = false
	}
	if cleanupErr != nil {
		return nil, "", &SessionCleanupError{Err: errors.Join(err, failed, cleanupErr)}
	}
	if winner.Accepted {
		return winner.Value.session, winner.Value.transport, nil
	}
	return nil, "", fmt.Errorf("tunnel: all transport candidates failed: %w", err)
}

func dialCandidate(ctx context.Context, candidate Candidate, hello tunnelv1.Message) (result candidateResult) {
	ctx, finish := observability.Start(ctx, "tunnel.transport_candidate", trace.WithAttributes(observability.Transport.Value(boundedTransport(candidate.Transport))))
	started := time.Now()
	defer func() {
		err := errors.Join(result.err, result.cleanupErr)
		finish(err)
		if hello.Role == tunnelv1.Publisher {
			observability.PublisherTransportCandidate(ctx, string(candidate.Transport), time.Since(started), err)
		}
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
