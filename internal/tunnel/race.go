package tunnel

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
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
	session   *Session
	transport Transport
	err       error
	terminal  bool
}

// Race starts the primary candidate, then the fallback after fallbackDelay.
// the first authenticated publisher connection wins, not the first TLS handshake.
// a duplicate claim waits for a running sibling; other permanent rejections
// stop both attempts. this race does not retry visitor streams.
func Race(
	ctx context.Context,
	primary Candidate,
	fallback Candidate,
	fallbackDelay time.Duration,
	hello tunnelv1.Message,
) (*Session, Transport, error) {
	if primary.Connector == nil || fallback.Connector == nil || primary.Transport == "" || fallback.Transport == "" || fallbackDelay < 0 {
		return nil, "", errors.New("tunnel: two candidates and a non-negative fallback delay are required")
	}
	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan candidateResult, 2)
	start := func(candidate Candidate) {
		go func() { results <- dialCandidate(raceCtx, candidate, hello) }()
	}
	start(primary)
	timer := time.NewTimer(fallbackDelay)
	defer timer.Stop()
	fallbackStarted := false
	remaining := 1
	var failures []error
	var duplicateFailure error
	for remaining > 0 {
		select {
		case <-ctx.Done():
			cancel()
			closeLateWinner(results, remaining)
			return nil, "", context.Cause(ctx)
		case <-timer.C:
			if !fallbackStarted {
				fallbackStarted = true
				remaining++
				start(fallback)
			}
		case result := <-results:
			remaining--
			if result.session != nil {
				cancel()
				closeLateWinner(results, remaining)
				return result.session, result.transport, nil
			}
			failures = append(failures, result.err)
			if result.terminal {
				var protocolError *ProtocolError
				if errors.As(result.err, &protocolError) && protocolError.Code == tunnelv1.DuplicatePublisherConnection && remaining > 0 {
					duplicateFailure = result.err
					continue
				}
				cancel()
				closeLateWinner(results, remaining)
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
				remaining++
				start(fallback)
			}
		}
	}
	if duplicateFailure != nil {
		return nil, "", duplicateFailure
	}
	return nil, "", fmt.Errorf("tunnel: all transport candidates failed: %w", errors.Join(failures...))
}

func dialCandidate(ctx context.Context, candidate Candidate, hello tunnelv1.Message) candidateResult {
	setupCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	transport, err := candidate.Connector.Connect(setupCtx, candidate.Endpoint)
	if err != nil {
		return candidateResult{err: err}
	}
	session, err := Dial(setupCtx, transport, hello)
	if err == nil {
		return candidateResult{session: session, transport: candidate.Transport}
	}
	return candidateResult{err: err, terminal: IsTerminalHandshakeError(err)}
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

func closeLateWinner(results <-chan candidateResult, remaining int) {
	if remaining == 0 {
		return
	}
	go func() {
		for range remaining {
			result := <-results
			if result.session != nil {
				_ = result.session.Close()
			}
		}
	}()
}
