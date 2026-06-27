package tunnel

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// Candidate is one transport implementation for the same logical endpoint.
type Candidate struct {
	Connector muxsession.Connector
	Endpoint  muxsession.Endpoint
}

type candidateResult struct {
	session  *Session
	err      error
	terminal bool
}

// Race establishes QUIC first and starts the fallback after fallbackDelay. The
// first candidate accepted by tunnelv1 wins; TLS completion alone cannot win.
func Race(
	ctx context.Context,
	primary Candidate,
	fallback Candidate,
	fallbackDelay time.Duration,
	hello tunnelv1.Message,
) (*Session, error) {
	if primary.Connector == nil || fallback.Connector == nil || fallbackDelay < 0 {
		return nil, errors.New("tunnel: two candidates and a non-negative fallback delay are required")
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
	for remaining > 0 {
		select {
		case <-ctx.Done():
			cancel()
			closeLateWinner(results, remaining)
			return nil, context.Cause(ctx)
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
				return result.session, nil
			}
			failures = append(failures, result.err)
			if result.terminal {
				cancel()
				closeLateWinner(results, remaining)
				return nil, result.err
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
	return nil, fmt.Errorf("tunnel: all transport candidates failed: %w", errors.Join(failures...))
}

func dialCandidate(ctx context.Context, candidate Candidate, hello tunnelv1.Message) candidateResult {
	transport, err := candidate.Connector.Connect(ctx, candidate.Endpoint)
	if err != nil {
		return candidateResult{err: err}
	}
	session, err := Dial(ctx, transport, hello)
	if err == nil {
		return candidateResult{session: session}
	}
	var protocolError *ProtocolError
	terminal := errors.As(err, &protocolError) && protocolError.Code != tunnelv1.Unavailable &&
		protocolError.Code != tunnelv1.CapacityExceeded && protocolError.Code != tunnelv1.Internal
	return candidateResult{err: err, terminal: terminal}
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
