package tunnel

import (
	"context"
	"errors"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func RacePrivateConnector(ctx context.Context, primary, fallback Candidate, delay time.Duration, hello tunnelv1.PrivateConnectorSessionHello) (*PrivateConnectorSession, Transport, error) {
	if primary.Connector == nil || fallback.Connector == nil || delay < 0 {
		return nil, "", errors.New("tunnel: two private transport candidates are required")
	}
	type result struct {
		session   *PrivateConnectorSession
		transport Transport
		err       error
	}
	setup, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan result, 2)
	start := func(candidate Candidate) {
		go func() {
			attempt, stop := context.WithTimeout(setup, handshakeTimeout)
			defer stop()
			transport, err := candidate.Connector.Connect(attempt, candidate.Endpoint)
			if err != nil {
				results <- result{err: err}
				return
			}
			session, err := DialPrivateConnector(attempt, transport, hello)
			results <- result{session: session, transport: candidate.Transport, err: err}
		}()
	}
	remaining := 1
	started := false
	start(primary)
	timer := time.NewTimer(delay)
	defer timer.Stop()
	cleanup := func() {
		cancel()
		count := remaining
		go func() {
			for range count {
				r := <-results
				if r.session != nil {
					_ = r.session.Close()
				}
			}
		}()
	}
	var failures error
	for remaining > 0 {
		select {
		case <-ctx.Done():
			cleanup()
			return nil, "", context.Cause(ctx)
		case <-timer.C:
			if !started {
				started = true
				remaining++
				start(fallback)
			}
		case r := <-results:
			remaining--
			if r.session != nil {
				cleanup()
				return r.session, r.transport, nil
			}
			failures = errors.Join(failures, r.err)
			if !started {
				started = true
				remaining++
				start(fallback)
			}
		}
	}
	return nil, "", failures
}
