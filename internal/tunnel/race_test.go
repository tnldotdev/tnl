package tunnel

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestRacePrimarySuccessDoesNotStartFallback(t *testing.T) {
	var primaryCalls, fallbackCalls atomic.Int32
	primary, fallback := authenticatedConnector(t, &primaryCalls), authenticatedConnector(t, &fallbackCalls)
	s, transport, err := Race(tunnelContext(t), Candidate{Connector: primary, Transport: TransportQUIC}, Candidate{Connector: fallback, Transport: TransportTLSTCP}, time.Hour, publisherHello())
	if s != nil {
		t.Cleanup(func() { _ = s.Close() })
	}
	if err != nil || transport != TransportQUIC || primaryCalls.Load() != 1 || fallbackCalls.Load() != 0 {
		t.Fatalf("race: %s, %v; calls %d/%d", transport, err, primaryCalls.Load(), fallbackCalls.Load())
	}
}

func TestRaceUsesFallbackAfterPrimaryFailure(t *testing.T) {
	var calls atomic.Int32
	fallback := authenticatedConnector(t, &calls)
	primary := muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
		return nil, errors.New("UDP unavailable")
	})
	s, transport, err := Race(tunnelContext(t), Candidate{Connector: primary, Transport: TransportQUIC}, Candidate{Connector: fallback, Transport: TransportTLSTCP}, time.Hour, publisherHello())
	if s != nil {
		t.Cleanup(func() { _ = s.Close() })
	}
	if err != nil || transport != TransportTLSTCP || calls.Load() != 1 {
		t.Fatalf("race=%s, %v; fallback=%d", transport, err, calls.Load())
	}
}

func TestRaceStopsOnTerminalProtocolError(t *testing.T) {
	var calls atomic.Int32
	fallback := authenticatedConnector(t, &calls)
	_, _, err := Race(tunnelContext(t), Candidate{Connector: rejectingConnector(t, tunnelv1.Unauthenticated), Transport: TransportQUIC}, Candidate{Connector: fallback, Transport: TransportTLSTCP}, time.Hour, publisherHello())
	var p *ProtocolError
	if !errors.As(err, &p) || p.Code != tunnelv1.Unauthenticated || calls.Load() != 0 {
		t.Fatalf("race=%v; fallback=%d", err, calls.Load())
	}
}

func TestRaceDuplicateClaimRemainsTerminalWithoutRunningSibling(t *testing.T) {
	var calls atomic.Int32
	fallback := authenticatedConnector(t, &calls)
	_, _, err := Race(tunnelContext(t), Candidate{Connector: rejectingConnector(t, tunnelv1.DuplicatePublisherConnection), Transport: TransportQUIC}, Candidate{Connector: fallback, Transport: TransportTLSTCP}, time.Hour, publisherHello())
	var protocolError *ProtocolError
	if !errors.As(err, &protocolError) || protocolError.Code != tunnelv1.DuplicatePublisherConnection || calls.Load() != 0 {
		t.Fatalf("race=%v; fallback=%d", err, calls.Load())
	}
}

func TestRaceDuplicateClaimDoesNotCancelRunningSibling(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fallbackStarted := make(chan struct{})
		primary := rejectingConnectorAfter(t, fallbackStarted, tunnelv1.DuplicatePublisherConnection)
		var calls atomic.Int32
		authenticated := authenticatedConnector(t, &calls)
		fallback := muxsession.ConnectorFunc(func(ctx context.Context, endpoint muxsession.Endpoint) (muxsession.Session, error) {
			close(fallbackStarted)
			time.Sleep(time.Second)
			return authenticated.Connect(ctx, endpoint)
		})
		session, transport, err := Race(
			t.Context(),
			Candidate{Connector: primary, Transport: TransportQUIC},
			Candidate{Connector: fallback, Transport: TransportTLSTCP},
			0,
			publisherHello(),
		)
		if session != nil {
			t.Cleanup(func() { _ = session.Close() })
		}
		if err != nil || transport != TransportTLSTCP || calls.Load() != 1 {
			t.Fatalf("race: %s, %v; fallback=%d", transport, err, calls.Load())
		}
	})
}

func TestRaceDuplicateClaimDoesNotWaitPastSiblingSetupDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fallbackStarted := make(chan struct{})
		primary := rejectingConnectorAfter(t, fallbackStarted, tunnelv1.DuplicatePublisherConnection)
		fallback := muxsession.ConnectorFunc(func(ctx context.Context, _ muxsession.Endpoint) (muxsession.Session, error) {
			close(fallbackStarted)
			<-ctx.Done()
			return nil, context.Cause(ctx)
		})
		_, _, err := Race(
			t.Context(),
			Candidate{Connector: primary, Transport: TransportQUIC},
			Candidate{Connector: fallback, Transport: TransportTLSTCP},
			0,
			publisherHello(),
		)
		var protocolError *ProtocolError
		if !errors.As(err, &protocolError) || protocolError.Code != tunnelv1.DuplicatePublisherConnection {
			t.Fatalf("race = %v", err)
		}
	})
}

func TestRaceRetriesDrainingPublisherConnection(t *testing.T) {
	var calls atomic.Int32
	fallback := authenticatedConnector(t, &calls)
	session, transport, err := Race(
		tunnelContext(t),
		Candidate{Connector: rejectingConnector(t, tunnelv1.DrainingPublisherConnection), Transport: TransportQUIC},
		Candidate{Connector: fallback, Transport: TransportTLSTCP},
		time.Hour,
		publisherHello(),
	)
	if session != nil {
		t.Cleanup(func() { _ = session.Close() })
	}
	if err != nil || transport != TransportTLSTCP || calls.Load() != 1 {
		t.Fatalf("race: %s, %v; fallback=%d", transport, err, calls.Load())
	}
}

func TestRaceTransportWithoutAuthenticationCannotWin(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pending := make(chan struct{})
		primary, transport := handshakeConnector(t, func(ctx context.Context, _ tunnelv1.Message) error {
			close(pending)
			<-ctx.Done()
			return ctx.Err()
		})
		var calls atomic.Int32
		fallback := authenticatedConnector(t, &calls)
		s, winner, err := Race(tunnelContext(t), Candidate{Connector: primary, Transport: TransportQUIC}, Candidate{Connector: fallback, Transport: TransportTLSTCP}, time.Second, publisherHello())
		if s != nil {
			t.Cleanup(func() { _ = s.Close() })
		}
		if err != nil || winner != TransportTLSTCP {
			t.Fatalf("unauthenticated winner: %s, %v", winner, err)
		}
		await(t, pending)
		// Close the deliberately stalled peer to release the losing handshake.
		_ = transport.Close()
	})
}

func TestRaceCancellationStopsBothCandidates(t *testing.T) {
	ctx, cancel := context.WithCancel(tunnelContext(t))
	t.Cleanup(cancel)
	started, finished := make(chan struct{}, 2), make(chan struct{}, 2)
	blocked := muxsession.ConnectorFunc(func(ctx context.Context, _ muxsession.Endpoint) (muxsession.Session, error) {
		started <- struct{}{}
		<-ctx.Done()
		finished <- struct{}{}
		return nil, context.Cause(ctx)
	})
	done := make(chan error, 1)
	joined := make(chan struct{})
	t.Cleanup(func() { cancel(); await(t, joined) })
	go func() {
		defer close(joined)
		_, _, err := Race(ctx, Candidate{Connector: blocked, Transport: TransportQUIC}, Candidate{Connector: blocked, Transport: TransportTLSTCP}, 0, publisherHello())
		done <- err
	}()
	await(t, started)
	await(t, started)
	cancel()
	if err := await(t, done); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	await(t, finished)
	await(t, finished)
}

func TestRaceTerminalRejectionAfterBothStarted(t *testing.T) {
	started, stopped := make(chan struct{}), make(chan struct{})
	primary := rejectingConnectorAfter(t, started, tunnelv1.StaleConnectionAssignment)
	fallback := muxsession.ConnectorFunc(func(ctx context.Context, _ muxsession.Endpoint) (muxsession.Session, error) {
		defer close(stopped)
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	t.Cleanup(func() { await(t, stopped) })
	_, _, err := Race(tunnelContext(t), Candidate{Connector: primary, Transport: TransportQUIC}, Candidate{Connector: fallback, Transport: TransportTLSTCP}, 0, publisherHello())
	var p *ProtocolError
	if !errors.As(err, &p) || p.Code != tunnelv1.StaleConnectionAssignment {
		t.Fatalf("terminal rejection: %v", err)
	}
}

func rejectingConnectorAfter(t *testing.T, gate <-chan struct{}, code tunnelv1.ErrorCode) muxsession.Connector {
	connector, _ := handshakeConnector(t, func(ctx context.Context, _ tunnelv1.Message) error {
		select {
		case <-gate:
			return &ProtocolError{Code: code}
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	return connector
}

func TestRaceClosesLateSuccessfulLoser(t *testing.T) {
	// Pause the fallback after hello_accepted, immediately before Dial returns.
	// This models a successful result already in flight when the winner cancels.
	entered, release := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	fallback, loser := handshakeConnector(t, func(context.Context, tunnelv1.Message) error { return nil })
	wrapped := muxsession.ConnectorFunc(func(ctx context.Context, e muxsession.Endpoint) (muxsession.Session, error) {
		s, err := fallback.Connect(ctx, e)
		return &gatedDeadlineSession{Session: s, entered: entered, release: release}, err
	})
	primary, _ := handshakeConnector(t, func(ctx context.Context, _ tunnelv1.Message) error {
		select {
		case <-entered:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	t.Cleanup(unblock)
	s, winner, err := Race(tunnelContext(t), Candidate{Connector: primary, Transport: TransportQUIC}, Candidate{Connector: wrapped, Transport: TransportTLSTCP}, 0, publisherHello())
	if s != nil {
		t.Cleanup(func() { _ = s.Close() })
	}
	if err != nil || winner != TransportQUIC {
		t.Fatalf("race: %s, %v", winner, err)
	}
	unblock()
	await(t, loser.Done())
}

type gatedDeadlineSession struct {
	muxsession.Session
	entered chan struct{}
	release <-chan struct{}
}

func (s *gatedDeadlineSession) OpenStream(ctx context.Context) (muxsession.Stream, error) {
	stream, err := s.Session.OpenStream(ctx)
	if err != nil {
		return nil, err
	}
	return &gatedDeadlineStream{Stream: stream, entered: s.entered, release: s.release}, nil
}

type gatedDeadlineStream struct {
	muxsession.Stream
	entered chan struct{}
	release <-chan struct{}
}

func (s *gatedDeadlineStream) SetDeadline(at time.Time) error {
	if at.IsZero() {
		close(s.entered)
		<-s.release
	}
	return s.Stream.SetDeadline(at)
}

func TestRacePreservesBothTransportFailures(t *testing.T) {
	one, two := errors.New("QUIC failed"), errors.New("TLS failed")
	failed := func(err error) muxsession.Connector {
		return muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) { return nil, err })
	}
	s, transport, err := Race(tunnelContext(t), Candidate{Connector: failed(one), Transport: TransportQUIC}, Candidate{Connector: failed(two), Transport: TransportTLSTCP}, time.Hour, publisherHello())
	if s != nil || transport != "" || !errors.Is(err, one) || !errors.Is(err, two) {
		t.Fatalf("both failures: %v, %s, %v", s, transport, err)
	}
}
