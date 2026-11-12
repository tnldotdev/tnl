package tunnel

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
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
	metrics := observability.New("publisher")
	t.Cleanup(func() { _ = metrics.Shutdown(context.Background()) })
	var calls atomic.Int32
	fallback := authenticatedConnector(t, &calls)
	primary := muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
		return nil, errors.New("UDP unavailable")
	})
	observed := make(chan struct {
		transport Transport
		failed    bool
	}, 2)
	observe := func(_ context.Context, transport Transport, elapsed time.Duration, err error) {
		if elapsed < 0 {
			t.Error("negative attempt duration")
		}
		observed <- struct {
			transport Transport
			failed    bool
		}{transport, err != nil}
	}
	s, transport, err := Race(observability.WithMetrics(tunnelContext(t), metrics), Candidate{Connector: primary, Transport: TransportQUIC, Observe: observe}, Candidate{Connector: fallback, Transport: TransportTLSTCP, Observe: observe}, time.Hour, publisherHello())
	if s != nil {
		t.Cleanup(func() { _ = s.Close() })
	}
	if err != nil || transport != TransportTLSTCP || calls.Load() != 1 {
		t.Fatalf("race=%s, %v; fallback=%d", transport, err, calls.Load())
	}
	for range 2 {
		select {
		case result := <-observed:
			if result.failed != (result.transport == TransportQUIC) {
				t.Fatalf("lost candidate outcome: %+v", result)
			}
		case <-time.After(time.Second):
			t.Fatal("candidate did not report outcome")
		}
	}
	families, err := metrics.Gather()
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]uint64{}
	for _, family := range families {
		if family.GetName() != "tnl_publisher_transport_candidate_duration_seconds" {
			continue
		}
		for _, point := range family.Metric {
			labels := map[string]string{}
			for _, label := range point.Label {
				labels[label.GetName()] = label.GetValue()
			}
			counts[labels["tnl_transport"]+"/"+labels["tnl_outcome"]] += point.GetHistogram().GetSampleCount()
		}
	}
	if len(counts) != 2 || counts["quic/error"] != 1 || counts["tls-tcp/success"] != 1 {
		t.Fatal("failed primary candidate disappeared behind successful race result", counts)
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
		// close the deliberately stalled peer to release the losing handshake.
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
	synctest.Test(t, testRaceClosesLateSuccessfulLoser)
}

func testRaceClosesLateSuccessfulLoser(t *testing.T) {
	// pause the fallback after hello_accepted, immediately before Dial returns.
	// this models a successful result already in flight when the winner cancels.
	entered, release := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	fallback, loser := handshakeConnector(t, func(context.Context, tunnelv1.Message) error { return nil })
	started := make(chan context.Context, 1)
	wrapped := muxsession.ConnectorFunc(func(ctx context.Context, e muxsession.Endpoint) (muxsession.Session, error) {
		started <- ctx
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
	done := make(chan struct{})
	var result raceOutcome
	go func() {
		result.session, result.transport, result.err = Race(t.Context(), Candidate{Connector: primary, Transport: TransportQUIC}, Candidate{Connector: wrapped, Transport: TransportTLSTCP}, 0, publisherHello())
		close(done)
	}()
	loserCtx := <-started
	synctest.Wait()
	select {
	case <-loserCtx.Done():
	default:
		t.Error("winner did not cancel the in-flight successful loser")
	}
	select {
	case <-done:
		t.Error("race returned before the late successful handshake finished")
	default:
	}
	unblock()
	<-done
	if result.session != nil {
		defer result.session.Close()
	}
	if result.err != nil || result.transport != TransportQUIC {
		t.Fatalf("race: %s, %v", result.transport, result.err)
	}
	select {
	case <-loser.Done():
	default:
		t.Fatal("race returned before closing the late successful loser")
	}
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

type raceOutcome struct {
	session   *Session
	transport Transport
	err       error
}

type raceCloseFailureSession struct {
	muxsession.Session
	err    error
	closes atomic.Int32
}

func (s *raceCloseFailureSession) Close() error {
	s.closes.Add(1)
	return errors.Join(s.Session.Close(), s.err)
}

type raceBlockedSession struct {
	*raceCloseFailureSession
	entered, canceled, release chan struct{}
	stage                      string
}

func (s *raceBlockedSession) OpenStream(ctx context.Context) (muxsession.Stream, error) {
	close(s.entered)
	<-ctx.Done()
	close(s.canceled)
	if s.stage == "authenticating" {
		<-s.release
	}
	return nil, errors.Join(ctx.Err(), context.Cause(ctx))
}

func (s *raceBlockedSession) Close() error {
	if s.stage == "closing" {
		<-s.release
	}
	return s.raceCloseFailureSession.Close()
}

func TestRaceJoinsLosingCandidatesBeforeReturning(t *testing.T) {
	for _, losingTransport := range []Transport{TransportQUIC, TransportTLSTCP} {
		for _, stage := range []string{"dialing", "authenticating", "closing"} {
			t.Run(string(losingTransport)+"/"+stage, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
					raw, _ := newMemoryPair(t)
					loser := &raceBlockedSession{raceCloseFailureSession: &raceCloseFailureSession{Session: raw}, entered: entered, canceled: canceled, release: release, stage: stage}
					losing := muxsession.ConnectorFunc(func(ctx context.Context, _ muxsession.Endpoint) (muxsession.Session, error) {
						if stage != "dialing" {
							return loser, nil
						}
						close(entered)
						<-ctx.Done()
						close(canceled)
						<-release
						return nil, errors.Join(ctx.Err(), context.Cause(ctx))
					})
					winner, _ := handshakeConnector(t, func(context.Context, tunnelv1.Message) error { return nil })
					winning := muxsession.ConnectorFunc(func(ctx context.Context, endpoint muxsession.Endpoint) (muxsession.Session, error) {
						<-entered
						return winner.Connect(ctx, endpoint)
					})
					winningTransport := TransportQUIC
					if losingTransport == TransportQUIC {
						winningTransport = TransportTLSTCP
					}
					metrics := observability.New("publisher")
					t.Cleanup(func() { _ = metrics.Shutdown(context.Background()) })
					ctx := observability.WithMetrics(t.Context(), metrics)
					done := make(chan struct{})
					var result raceOutcome
					go func() {
						result.session, result.transport, result.err = Race(ctx, Candidate{Connector: losing, Transport: losingTransport}, Candidate{Connector: winning, Transport: winningTransport}, 0, publisherHello())
						close(done)
					}()
					synctest.Wait()
					select {
					case <-canceled:
					default:
						t.Error("proof did not reach the canceled losing candidate")
					}
					select {
					case <-done:
						t.Error("race exposed the winner before joining its losing candidate")
					default:
					}
					close(release)
					<-done
					if result.session != nil {
						defer result.session.Close()
					}
					if result.err != nil || result.transport != winningTransport {
						t.Fatal("joined candidate prevented ordinary fallback", result.err)
					}
					if stage != "dialing" && loser.closes.Load() != 1 {
						t.Fatal("failed authentication did not close its raw session exactly once", loser.closes.Load())
					}
					families, err := metrics.Gather()
					if err != nil {
						t.Fatal(err)
					}
					var observations uint64
					for _, family := range families {
						if family.GetName() == "tnl_publisher_transport_candidate_duration_seconds" {
							for _, point := range family.Metric {
								observations += point.GetHistogram().GetSampleCount()
							}
						}
					}
					if observations != 2 {
						t.Fatal("race returned before both candidate observations finished", observations)
					}
				})
			})
		}
	}
}

func TestRaceCleanupFailuresCloseWinnerAndPreserveCauses(t *testing.T) {
	for _, stage := range []string{"dialing", "authenticating"} {
		for _, canceled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/canceled=%t", stage, canceled), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					cleanupErr, winnerErr, cause := errors.New("loser cleanup failed"), errors.New("winner cleanup failed"), errors.New("publisher canceled")
					operationErr := errors.New("candidate failed independently")
					entered, stopped, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
					close(release)
					raw, _ := newMemoryPair(t)
					loser := &raceBlockedSession{raceCloseFailureSession: &raceCloseFailureSession{Session: raw, err: cleanupErr}, entered: entered, canceled: stopped, release: release, stage: stage}
					primary := muxsession.ConnectorFunc(func(ctx context.Context, _ muxsession.Endpoint) (muxsession.Session, error) {
						if stage == "authenticating" {
							return loser, nil
						}
						close(entered)
						<-ctx.Done()
						return nil, errors.Join(ctx.Err(), context.Cause(ctx), operationErr, &muxsession.QUICTransportCloseError{Err: cleanupErr})
					})
					winner, winnerRaw := handshakeConnector(t, func(context.Context, tunnelv1.Message) error { return nil })
					winnerSession := &raceCloseFailureSession{Session: winnerRaw, err: winnerErr}
					fallback := muxsession.ConnectorFunc(func(ctx context.Context, endpoint muxsession.Endpoint) (muxsession.Session, error) {
						<-entered
						if canceled {
							<-ctx.Done()
							return nil, context.Cause(ctx)
						}
						_, err := winner.Connect(ctx, endpoint)
						return winnerSession, err
					})
					ctx, cancel := context.WithCancelCause(t.Context())
					defer cancel(cause)
					done := make(chan struct{})
					var result raceOutcome
					go func() {
						result.session, result.transport, result.err = Race(ctx, Candidate{Connector: primary, Transport: TransportQUIC}, Candidate{Connector: fallback, Transport: TransportTLSTCP}, 0, publisherHello())
						close(done)
					}()
					synctest.Wait()
					if canceled {
						cancel(cause)
					}
					<-done
					if result.session != nil {
						_ = result.session.Close()
						t.Error("failed cleanup exposed an authenticated winner")
					}
					var cleanup *SessionCleanupError
					if !errors.As(result.err, &cleanup) || !errors.Is(result.err, cleanupErr) ||
						(canceled && (!errors.Is(result.err, cause) || !errors.Is(result.err, context.Canceled))) ||
						(!canceled && !errors.Is(result.err, winnerErr)) ||
						(stage == "dialing" && !errors.Is(result.err, operationErr)) {
						t.Fatal("race lost cleanup, operation, or cancellation identity", result.err)
					}
					if stage == "authenticating" && loser.closes.Load() != 1 {
						t.Fatal("handshake failure acquired a second closing owner", loser.closes.Load())
					}
					if !canceled && winnerSession.closes.Load() != 1 {
						t.Fatal("cleanup failure did not close the authenticated winner exactly once", winnerSession.closes.Load())
					}
				})
			})
		}
	}
}

func TestRaceCanceledBeforeEntryNeverAllocates(t *testing.T) {
	ctx, cancel := context.WithCancelCause(t.Context())
	cause := errors.New("race ended before entry")
	cancel(cause)
	var calls atomic.Int32
	connector := muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
		calls.Add(1)
		return nil, errors.New("late canceled candidate allocated")
	})
	primary, fallback := Candidate{Connector: connector, Transport: TransportQUIC}, Candidate{Connector: connector, Transport: TransportTLSTCP}
	if session, _, err := Race(ctx, primary, fallback, 0, publisherHello()); session != nil || !errors.Is(err, cause) || !errors.Is(err, context.Canceled) {
		t.Error("canceled race lost its cause", err)
	}
	// a worker already scheduled before cancellation must also skip Connect.
	if result := dialCandidate(ctx, primary, publisherHello()); result.session != nil || !errors.Is(result.err, cause) {
		t.Error("late canceled candidate lost its cause", result.err)
	}
	if calls.Load() != 0 {
		t.Fatal("canceled race or late candidate called the connector", calls.Load())
	}
}

func TestRaceTerminalRejectionJoinsSiblingCleanup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cleanupErr := errors.New("rejected race sibling cleanup failed")
		entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
		primary := rejectingConnectorAfter(t, entered, tunnelv1.Unauthenticated)
		raw, _ := newMemoryPair(t)
		loser := &raceBlockedSession{raceCloseFailureSession: &raceCloseFailureSession{Session: raw, err: cleanupErr}, entered: entered, canceled: canceled, release: release, stage: "closing"}
		fallback := muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) { return loser, nil })
		done := make(chan struct{})
		var result raceOutcome
		go func() {
			result.session, result.transport, result.err = Race(t.Context(), Candidate{Connector: primary, Transport: TransportQUIC}, Candidate{Connector: fallback, Transport: TransportTLSTCP}, 0, publisherHello())
			close(done)
		}()
		synctest.Wait()
		select {
		case <-canceled:
		default:
			t.Error("terminal rejection did not cancel its running sibling")
		}
		select {
		case <-done:
			t.Error("terminal rejection returned before joining sibling cleanup")
		default:
		}
		close(release)
		<-done
		var protocol *ProtocolError
		if result.session != nil || !errors.As(result.err, &protocol) || protocol.Code != tunnelv1.Unauthenticated || !errors.Is(result.err, cleanupErr) || loser.closes.Load() != 1 {
			t.Fatal("terminal denial lost precedence, cleanup cause, or its sole closing owner", result.err)
		}
	})
}
