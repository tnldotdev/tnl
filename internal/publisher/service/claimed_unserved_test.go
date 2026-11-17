package service

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
)

type claimedEndObservation struct {
	err      error
	expected bool
}

func observeClaimedEnd(claimed *Claimed) (<-chan claimedEndObservation, *atomic.Int32) {
	result := make(chan claimedEndObservation, 1)
	calls := new(atomic.Int32)
	var once sync.Once
	claimed.endObservation = func(err error, expected bool) {
		calls.Add(1)
		once.Do(func() { result <- claimedEndObservation{err, expected} })
	}
	return result, calls
}

func TestClaimedUnservedCloseOwnsAcceptObservation(t *testing.T) {
	for _, failedAccept := range []bool{false, true} {
		for _, failedCleanup := range []bool{false, true} {
			t.Run(fmt.Sprintf("accept=%t/cleanup=%t", failedAccept, failedCleanup), func(t *testing.T) {
				_, bound, _, _ := privateFixture(t, "127.0.0.1:1")
				var operation, cleanup error
				if failedAccept {
					operation = fmt.Errorf("unserved accept: %w", &quic.IdleTimeoutError{})
				}
				if failedCleanup {
					cleanup = errors.Join(context.Canceled, errors.New("unserved physical close failed"))
				}
				var wire *claimedTerminalTransport
				claimed, _ := newClaimedTestPair(t, bound, 0, func(outer muxsession.Session) muxsession.Session {
					wire = &claimedTerminalTransport{Session: outer, entered: make(chan struct{}), result: make(chan error, 1), cleanup: cleanup}
					return wire
				})
				observed, calls := observeClaimedEnd(claimed)
				claimedAwait(t, wire.entered)
				accept := operation
				if accept == nil {
					accept = muxsession.ErrClosed
				}
				wire.result <- accept
				// collect the actual accept boundary before retiring the unused
				// claim; no Serve result or serving observation exists.
				_ = claimed.dispatcher.Close()
				result := claimed.Close()
				summary := claimedAwait(t, observed)
				if summary.expected == failedAccept || failedAccept && !errors.Is(summary.err, operation) {
					t.Error("unused claim hid its independently failed accept observation", summary)
				}
				if failedCleanup && (!errors.Is(result, cleanup) || !errors.Is(summary.err, cleanup)) ||
					!failedCleanup && result != nil || failedAccept && errors.Is(result, operation) {
					t.Error("unused claim confused the operation with physical cleanup", result, summary)
				}
				late := claimed.Serve(t.Context())
				if failedAccept && !errors.Is(late, operation) || failedCleanup && !errors.Is(late, cleanup) {
					t.Error("late Serve discarded the already joined unused-claim result", late)
				}
				if claimed.Close() != result || calls.Load() != 1 || wire.closes.Load() != 1 {
					t.Error("Close and late Serve did not retain one result owner", calls.Load(), wire.closes.Load())
				}
			})
		}
	}
}

func TestClaimedUnservedSlotReplacementObservesAcceptWithoutCleanupPoison(t *testing.T) {
	for _, failedCleanup := range []bool{false, true} {
		t.Run(fmt.Sprintf("cleanup=%t", failedCleanup), func(t *testing.T) {
			_, bound, _, _ := privateFixture(t, "127.0.0.1:1")
			operation := errors.New("late connected claim accept failed")
			var cleanup error
			if failedCleanup {
				cleanup = errors.New("late connected claim cleanup failed")
			}
			var wire *claimedTerminalTransport
			claimed, _ := newClaimedTestPair(t, bound, 0, func(outer muxsession.Session) muxsession.Session {
				wire = &claimedTerminalTransport{Session: outer, entered: make(chan struct{}), result: make(chan error, 1), cleanup: cleanup}
				return wire
			})
			observed, calls := observeClaimedEnd(claimed)
			claimedAwait(t, wire.entered)
			wire.result <- operation
			_ = claimed.dispatcher.Close()
			entered, release := make(chan struct{}), make(chan struct{})
			finishConnect := sync.OnceFunc(func() { close(release) })
			defer finishConnect()
			var connections, ended atomic.Int32
			slots, err := tunnel.NewSlots(t.Context(), tunnel.SlotsConfig{SingleUse: true,
				Connect: func(ctx context.Context, _ uint8, _ bool) (tunnel.SlotSession, error) {
					if connections.Add(1) == 1 {
						close(entered)
						<-release
						return claimed, nil
					}
					<-ctx.Done()
					return nil, ctx.Err()
				},
				SessionEnded: func(uint8, tunnel.SlotSession, error) { ended.Add(1) }})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { finishConnect(); _ = slots.Close() })
			if err := slots.Set(0, "original"); err != nil {
				t.Fatal(err)
			}
			claimedAwait(t, entered)
			if err := slots.Set(0, "replacement"); err != nil {
				t.Fatal(err)
			}
			finishConnect()
			summary := claimedAwait(t, observed)
			result := slots.Close()
			if summary.expected || !errors.Is(summary.err, operation) {
				t.Error("unserved replaced slot hid the accept operation", summary)
			}
			if failedCleanup && !errors.Is(result, cleanup) || !failedCleanup && result != nil || errors.Is(result, operation) {
				t.Error("slots lost actual cleanup or cached an unserved operation as cleanup", result)
			}
			if ended.Load() != 0 || calls.Load() != 1 || wire.closes.Load() != 1 {
				t.Error("late connection was served, observed twice, or closed twice", ended.Load(), calls.Load(), wire.closes.Load())
			}
		})
	}
}

func TestClaimedServeWaitsForUnservedClose(t *testing.T) {
	for _, failedCleanup := range []bool{false, true} {
		t.Run(fmt.Sprintf("cleanup=%t", failedCleanup), func(t *testing.T) {
			_, bound, _, _ := privateFixture(t, "127.0.0.1:1")
			operation := errors.New("unused accept failed before Close won")
			var cleanup error
			if failedCleanup {
				cleanup = errors.New("unused physical close failed")
			}
			var wire *claimedSlotCleanupTransport
			claimed, _ := newClaimedTestPair(t, bound, 0, func(outer muxsession.Session) muxsession.Session {
				wire = &claimedSlotCleanupTransport{claimedTerminalTransport: claimedTerminalTransport{
					Session: outer, entered: make(chan struct{}), result: make(chan error, 1), cleanup: cleanup},
					closing: make(chan struct{}), release: make(chan struct{})}
				return wire
			})
			release := sync.OnceFunc(func() { close(wire.release) })
			defer release()
			observed, calls := observeClaimedEnd(claimed)
			claimedAwait(t, wire.entered)
			wire.result <- operation
			_ = claimed.dispatcher.Close()
			closed, served := make(chan error, 1), make(chan error, 1)
			go func() { closed <- claimed.Close() }()
			claimedAwait(t, wire.closing)
			go func() { served <- claimed.Serve(t.Context()) }()
			var summary claimedEndObservation
			early := false
			select {
			case summary = <-observed:
				early = true
				t.Error("unused Close reported before its physical cleanup joined", summary)
			default:
			}
			release()
			closeErr, serveErr := claimedAwait(t, closed), claimedAwait(t, served)
			if !early {
				summary = claimedAwait(t, observed)
			}
			if summary.expected || !errors.Is(summary.err, operation) || !errors.Is(serveErr, operation) {
				t.Error("Close-first race lost the unserved operation or observation", closeErr, serveErr, summary)
			}
			if failedCleanup && (!errors.Is(closeErr, cleanup) || !errors.Is(serveErr, cleanup)) ||
				!failedCleanup && closeErr != nil || errors.Is(closeErr, operation) {
				t.Error("Close-first race lost physical cleanup provenance", closeErr, serveErr)
			}
			if calls.Load() != 1 || wire.closes.Load() != 1 {
				t.Error("late Serve competed with the unserved result owner", calls.Load(), wire.closes.Load())
			}
		})
	}
}

// delay only Serve's final observation. Close must finish while that observation
// is gated, rather than consuming the observer with an earlier expected close.
type claimedObservationContext struct {
	context.Context
	entered chan struct{}
	gated   chan struct{}
	release chan struct{}
	start   sync.Once
	stop    sync.Once
	armed   atomic.Bool
}

func (c *claimedObservationContext) Done() <-chan struct{} {
	c.start.Do(func() { close(c.entered) })
	return c.Context.Done()
}

func (c *claimedObservationContext) Err() error {
	if c.armed.Load() {
		c.stop.Do(func() { close(c.gated) })
		<-c.release
	}
	return c.Context.Err()
}

func TestClaimedCloseCannotConsumeServingObservation(t *testing.T) {
	for _, failedCleanup := range []bool{false, true} {
		t.Run(fmt.Sprintf("cleanup=%t", failedCleanup), func(t *testing.T) {
			_, bound, _, _ := privateFixture(t, "127.0.0.1:1")
			operation := errors.New("serving accept failed before Close")
			var cleanup error
			if failedCleanup {
				cleanup = errors.New("serving physical close failed")
			}
			var wire *claimedSlotCleanupTransport
			claimed, _ := newClaimedTestPair(t, bound, 0, func(outer muxsession.Session) muxsession.Session {
				wire = &claimedSlotCleanupTransport{claimedTerminalTransport: claimedTerminalTransport{
					Session: outer, entered: make(chan struct{}), result: make(chan error, 1), cleanup: cleanup},
					closing: make(chan struct{}), release: make(chan struct{})}
				return wire
			})
			observed, calls := observeClaimedEnd(claimed)
			owner := &claimedObservationContext{Context: t.Context(), entered: make(chan struct{}), gated: make(chan struct{}), release: make(chan struct{})}
			releaseClose := sync.OnceFunc(func() { close(wire.release) })
			releaseObservation := sync.OnceFunc(func() { close(owner.release) })
			defer releaseClose()
			defer releaseObservation()
			served := make(chan error, 1)
			go func() { served <- claimed.Serve(owner) }()
			claimedAwait(t, owner.entered)
			claimedAwait(t, wire.entered)
			wire.result <- operation
			claimedAwait(t, wire.closing)
			owner.armed.Store(true)
			closed := make(chan error, 1)
			go func() { closed <- claimed.Close() }()
			releaseClose()
			claimedAwait(t, owner.gated)
			closeErr := claimedAwait(t, closed)
			select {
			case early := <-observed:
				t.Error("Close consumed the serving result before its owner could report", early)
				observed = nil
			default:
			}
			releaseObservation()
			serveErr := claimedAwait(t, served)
			if !errors.Is(serveErr, operation) || failedCleanup && (!errors.Is(serveErr, cleanup) || !errors.Is(closeErr, cleanup)) ||
				!failedCleanup && closeErr != nil || errors.Is(closeErr, operation) {
				t.Error("Close/Serve race lost provenance or cleanup", serveErr, closeErr)
			}
			if observed != nil {
				summary := claimedAwait(t, observed)
				if summary.expected || !errors.Is(summary.err, operation) {
					t.Error("serving owner lost its unexpected-loss observation", summary)
				}
			}
			if calls.Load() != 1 || wire.closes.Load() != 1 {
				t.Error("Close raced the serving result owner or physical close", calls.Load(), wire.closes.Load())
			}
		})
	}
}

type lateUnservedQUIC struct {
	privateSlotQUICTransport
	bound      *Bound
	operation  error
	cleanup    error
	entered    chan struct{}
	negotiated atomic.Int32
	closes     atomic.Int32
}

func (s *lateUnservedQUIC) SupportsDatagrams() bool {
	if s.negotiated.Add(1) == 2 {
		// the first check is the candidate fence before the hello; this check
		// constructs packet ownership after ConnectSlot's first current check.
		// retain the bound lock until the new dispatcher actually accepts, then
		// invalidate before the final current check can install this claim.
		s.bound.mu.Lock()
		go func() {
			<-s.entered
			s.bound.closed = true
			s.bound.mu.Unlock()
		}()
	}
	return s.privateSlotQUICTransport.SupportsDatagrams()
}

func (s *lateUnservedQUIC) AcceptStream(context.Context) (muxsession.Stream, error) {
	close(s.entered)
	return nil, s.operation
}

func (s *lateUnservedQUIC) Close() error {
	s.closes.Add(1)
	return errors.Join(s.privateSlotQUICTransport.Close(), s.cleanup)
}

func TestPrivateConnectSlotLateStaleClaimRetainsUnservedOperationAndCleanup(t *testing.T) {
	for _, failedCleanup := range []bool{false, true} {
		t.Run(fmt.Sprintf("cleanup=%t", failedCleanup), func(t *testing.T) {
			_, bound, _, _ := privateFixture(t, "127.0.0.1:1")
			relay := newPrivateSlotRelay(t, bound, true, nil, nil)
			operation := errors.New("new dispatcher accept failed before slot installation")
			var cleanup error
			if failedCleanup {
				cleanup = errors.Join(context.Canceled, errors.New("late stale physical close failed"))
			}
			options := relay.options(t, relay.roots)
			quic := options.QUIC
			var wire *lateUnservedQUIC
			options.QUIC = muxsession.ConnectorFunc(func(ctx context.Context, endpoint muxsession.Endpoint) (muxsession.Session, error) {
				outer, err := quic.Connect(ctx, endpoint)
				if err != nil {
					return nil, err
				}
				wire = &lateUnservedQUIC{privateSlotQUICTransport: outer.(privateSlotQUICTransport),
					bound: bound, operation: operation, cleanup: cleanup, entered: make(chan struct{})}
				return wire, nil
			})
			options.TCP = muxsession.DisabledConnector{}
			metrics := observability.New("publisher")
			defer metrics.Shutdown(context.Background())
			claimed, err := bound.ConnectSlot(observability.WithMetrics(t.Context(), metrics), 0, options)
			if claimed != nil || !errors.Is(err, ErrPrivateStream) || !errors.Is(err, operation) {
				t.Fatal("late stale claim lost its independent connect operation", claimed, err)
			}
			var report *tunnel.SessionCleanupError
			if errors.As(err, &report) != failedCleanup ||
				failedCleanup && (!errors.Is(report, cleanup) || errors.Is(report, operation)) {
				t.Error("late stale cleanup was lost or the accept operation was relabeled as cleanup", err)
			}
			if wire.negotiated.Load() != 2 || wire.closes.Load() != 1 || bound.packetSlots[0] != nil {
				t.Fatal("test missed the post-dispatcher stale boundary or leaked its claim", wire.negotiated.Load(), wire.closes.Load())
			}
			families, gatherErr := metrics.Gather()
			if gatherErr != nil {
				t.Fatal(gatherErr)
			}
			var unexpected, expected float64
			for _, family := range families {
				if family.GetName() != "tnl_publisher_connection_events_total" {
					continue
				}
				for _, metric := range family.Metric {
					for _, label := range metric.Label {
						if label.GetName() == "tnl_event" {
							switch label.GetValue() {
							case "unexpected_close":
								unexpected += metric.GetCounter().GetValue()
							case "expected_close":
								expected += metric.GetCounter().GetValue()
							}
						}
					}
				}
			}
			if unexpected != 1 || expected != 0 {
				t.Error("unserved stale claim hid the actual unexpected-loss metric", unexpected, expected)
			}
		})
	}
}
