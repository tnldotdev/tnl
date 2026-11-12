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
)

type drainingSlot struct {
	result   chan error
	draining chan struct{}
	release  chan struct{}
	closed   chan struct{}
	once     sync.Once
}

func newDrainingSlot() *drainingSlot {
	return &drainingSlot{result: make(chan error, 1), draining: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{})}
}
func (s *drainingSlot) Serve(ctx context.Context) error {
	select {
	case err := <-s.result:
		return err
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-s.closed:
		return nil
	}
}
func (s *drainingSlot) Close() error         { s.once.Do(func() { close(s.closed) }); return nil }
func (s *drainingSlot) Transport() Transport { return TransportQUIC }
func (s *drainingSlot) Drain(ctx context.Context) error {
	close(s.draining)
	select {
	case <-s.release:
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

func TestReusableSlotRotationConnectsReplacementWhileOldStreamsDrain(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	old, replacement, healthy := newDrainingSlot(), newDrainingSlot(), newDrainingSlot()
	first := true
	paths, err := NewSlots(ctx, SlotsConfig{Connect: func(_ context.Context, slot uint8, _ bool) (SlotSession, error) {
		if slot == 1 {
			return healthy, nil
		}
		if first {
			first = false
			return old, nil
		}
		return replacement, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer paths.Close()
	for slot := range uint8(2) {
		if err := paths.Set(slot, "assignment"); err != nil {
			t.Fatal(err)
		}
	}
	wait := func(want SlotSession) {
		t.Helper()
		for {
			ready, changed := paths.Snapshot()
			if ready[0] == want && ready[1] == healthy {
				return
			}
			select {
			case <-ctx.Done():
				t.Fatal("slots did not become ready")
			case <-changed:
			}
		}
	}
	wait(old)
	old.result <- ErrRotateSession
	wait(replacement)
	select {
	case <-old.draining:
	case <-ctx.Done():
		t.Fatal("old session never drained")
	}
	select {
	case <-old.closed:
		t.Fatal("credential rotation closed live streams")
	default:
	}
	select {
	case <-healthy.closed:
		t.Fatal("credential rotation restarted healthy path")
	default:
	}
	close(old.release)
	select {
	case <-old.closed:
	case <-ctx.Done():
		t.Fatal("retired session did not close after last stream")
	}
}

func TestStopAdmissionsAcknowledgesDrainWithoutClosingAdmittedTransport(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	serving := newDrainingSlot()
	connecting, canceled := make(chan struct{}), make(chan struct{})
	paths, err := NewSlots(ctx, SlotsConfig{SingleUse: true, Connect: func(ctx context.Context, slot uint8, _ bool) (SlotSession, error) {
		if slot == 0 {
			return serving, nil
		}
		close(connecting)
		<-ctx.Done()
		close(canceled)
		return nil, context.Cause(ctx)
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer paths.Close()
	for slot := range uint8(2) {
		if err := paths.Set(slot, "initial"); err != nil {
			t.Fatal(err)
		}
	}
	for {
		current, changed := paths.Snapshot()
		if current[0] == serving {
			break
		}
		select {
		case <-changed:
		case <-ctx.Done():
			t.Fatal("serving slot did not become ready")
		}
	}
	select {
	case <-connecting:
	case <-ctx.Done():
		t.Fatal("pending handshake did not start")
	}
	done := make(chan error, 1)
	go func() { done <- paths.StopAdmissions(ctx) }()
	for _, boundary := range []<-chan struct{}{serving.draining, canceled} {
		select {
		case <-boundary:
		case <-ctx.Done():
			t.Fatal("drain failed to cancel the pending handshake or request acknowledgement")
		}
	}
	select {
	case <-done:
		t.Fatal("drain returned before its acknowledgement")
	default:
	}
	close(serving.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	select {
	case <-serving.closed:
		t.Fatal("drain acknowledgement closed an admitted visitor's transport")
	default:
	}
	if ready, _ := paths.Snapshot(); ready[0] != nil || ready[1] != nil {
		t.Fatal("draining slots remained ready for new admissions")
	}
	if err := paths.Set(0, "replacement"); err == nil {
		t.Fatal("draining slots accepted a new assignment")
	}
	_ = paths.Close()
	select {
	case <-serving.closed:
	default:
		t.Fatal("Close did not join the admitted transport after drain")
	}
}

type transportedSlot struct {
	*drainingSlot
	transport Transport
}

func (s *transportedSlot) Transport() Transport { return s.transport }

func TestSingleUseSlotsWaitForReplacementAndResetFallbackPreference(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	initial := &transportedSlot{newDrainingSlot(), TransportQUIC}
	recovered := &transportedSlot{newDrainingSlot(), TransportTLSTCP}
	afterRecovery := &transportedSlot{newDrainingSlot(), TransportQUIC}
	healthy := &transportedSlot{newDrainingSlot(), TransportQUIC}
	preferences := make(chan bool, 4)
	connections := 0
	paths, err := NewSlots(ctx, SlotsConfig{SingleUse: true, BackoffMin: time.Millisecond, BackoffMax: time.Millisecond,
		Connect: func(_ context.Context, slot uint8, preferTCP bool) (SlotSession, error) {
			if slot == 1 {
				return healthy, nil
			}
			preferences <- preferTCP
			connections++
			if connections == 1 {
				return initial, nil
			}
			if connections == 2 {
				return recovered, nil
			}
			return afterRecovery, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	defer paths.Close()
	for slot := range uint8(2) {
		if err := paths.Set(slot, "initial"); err != nil {
			t.Fatal(err)
		}
	}
	wait := func(want SlotSession) {
		t.Helper()
		for {
			current, changed := paths.Snapshot()
			if current[0] == want && current[1] == healthy {
				return
			}
			select {
			case <-changed:
			case <-ctx.Done():
				t.Fatal("replacement changed the healthy sibling or failed readiness")
			}
		}
	}
	wait(initial)
	if <-preferences {
		t.Fatal("initial assignment preferred TCP")
	}
	initial.result <- errors.New("QUIC carrier lost")
	wait(nil)
	paths.mu.Lock()
	_, waiting := paths.workers[0].phase.(slotAwaitingAssignment)
	_, sibling := paths.workers[1].phase.(slotServing)
	paths.mu.Unlock()
	if !waiting || !sibling {
		t.Fatal("spent assignment did not wait while its sibling kept serving")
	}
	if err := paths.Set(0, "initial"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-preferences:
		t.Fatal("claimed assignment was reused without a replacement")
	case <-time.After(20 * time.Millisecond):
	}
	if err := paths.Set(0, "recovered"); err != nil {
		t.Fatal(err)
	}
	wait(recovered)
	if !<-preferences {
		t.Fatal("QUIC loss did not prefer TCP on replacement")
	}
	if err := paths.Set(0, "after-recovery"); err != nil {
		t.Fatal(err)
	}
	select {
	case preferTCP := <-preferences:
		if preferTCP {
			t.Fatal("authenticated TCP recovery retained TCP-first preference")
		}
	case <-ctx.Done():
		t.Fatal("replacement did not connect")
	}
}

type cleanupFailureSlot struct {
	*drainingSlot
	err     error
	closing chan struct{}
	finish  chan struct{}
	closes  atomic.Int32
}

func (s *cleanupFailureSlot) Serve(ctx context.Context) error {
	select {
	case err := <-s.result:
		return err
	case <-ctx.Done():
		// keep this worker on a durable channel while AfterFunc owns Close.
		// synctest does not consider contention on sync.Once durably blocked.
		<-s.finish
		return context.Cause(ctx)
	}
}

func (s *cleanupFailureSlot) Close() error {
	s.closes.Add(1)
	_ = s.drainingSlot.Close()
	close(s.closing)
	<-s.finish
	return s.err
}

func TestSlotsRetainCleanupAcrossStopReplacementRotationAndLateConnect(t *testing.T) {
	for _, boundary := range []string{"stop", "replacement", "rotation", "late connect"} {
		t.Run(boundary, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				cleanupErr := errors.New("retired session cleanup failed")
				old := &cleanupFailureSlot{drainingSlot: newDrainingSlot(), err: errors.Join(context.Canceled, cleanupErr), closing: make(chan struct{}), finish: make(chan struct{})}
				replacement := newDrainingSlot()
				entered, release := make(chan struct{}), make(chan struct{})
				var calls atomic.Int32
				paths, err := NewSlots(ctx, SlotsConfig{Connect: func(ctx context.Context, _ uint8, _ bool) (SlotSession, error) {
					if calls.Add(1) == 1 {
						close(entered)
						if boundary == "late connect" {
							<-ctx.Done()
							<-release
						}
						return old, nil
					}
					return replacement, nil
				}})
				if err != nil {
					t.Fatal(err)
				}
				if err := paths.Set(0, "initial"); err != nil {
					t.Fatal(err)
				}
				synctest.Wait()
				<-entered
				switch boundary {
				case "stop":
					cancel() // force the context.AfterFunc closing path.
				case "replacement", "late connect":
					if err := paths.Set(0, "replacement"); err != nil {
						t.Fatal(err)
					}
					close(release)
				case "rotation":
					old.result <- ErrRotateSession
					synctest.Wait()
					close(old.release)
				}
				synctest.Wait()
				select {
				case <-old.closing:
				default:
					t.Error("proof did not reach the retired session's physical Close")
				}
				done := make(chan error, 1)
				go func() { done <- paths.Close() }()
				synctest.Wait()
				select {
				case err := <-done:
					t.Error("slots returned before joining physical session cleanup", err)
					done <- err
				default:
				}
				close(old.finish)
				err = <-done
				if !errors.Is(err, context.Canceled) || !errors.Is(err, cleanupErr) || old.closes.Load() != 1 {
					t.Fatal("slots lost the retired cleanup failure or closed twice", err, old.closes.Load())
				}
				if again := paths.Close(); again != err || old.closes.Load() != 1 {
					t.Fatal("slots did not return their cached cleanup failure", again)
				}
			})
		})
	}
}

func TestSlotsRetainOnlyClassifiedConnectCleanupAfterCancellation(t *testing.T) {
	for _, cleanupFailed := range []bool{false, true} {
		t.Run(fmt.Sprintf("cleanup=%t", cleanupFailed), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cause, cleanupErr, dialErr := errors.New("owner canceled"), errors.New("failed dial cleanup failed"), errors.New("recoverable network failure")
				ctx, cancel := context.WithCancelCause(t.Context())
				entered := make(chan struct{})
				paths, err := NewSlots(ctx, SlotsConfig{Connect: func(ctx context.Context, _ uint8, _ bool) (SlotSession, error) {
					close(entered)
					<-ctx.Done()
					err := errors.Join(ctx.Err(), context.Cause(ctx), dialErr)
					if cleanupFailed {
						err = errors.Join(err, &SessionCleanupError{Err: cleanupErr})
					}
					return nil, err
				}})
				if err != nil {
					t.Fatal(err)
				}
				if err := paths.Set(0, "initial"); err != nil {
					t.Fatal(err)
				}
				<-entered
				cancel(cause)
				err = paths.Close()
				if cleanupFailed {
					if !errors.Is(err, cleanupErr) || !errors.Is(err, cause) || !errors.Is(err, context.Canceled) || !errors.Is(err, dialErr) {
						t.Fatal("classified failed-dial cleanup lost independent causes under cancellation", err)
					}
				} else if err != nil {
					t.Fatal("recoverable network failure became a permanent shutdown failure", err)
				}
			})
		})
	}
}
