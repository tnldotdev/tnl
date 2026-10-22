package tunnel

import (
	"context"
	"errors"
	"sync"
	"testing"
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
func (s *drainingSlot) Close() error { s.once.Do(func() { close(s.closed) }); return nil }
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
