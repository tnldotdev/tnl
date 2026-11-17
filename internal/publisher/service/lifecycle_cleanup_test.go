package service

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type invalidSetupControl struct {
	*lifecycleControl
	closeErr error
	closed   bool
}

func (c *invalidSetupControl) StartServiceRun(ctx context.Context, service, run, access string, number int64) (controlv1.ServiceRunSetup, error) {
	setup, err := c.lifecycleControl.StartServiceRun(ctx, service, run, access, number)
	if err == nil {
		setup.RunNumber++
	}
	return setup, err
}

func (c *invalidSetupControl) CloseServiceRun(_ context.Context, _, _ string, token credentials.ServiceRunToken) error {
	c.closed = token.String() == c.setup.RunToken
	return c.closeErr
}

func TestServiceRunInvalidSetupStillClosesAndPreservesCleanupFailure(t *testing.T) {
	config, control := lifecycleFixture(t)
	cleanup := errors.New("close failed")
	invalid := &invalidSetupControl{lifecycleControl: control, closeErr: cleanup}
	config.Control = invalid
	err := Publish(t.Context(), config)
	if !invalid.closed || !errors.Is(err, ErrPrivateStream) || !errors.Is(err, cleanup) {
		t.Fatal("invalid setup skipped its close or lost either error", err)
	}
}

func TestServiceRunRequiresExplicitProtocolBeforeAccess(t *testing.T) {
	config, _ := lifecycleFixture(t)
	config.Metadata.Protocol = ""
	config.Access = func(context.Context) (string, error) {
		t.Fatal("missing service protocol reached credential exchange")
		return "", nil
	}
	if err := Publish(t.Context(), config); !errors.Is(err, ErrPrivateStream) {
		t.Fatal("missing service protocol used an implicit TCP declaration", err)
	}
}

type deadlineDrainSlot struct {
	*heldSlot
	deadlines chan<- time.Time
}

func (s *deadlineDrainSlot) Drain(ctx context.Context) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		return errors.New("service drain has no deadline")
	}
	s.deadlines <- deadline
	return nil
}

func TestServiceRunDrainUsesItsOwningProcessBudget(t *testing.T) {
	for _, duration := range []time.Duration{0, 30 * time.Second} {
		t.Run(duration.String(), func(t *testing.T) {
			config, _ := lifecycleFixture(t)
			config.DrainTime = duration
			deadlines := make(chan time.Time, 2)
			var slots [2]*deadlineDrainSlot
			config.Connect = func(_ context.Context, _ *Bound, slot uint8, _ ConnectOptions) (SlotSession, error) {
				session := &deadlineDrainSlot{heldSlot: &heldSlot{stopped: make(chan struct{})}, deadlines: deadlines}
				slots[slot] = session
				return session, nil
			}
			ready := make(chan struct{})
			config.Ready = func() error { close(ready); return nil }
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			finished := make(chan struct{})
			t.Cleanup(func() { cancel(); <-finished })
			go func() {
				defer close(finished)
				done <- Publish(ctx, config)
			}()
			timer := time.NewTimer(5 * time.Second)
			defer timer.Stop()
			select {
			case <-ready:
			case err := <-done:
				t.Fatal("service exited before it could drain", err)
			case <-timer.C:
				t.Fatal("service did not become ready")
			}
			before := time.Now()
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-timer.C:
				t.Fatal("service did not join its slots after drain")
			}
			after := time.Now()
			want := duration
			if want == 0 {
				want = 10 * time.Second
			}
			for _, slot := range slots {
				select {
				case deadline := <-deadlines:
					if deadline.Before(before.Add(want)) || deadline.After(after.Add(want)) {
						t.Fatal("service replaced its process's drain budget", duration, deadline.Sub(before))
					}
				default:
					t.Fatal("service skipped a slot's drain")
				}
				select {
				case <-slot.stopped:
				default:
					t.Fatal("service returned before closing a drained slot")
				}
			}
		})
	}
}

func TestServiceRunRejectsNegativeDrainBeforeAccess(t *testing.T) {
	config, _ := lifecycleFixture(t)
	config.DrainTime = -time.Second
	config.Access = func(context.Context) (string, error) {
		t.Fatal("invalid drain budget reached credential exchange")
		return "", nil
	}
	if err := Publish(t.Context(), config); !errors.Is(err, ErrPrivateStream) {
		t.Fatal("service accepted a negative drain budget", err)
	}
}

type canceledHeartbeatControl struct {
	*lifecycleControl
	entered  chan struct{}
	failure  error
	closeErr error
}

func (c *canceledHeartbeatControl) HeartbeatServiceRun(ctx context.Context, service, run string, token credentials.ServiceRunToken, heartbeat controlv1.ServiceRunHeartbeat) (controlv1.ServiceRunState, error) {
	c.mu.Lock()
	first := c.heartbeats == 0
	c.mu.Unlock()
	if first {
		return c.lifecycleControl.HeartbeatServiceRun(ctx, service, run, token, heartbeat)
	}
	close(c.entered)
	<-ctx.Done()
	return controlv1.ServiceRunState{}, errors.Join(context.Canceled, c.failure)
}

func (c *canceledHeartbeatControl) CloseServiceRun(ctx context.Context, service, run string, token credentials.ServiceRunToken) error {
	return errors.Join(c.lifecycleControl.CloseServiceRun(ctx, service, run, token), c.closeErr)
}

func TestServiceRunCancellationKeepsIndependentHeartbeatAndCleanupFailures(t *testing.T) {
	cfg, control := lifecycleFixture(t)
	heartbeatFailure, closeFailure := errors.New("heartbeat failed while canceled"), errors.New("run close failed")
	wrapped := &canceledHeartbeatControl{lifecycleControl: control, entered: make(chan struct{}), failure: heartbeatFailure, closeErr: closeFailure}
	cfg.Control = wrapped
	cfg.Connect = func(context.Context, *Bound, uint8, ConnectOptions) (SlotSession, error) {
		return &heldSlot{stopped: make(chan struct{})}, nil
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	joined := make(chan struct{})
	go func() { defer close(joined); done <- Publish(ctx, cfg) }()
	defer func() { cancel(); <-joined }()
	serviceHTTPAwait(t, wrapped.entered)
	cancel()
	if err := serviceHTTPAwait(t, done); !errors.Is(err, heartbeatFailure) || !errors.Is(err, closeFailure) {
		t.Fatal("cancellation discarded an independent operation or cleanup error", err)
	}
}

func TestServiceWorkerStopKeepsIndependentFailures(t *testing.T) {
	failure := errors.New("independent worker failure")
	for _, stopped := range []error{context.Canceled, context.DeadlineExceeded} {
		for _, err := range []error{stopped, fmt.Errorf("worker stopped: %w", stopped), errors.Join(stopped, fmt.Errorf("wrapped stop: %w", stopped))} {
			if got := serviceWorkerError(err, stopped); got != nil {
				t.Fatal("expected worker stop became a failure", got)
			}
		}
		for _, err := range []error{failure, errors.Join(stopped, failure), fmt.Errorf("worker failed: %w", errors.Join(stopped, failure))} {
			if got := serviceWorkerError(err, stopped); !errors.Is(got, failure) {
				t.Fatal("expected stop discarded an independent failure", got)
			}
		}
	}
}
