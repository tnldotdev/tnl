package service

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/credentials"
)

type budgetCleanupControl struct {
	*lifecycleControl
	until   time.Time
	failure error
}

func (c *budgetCleanupControl) CloseServiceRun(ctx context.Context, service, run string, token credentials.ServiceRunToken) error {
	c.until, _ = ctx.Deadline()
	return errors.Join(c.lifecycleControl.CloseServiceRun(ctx, service, run, token), c.failure, ctx.Err())
}

type budgetDrainSlot struct {
	*heldSlot
	until chan<- time.Time
}

func (s *budgetDrainSlot) Drain(ctx context.Context) error {
	until, _ := ctx.Deadline()
	s.until <- until
	<-ctx.Done()
	return ctx.Err()
}

func TestServiceShutdownDrainAndExactCleanupShareOriginalDeadline(t *testing.T) {
	config, control := lifecycleFixture(t)
	cleanup := errors.New("remote cleanup unconfirmed")
	wrapped := &budgetCleanupControl{lifecycleControl: control, failure: cleanup}
	config.Control = wrapped
	config.DrainTime = time.Second
	var calls atomic.Int32
	var until time.Time
	config.ShutdownDeadline = func() time.Time {
		calls.Add(1)
		until = time.Now().Add(80 * time.Millisecond)
		return until
	}
	deadlines := make(chan time.Time, 2)
	config.Connect = func(context.Context, *Bound, uint8, ConnectOptions) (SlotSession, error) {
		return &budgetDrainSlot{heldSlot: &heldSlot{stopped: make(chan struct{})}, until: deadlines}, nil
	}
	ready := make(chan struct{})
	config.Ready = func() error { close(ready); return nil }
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- Publish(ctx, config) }()
	defer func() { cancel() }()
	serviceHTTPAwait(t, ready)
	cancel()
	err := serviceHTTPAwait(t, done)
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, cleanup) {
		t.Fatal("forced drain hid timeout or independent remote cleanup failure", err)
	}
	if calls.Load() != 1 || !wrapped.until.Equal(until) {
		t.Fatal("exact-run cleanup started a fresh budget", calls.Load(), wrapped.until, until)
	}
	for range 2 {
		if drain := serviceHTTPAwait(t, deadlines); !drain.Equal(until) {
			t.Fatal("slot drain did not receive the original remaining budget", drain, until)
		}
	}
}
