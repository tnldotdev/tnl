package identity

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestApplicationSessionFenceJoinsWorkerAndPreservesIndependentFailure(t *testing.T) {
	s := &ApplicationSession{}
	s.publishFence(time.Now().Add(time.Hour), false)
	started := make(chan struct{})
	joined := make(chan struct{})
	done := make(chan error, 1)
	independent := errors.New("independent stream drain failure")
	go func() {
		done <- s.Run(t.Context(), func(ctx context.Context) error {
			close(started)
			<-ctx.Done()
			close(joined)
			return errors.Join(ctx.Err(), independent)
		})
	}()
	<-started
	s.publishFence(time.Now().Add(-time.Second), false)
	if err := s.CheckServing(); !errors.Is(err, ErrScope) {
		t.Fatal("expired confirmed fence admitted visitors", err)
	}
	if err := <-done; !errors.Is(err, ErrScope) || !errors.Is(err, independent) {
		t.Fatal("fence dropped independent worker failure", err)
	}
	select {
	case <-joined:
	default:
		t.Fatal("fence returned without joining owned worker")
	}
}

func TestApplicationSessionFenceReplacementDoesNotCancelFromStaleDeadline(t *testing.T) {
	s := &ApplicationSession{}
	s.publishFence(time.Now().Add(time.Hour), false)
	started := make(chan struct{})
	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() {
		done <- s.Run(ctx, func(ctx context.Context) error { close(started); <-ctx.Done(); return ctx.Err() })
	}()
	<-started
	for range 100 {
		s.publishFence(time.Now().Add(time.Hour), false)
	}
	if err := s.CheckServing(); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) || errors.Is(err, ErrScope) {
		t.Fatal("stale watcher canceled a current fence", err)
	}
}
