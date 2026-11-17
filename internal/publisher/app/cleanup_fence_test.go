package app

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func TestCleanupRetryActiveDeadlineCanOnlyNarrow(t *testing.T) {
	for _, boundary := range []string{"own-deadline", "exact-owner-limit", "parent-stop"} {
		t.Run(boundary, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				manager, err := newTestManager(t, t.TempDir(), t.TempDir(), []Service{{Name: "web"}}, nil)
				if err != nil {
					t.Fatal(err)
				}
				parent, cancelParent := context.WithCancel(t.Context())
				defer cancelParent()
				manager.ctx = parent
				defer manager.Close()
				id, err := manager.Reserve("web", "owner", 1, "")
				if err != nil {
					t.Fatal(err)
				}
				original := time.Now().Add(time.Second)
				if err := manager.LimitShutdown(id, "owner", "", original); err != nil {
					t.Fatal(err)
				}
				firstFailure := errors.New("initial allocation deletion failed independently")
				manager.Cleanup = func(Service) error { return firstFailure }
				if err := manager.UnregisterTarget(id, "owner", ""); !errors.Is(err, firstFailure) {
					t.Fatal("first cleanup lost its independent failure", err)
				}
				time.Sleep(LeaseDuration + time.Second)
				synctest.Wait()
				entered := make(chan context.Context, 1)
				release := make(chan struct{})
				retryFailure := errors.New("retried allocation deletion failed independently")
				manager.Cleanup = func(Service) error {
					ctx := manager.PublicationCleanupContext(id)
					entered <- ctx
					select {
					case <-ctx.Done():
					case <-release:
					}
					return errors.Join(context.Cause(ctx), retryFailure)
				}
				retryUntil := time.Now().Add(3 * time.Second)
				if err := manager.LimitShutdown(id, "owner", "", retryUntil); err != nil {
					t.Fatal(err)
				}
				result := make(chan error, 1)
				go func() { result <- manager.UnregisterTarget(id, "owner", "") }()
				active := <-entered
				until := retryUntil
				switch boundary {
				case "exact-owner-limit":
					until = time.Now().Add(time.Second)
					if err := manager.LimitShutdown(id, "owner", "", until); err != nil {
						t.Fatal(err)
					}
					if err := manager.LimitShutdown(id, "owner", "", until.Add(time.Hour)); err != nil {
						t.Fatal(err)
					}
				case "parent-stop":
					until = time.Now().Add(100 * time.Millisecond)
					manager.ShutdownDeadline = func() time.Time { return until }
					cancelParent()
				}
				time.Sleep(time.Until(until))
				synctest.Wait()
				if active.Err() == nil || context.Cause(active) != context.DeadlineExceeded {
					t.Error("active retry ignored its original or tighter exact-owner/process bound", active.Err(), context.Cause(active))
				}
				if deadline, _ := active.Deadline(); !deadline.Equal(retryUntil) {
					t.Error("late narrowing changed the borrowed context's original deadline", deadline, retryUntil)
				}
				close(release)
				if err := <-result; !errors.Is(err, retryFailure) {
					t.Fatal("deadline handling hid an independent cleanup failure", err)
				}
				if !errors.Is(manager.RetirementError(), firstFailure) || !errors.Is(manager.RetirementError(), retryFailure) {
					t.Fatal("retirement lost independent allocation failures", manager.RetirementError())
				}
				if got := manager.PublicationShutdownDeadline(id); !got.Equal(original) {
					t.Fatal("explicit retry changed the original automatic shutdown budget", got, original)
				}
			})
		})
	}
}

func TestManagerCloseFencesActiveRetryBeforeWaitingForOperationLock(t *testing.T) {
	manager, err := newTestManager(t, t.TempDir(), t.TempDir(), []Service{{Name: "web"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	id, err := manager.Reserve("web", "owner", 1, "")
	if err != nil {
		t.Fatal(err)
	}
	original := time.Now().Add(-time.Second)
	if err := manager.LimitShutdown(id, "owner", "", original); err != nil {
		t.Fatal(err)
	}
	manager.Cleanup = func(Service) error { return errors.New("initial transient allocation cleanup failure") }
	if err := manager.UnregisterTarget(id, "owner", ""); err == nil {
		t.Fatal("initial cleanup unexpectedly succeeded")
	}
	entered := make(chan context.Context, 1)
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	failure := errors.New("active retry cleanup failed independently")
	manager.Cleanup = func(Service) error {
		ctx := manager.PublicationCleanupContext(id)
		entered <- ctx
		select {
		case <-ctx.Done():
		case <-release:
		}
		return errors.Join(context.Cause(ctx), failure)
	}
	result := make(chan error, 1)
	go func() { result <- manager.UnregisterTarget(id, "owner", "") }()
	active := <-entered
	closing := make(chan struct{})
	processUntil := time.Now().Add(-time.Millisecond)
	manager.ShutdownDeadline = sync.OnceValue(func() time.Time { close(closing); return processUntil })
	closed := make(chan struct{})
	go func() { manager.Close(); close(closed) }()
	<-closing
	// the deadline is captured while holding mu, before waiting for op. this
	// barrier proves Close has published every active cleanup fence, without a
	// sleep or advancing fake time while another goroutine waits on op.
	manager.mu.Lock()
	manager.mu.Unlock()
	if active.Err() == nil || context.Cause(active) != context.DeadlineExceeded {
		t.Error("process close waited on the retry without first fencing its active context")
	}
	unblock()
	if err := <-result; !errors.Is(err, failure) {
		t.Error("process close hid the retry's independent cleanup failure", err)
	}
	<-closed
	if !errors.Is(manager.RetirementError(), failure) {
		t.Fatal("process retirement discarded the active retry's failure", manager.RetirementError())
	}
}
