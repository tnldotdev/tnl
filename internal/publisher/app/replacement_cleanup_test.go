package app

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRegistrationReplacementJoinsAndPreservesOldCleanupFailure(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(map[bool]string{false: "clean", true: "independent-cleanup-failure"}[failed], func(t *testing.T) {
			cleanupFailure := errors.New("old publisher physical cleanup failed")
			started := make(chan string, 2)
			stopping := make(chan struct{})
			release := make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })
			var cleanups atomic.Int32
			manager, err := newTestManager(t, t.TempDir(), t.TempDir(), []Service{{Name: "web"}}, func(ctx context.Context, service Service, _ func(PublicationUpdate) error) error {
				started <- service.Target
				<-ctx.Done()
				if service.Target == "http://127.0.0.1:3000" {
					close(stopping)
					<-release
					cleanups.Add(1)
					if failed {
						return errors.Join(ctx.Err(), cleanupFailure)
					}
				}
				return ctx.Err()
			})
			if err != nil {
				t.Fatal(err)
			}
			defer manager.Close()
			defer unblock()
			var allocationCleanups atomic.Int32
			manager.Cleanup = func(Service) error {
				allocationCleanups.Add(1)
				return nil
			}
			id, err := manager.Reserve("web", "owner", 1, "")
			if err != nil {
				t.Fatal(err)
			}
			const previous, next = "http://127.0.0.1:3000", "http://127.0.0.1:3001"
			if err := manager.Register(id, "owner", previous, "node"); err != nil {
				t.Fatal(err)
			}
			<-started
			replaced := make(chan error, 1)
			go func() { replaced <- manager.Register(id, "owner", next, "node") }()
			<-stopping
			select {
			case err := <-replaced:
				t.Fatal("replacement returned before old publisher cleanup joined", err)
			case target := <-started:
				t.Fatal("replacement started before old publisher cleanup joined", target)
			default:
			}
			unblock()
			err = <-replaced
			if failed {
				if !errors.Is(err, cleanupFailure) || errors.Is(err, context.Canceled) {
					t.Fatal("replacement discarded the old publisher's independent cleanup failure", err)
				}
				select {
				case target := <-started:
					t.Fatal("replacement started after unconfirmed old cleanup", target)
				default:
				}
				if !errors.Is(manager.RetirementError(), cleanupFailure) {
					t.Fatal("replacement lost the old cleanup failure at the retirement boundary", manager.RetirementError())
				}
				if err := manager.Register(id, "owner", next, "node"); !errors.Is(err, cleanupFailure) {
					t.Fatal("repeated replacement cleared the old cleanup failure", err)
				}
				if allocationCleanups.Load() != 0 {
					t.Fatal("replacement ran unregister cleanup instead of retaining ownership")
				}
				if err := manager.UnregisterTarget(id, "owner", previous); !errors.Is(err, cleanupFailure) {
					t.Fatal("later unregister discarded the retained old cleanup failure", err)
				}
			} else {
				if err != nil {
					t.Fatal("expected cancellation prevented clean replacement", err)
				}
				select {
				case target := <-started:
					if target != next {
						t.Fatal("replacement started the wrong listener", target)
					}
				case <-time.After(time.Second):
					t.Fatal("clean replacement did not start")
				}
				if err := manager.UnregisterTarget(id, "owner", next); err != nil {
					t.Fatal("clean replacement could not stop", err)
				}
				if err := manager.RetirementError(); err != nil {
					t.Fatal("expected old cancellation became a retirement failure", err)
				}
			}
			if cleanups.Load() != 1 {
				t.Fatal("replacement or later unregister repeated old cleanup", cleanups.Load())
			}
			if allocationCleanups.Load() != 1 {
				t.Fatal("final unregister did not run exact allocation cleanup once", allocationCleanups.Load())
			}
			if failed && !errors.Is(manager.RetirementError(), cleanupFailure) {
				t.Fatal("later unregister erased the retained replacement failure", manager.RetirementError())
			}
		})
	}
}
