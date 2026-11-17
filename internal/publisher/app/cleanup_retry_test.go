package app

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"
)

func TestManagerExplicitCleanupRetryDoesNotResetAutomaticShutdown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		manager, err := newTestManager(t, t.TempDir(), t.TempDir(), []Service{{Name: "web"}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer manager.Close()
		const owner = "owner"
		id, err := manager.Reserve("web", owner, 1, "https://web.example")
		if err != nil {
			t.Fatal(err)
		}
		until := time.Now().Add(time.Second)
		if err := manager.LimitShutdown(id, owner, "", until); err != nil {
			t.Fatal(err)
		}
		shutdown := manager.PublicationShutdownContext(id)
		failure := errors.New("independent allocation deletion failure")
		entered := make(chan context.Context, 1)
		attempts := 0
		manager.Cleanup = func(service Service) error {
			attempts++
			if service.RegistrationID != id {
				t.Error("cleanup changed the retained allocation's registration")
			}
			ctx := manager.PublicationCleanupContext(id)
			entered <- ctx
			if attempts == 1 {
				<-ctx.Done()
				return errors.Join(context.Cause(ctx), failure)
			}
			return nil
		}
		first := make(chan error, 1)
		go func() { first <- manager.UnregisterTarget(id, owner, "") }()
		active := <-entered
		time.Sleep(time.Until(until))
		if err := <-first; !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, failure) {
			t.Fatal("initial cleanup lost timeout or its independent failure", err)
		}
		synctest.Wait()
		if active.Err() == nil || context.Cause(shutdown) != context.DeadlineExceeded {
			t.Fatal("the original automatic shutdown fence did not expire")
		}
		// an automatic sweep must not acquire a fresh budget, even after the SDK
		// lease has expired. it still retains exact cleanup ownership on failure.
		time.Sleep(LeaseDuration)
		if manager.Sweep(func(int) bool { return false }) {
			t.Fatal("retained cleanup made the process idle or poisoned its journal")
		}
		if attempts != 1 {
			t.Fatal("an automatic cleanup loop restarted its exhausted operation", attempts)
		}
		retryUntil := time.Now().Add(2 * time.Second)
		if err := manager.LimitShutdown(id, "other-owner", "", retryUntil); !errors.Is(err, ErrRegistrationStale) {
			t.Fatal("another owner selected the retry's deadline", err)
		}
		if err := manager.UnregisterTarget(id, owner, "another-target"); !errors.Is(err, ErrRegistrationStale) || attempts != 1 {
			t.Fatal("another target retried retained allocation cleanup", err, attempts)
		}
		if err := manager.LimitShutdown(id, owner, "", retryUntil); err != nil {
			t.Fatal("exact cleanup capability expired with the SDK lease", err)
		}
		if got := manager.PublicationShutdownDeadline(id); !got.Equal(until) {
			t.Fatal("explicit retry changed the original automatic shutdown deadline", got, until)
		}
		if err := manager.UnregisterTarget(id, owner, ""); err != nil {
			t.Fatal("recovered exact cleanup could not complete", err)
		}
		retry := <-entered
		if got, _ := retry.Deadline(); !got.Equal(retryUntil) || context.Cause(retry) != context.Canceled {
			t.Fatal("explicit retry did not own and join its separate bounded lifetime", got, context.Cause(retry))
		}
		if _, retained := manager.ServiceForRegistration(id); retained || attempts != 2 {
			t.Fatal("confirmed cleanup did not release only the retained registration", retained, attempts)
		}
		if !errors.Is(manager.RetirementError(), failure) || !errors.Is(manager.RetirementError(), context.DeadlineExceeded) {
			t.Fatal("successful retry erased the first cleanup's failures", manager.RetirementError())
		}
		if err := manager.UnregisterTarget(id, owner, ""); err != nil || attempts != 2 {
			t.Fatal("lost reply recovery repeated confirmed deletion", err, attempts)
		}
	})
}
