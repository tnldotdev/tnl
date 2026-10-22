package publisher

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/failure"
)

func TestVisitorDecisionCacheExplicitErrorsEvictAllowance(t *testing.T) {
	for _, denied := range []error{clientcontrol.ErrUnauthenticated, &clientcontrol.ProblemError{Status: 403}, errors.New("invalid authority response")} {
		t.Run(denied.Error(), func(t *testing.T) {
			var cache visitorDecisionCache[bool]
			key := sha256.Sum256([]byte("original browser cookie"))
			if _, err := cache.check(t.Context(), key, func(context.Context) (bool, time.Time, bool, error) {
				return true, time.Now().Add(time.Hour), true, nil
			}); err != nil {
				t.Fatal(err)
			}
			cache.mu.Lock()
			entry := cache.entries[key]
			entry.refreshAfter = time.Now().Add(-time.Second)
			cache.entries[key] = entry
			cache.mu.Unlock()
			got, err := cache.check(t.Context(), key, func(context.Context) (bool, time.Time, bool, error) {
				return false, time.Time{}, false, denied
			})
			if got || !errors.Is(err, denied) {
				t.Fatalf("terminal error restored allowance: allowed=%t, err=%v", got, err)
			}
			if len(cache.entries) != 0 {
				t.Fatal("terminal error retained a positive decision")
			}
		})
	}
}

func TestVisitorDecisionCacheBoundsRevocationAndOutages(t *testing.T) {
	var cache visitorDecisionCache[string]
	key := sha256.Sum256([]byte("one URL, run, IP and credential"))
	checks := 0
	load := func(context.Context) (string, time.Time, bool, error) {
		checks++
		return "allowed", time.Now().Add(time.Hour), true, nil
	}
	if result, err := cache.check(t.Context(), key, load); err != nil || result != "allowed" {
		t.Fatal(result, err)
	}
	if _, err := cache.check(t.Context(), key, load); err != nil || checks != 1 {
		t.Fatalf("cache hit made %d control checks: %v", checks, err)
	}
	cache.mu.Lock()
	entry := cache.entries[key]
	if entry.validUntil.After(entry.checkedAt.Add(visitorDecisionLifetime)) {
		t.Fatal("cache exceeded its hard lifetime")
	}
	entry.refreshAfter = time.Now().Add(-time.Second)
	cache.entries[key] = entry
	cache.mu.Unlock()
	unavailable := func(context.Context) (string, time.Time, bool, error) {
		checks++
		return "", time.Time{}, false, clientcontrol.ErrUnavailable
	}
	if result, err := cache.check(t.Context(), key, unavailable); err != nil || result != "allowed" {
		t.Fatalf("unexpired decision during outage = %q, %v", result, err)
	}
	cache.mu.Lock()
	entry = cache.entries[key]
	entry.validUntil = time.Now().Add(-time.Second)
	cache.entries[key] = entry
	cache.mu.Unlock()
	if _, err := cache.check(t.Context(), key, unavailable); err == nil {
		t.Fatal("expired decision survived control outage")
	}
	if _, err := cache.check(t.Context(), sha256.Sum256([]byte("another credential")), unavailable); err == nil {
		t.Fatal("unknown credential was allowed during outage")
	}
}

func TestVisitorDecisionCacheDoesNotRetainDenialsOrExpiredProofs(t *testing.T) {
	var cache visitorDecisionCache[bool]
	key := sha256.Sum256([]byte("visitor"))
	checked := 0
	check := func(context.Context) (bool, time.Time, bool, error) {
		checked++
		return true, time.Now().Add(30 * time.Second), true, nil
	}
	if _, err := cache.check(t.Context(), key, check); err != nil {
		t.Fatal(err)
	}
	cache.mu.Lock()
	entry := cache.entries[key]
	if entry.validUntil.After(time.Now().Add(31 * time.Second)) {
		t.Fatal("proof expiration was ignored")
	}
	entry.refreshAfter = time.Now().Add(-time.Second)
	cache.entries[key] = entry
	cache.mu.Unlock()
	denied := func(context.Context) (bool, time.Time, bool, error) {
		checked++
		return false, time.Now().Add(time.Hour), false, nil
	}
	if result, err := cache.check(t.Context(), key, denied); err != nil || result {
		t.Fatalf("revoked proof = %t, %v", result, err)
	}
	if result, err := cache.check(t.Context(), key, denied); err != nil || result || checked != 3 {
		t.Fatalf("denial was reused: %t, checks=%d, %v", result, checked, err)
	}
}

func TestVisitorDecisionCacheSharesOneUncachedCheck(t *testing.T) {
	var cache visitorDecisionCache[string]
	key := sha256.Sum256([]byte("one credential"))
	started := make(chan struct{})
	finish := make(chan struct{})
	var count atomic.Int32
	load := func(context.Context) (string, time.Time, bool, error) {
		if count.Add(1) == 1 {
			close(started)
			<-finish
		}
		return "allowed", time.Now().Add(time.Minute), true, nil
	}
	var workers sync.WaitGroup
	for range 20 {
		workers.Go(func() {
			result, err := cache.check(t.Context(), key, load)
			if err != nil || result != "allowed" {
				t.Errorf("shared check = %q, %v", result, err)
			}
		})
	}
	<-started
	close(finish)
	workers.Wait()
	if count.Load() != 1 {
		t.Fatalf("one cache miss made %d control checks", count.Load())
	}
}

func TestVisitorDecisionCacheWaitersCancelIndependentlyAndJoinLastCleanup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var cache visitorDecisionCache[bool]
		key := sha256.Sum256([]byte("same run, source and original browser cookie"))
		until := time.Now().Add(time.Minute)
		if _, err := cache.check(t.Context(), key, func(context.Context) (bool, time.Time, bool, error) {
			return true, until, true, nil
		}); err != nil {
			t.Fatal(err)
		}
		original := cache.entries[key]
		started, cleanupStarted, releaseCleanup, stopped := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
		defer func() {
			select {
			case <-releaseCleanup:
			default:
				close(releaseCleanup)
			}
		}()
		load := func(ctx context.Context) (bool, time.Time, bool, error) {
			close(started)
			<-ctx.Done()
			close(cleanupStarted)
			<-releaseCleanup
			close(stopped)
			return false, time.Time{}, false, ctx.Err()
		}
		firstCtx, cancelFirst := context.WithCancel(t.Context())
		defer cancelFirst()
		first := make(chan error, 1)
		go func() { _, _, err := cache.checkCurrent(firstCtx, key, true, load); first <- err }()
		<-started
		secondCtx, cancelSecond := context.WithCancel(t.Context())
		defer cancelSecond()
		second := make(chan error, 1)
		go func() { _, _, err := cache.checkCurrent(secondCtx, key, true, load); second <- err }()
		synctest.Wait()
		cancelSecond()
		if err := <-second; !errors.Is(err, context.Canceled) {
			t.Fatalf("second waiter cancellation = %v", err)
		}
		select {
		case <-cleanupStarted:
			t.Fatal("canceling a waiter canceled the initiator's work")
		default:
		}
		cancelFirst()
		<-cleanupStarted
		synctest.Wait()
		select {
		case err := <-first:
			t.Fatalf("last waiter returned before joining authority cleanup: %v", err)
		default:
		}
		close(releaseCleanup)
		if err := <-first; !errors.Is(err, context.Canceled) {
			t.Fatalf("last waiter cancellation = %v", err)
		}
		select {
		case <-stopped:
		default:
			t.Fatal("authority work outlived its last waiter")
		}
		if len(cache.active) != 0 {
			t.Fatal("canceled work remained active")
		}
		if got := cache.entries[key]; !got.validUntil.Equal(original.validUntil) || !got.checkedAt.Equal(original.checkedAt) || !got.value {
			t.Fatal("caller cancellation evicted or extended the last successful decision")
		}
	})
}

func TestVisitorDecisionCacheOwnedTimeoutPreservesDeadlineAndTerminalFailures(t *testing.T) {
	for _, test := range []struct {
		name     string
		err      error
		fallback bool
	}{
		{"owned timeout", clientcontrol.ErrUnavailable, true},
		{"unauthenticated", clientcontrol.ErrUnauthenticated, false},
		{"forbidden", &clientcontrol.ProblemError{Status: 403}, false},
		{"malformed", errors.New("invalid authority response"), false},
		{"malformed with timeout cause", failure.Wrap("decode authority response", failure.ServerResponseInvalid, context.DeadlineExceeded), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var cache visitorDecisionCache[bool]
				key := sha256.Sum256([]byte("original credential"))
				until := time.Now().Add(time.Minute)
				if _, err := cache.check(t.Context(), key, func(context.Context) (bool, time.Time, bool, error) { return true, until, true, nil }); err != nil {
					t.Fatal(err)
				}
				original := cache.entries[key]
				started := time.Now()
				allowed, _, err := cache.checkCurrent(t.Context(), key, true, func(ctx context.Context) (bool, time.Time, bool, error) {
					<-ctx.Done()
					if test.fallback {
						// controlclient preserves the owned request's structured cause.
						return false, time.Time{}, false, context.Cause(ctx)
					}
					return false, time.Time{}, false, test.err
				})
				if elapsed := time.Since(started); elapsed != 5*time.Second {
					t.Fatalf("shared authority lifetime = %s, want 5s", elapsed)
				}
				if test.fallback {
					if err != nil || !allowed {
						t.Fatalf("owned timeout lost the bounded last success: allowed=%t, err=%v", allowed, err)
					}
					if got := cache.entries[key]; !got.validUntil.Equal(original.validUntil) || !got.checkedAt.Equal(original.checkedAt) {
						t.Fatal("owned timeout extended the last successful deadline")
					}
				} else if allowed || !errors.Is(err, test.err) || len(cache.entries) != 0 {
					t.Fatalf("terminal authority failure became outage fallback: allowed=%t, err=%v", allowed, err)
				}
				if len(cache.active) != 0 {
					t.Fatal("bounded authority work was not joined")
				}
			})
		})
	}
}
