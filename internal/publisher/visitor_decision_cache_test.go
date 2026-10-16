package publisher

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

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
		return "", time.Time{}, false, errors.New("control is unavailable")
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
