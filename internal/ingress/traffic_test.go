package ingress

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func trafficFixture(t *testing.T) *trafficAdmission {
	t.Helper()
	c, err := (TrafficConfig{}).Resolve()
	if err != nil {
		t.Fatal(err)
	}
	p, err := (PendingConfig{}).Resolve()
	if err != nil {
		t.Fatal(err)
	}
	return newTrafficAdmission(c, p)
}

func TestRunBucketsSurviveRefreshAndSeparateRuns(t *testing.T) {
	a := trafficFixture(t)
	l := a.config.Default
	l.Burst = 1
	l.Rate = 1
	l.RatePer = time.Hour
	key := trafficKey{url: "url", run: 1}
	release, reason := a.acquire(key, l)
	if release == nil {
		t.Fatal(reason)
	}
	release()
	if release, reason := a.acquire(key, l); release != nil || reason != "public_url_connection_rate" {
		t.Fatal("same run refilled", reason)
	}
	if release, reason := a.acquire(trafficKey{url: "url", run: 2}, l); release == nil {
		t.Fatal(reason)
	} else {
		release()
	}
	if release, reason := a.acquire(trafficKey{url: "other", run: 1}, l); release == nil {
		t.Fatal(reason)
	} else {
		release()
	}
}

func TestRunConcurrencyAndTotalsAreAtomic(t *testing.T) {
	a := trafficFixture(t)
	l := a.config.Default
	l.Connections = 3
	l.Burst = 100
	l.TotalConnections = 3
	var group sync.WaitGroup
	var accepted atomic.Int32
	releases := make(chan func(), 50)
	for range 50 {
		group.Go(func() {
			if release, _ := a.acquire(trafficKey{url: "url", run: 1}, l); release != nil {
				accepted.Add(1)
				releases <- release
			}
		})
	}
	group.Wait()
	close(releases)
	if accepted.Load() != 3 {
		t.Fatal(accepted.Load())
	}
	for release := range releases {
		release()
		release()
	}
	if release, reason := a.acquire(trafficKey{url: "url", run: 1}, l); release != nil || reason != "public_url_connection_total" {
		t.Fatal(reason)
	}
}

func TestEncryptedBytesTotalsWaitAndCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a := trafficFixture(t)
		l := a.config.Default
		l.UploadBytes = 64 << 10
		l.TotalDownloadBytes = 4
		key := trafficKey{url: "url", run: 1}
		release, _ := a.acquire(key, l)
		defer release()
		if err := a.bytes(t.Context(), key, false, 4, true); err != nil {
			t.Fatal(err)
		}
		if err := a.bytes(t.Context(), key, false, 1, true); err == nil {
			t.Fatal("total exceeded")
		}
		if err := a.bytes(t.Context(), key, true, 64<<10, true); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		if err := a.bytes(t.Context(), key, true, 32<<10, true); err != nil {
			t.Fatal(err)
		}
		if time.Since(start) < 500*time.Millisecond {
			t.Fatal("upload did not wait")
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if err := a.bytes(ctx, key, true, 1, true); err == nil {
			t.Fatal("cancellation ignored")
		}
		time.Sleep(3 * time.Minute)
		a.mu.Lock()
		a.prune(time.Now())
		a.mu.Unlock()
		if err := a.bytes(t.Context(), key, false, 1, true); err == nil {
			t.Fatal("idle pruning reset total")
		}
	})
}

func TestSourceAndPendingBudgetsUseIPv6Networks(t *testing.T) {
	a := trafficFixture(t)
	a.pending.SourceConnections = 1
	key := trafficKey{url: "url", run: 1}
	one := netip.MustParseAddr("2001:db8::1")
	two := netip.MustParseAddr("2001:db8::2")
	release, reason := a.acquirePending(key, one)
	if release == nil {
		t.Fatal(reason)
	}
	if r, reason := a.acquirePending(trafficKey{url: "other", run: 1}, two); r != nil || reason != "pending_source_connections" {
		t.Fatal(reason)
	}
	release()
	release()
	if r, reason := a.acquirePending(key, two); r == nil {
		t.Fatal(reason)
	} else {
		r()
	}
	a.config.SourceBurst = 1
	r, reason := a.source(one)
	if r == nil {
		t.Fatal(reason)
	}
	defer r()
	if r, reason := a.source(two); r != nil || reason != "source_connection_rate" {
		t.Fatal(reason)
	}
}

func TestRunTotalsRetireOnlyAfterTrustedRunClosure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a := trafficFixture(t)
		key := trafficKey{url: "url", id: "run", run: 1}
		l := a.config.Default
		l.TotalConnections = 1
		terminal := map[TrafficRun]struct{}{}
		a.terminalRuns = func([]TrafficRun) map[TrafficRun]struct{} { return terminal }
		release, _ := a.acquire(key, l)
		release()
		time.Sleep(3 * time.Minute)
		if release, reason := a.acquire(key, l); release != nil || reason != "public_url_connection_total" {
			t.Fatal("refresh reset live totals", reason)
		}
		terminal[TrafficRun{PublicURLID: key.url, PublishRunID: key.id, PublishRunNumber: key.run}] = struct{}{}
		time.Sleep(31 * time.Second)
		a.mu.Lock()
		a.prune(time.Now())
		_, exists := a.runs[key]
		a.mu.Unlock()
		if exists {
			t.Fatal("retired run retained total state")
		}
	})
}
