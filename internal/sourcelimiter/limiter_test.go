package sourcelimiter

import (
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLimiterTokenBucketAndSourceNormalization(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	var entryCounts []int
	limiter, err := New(Config{
		Rate: 1, Burst: 2, MaxEntries: 8, IdleExpiration: time.Minute, Shards: 4,
		Now: func() time.Time { return now },
		OnEntriesChanged: func(entries int) {
			entryCounts = append(entryCounts, entries)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for index, source := range []string{"::ffff:192.0.2.1", "192.0.2.1", "192.0.2.1"} {
		allowed := limiter.Allow(netip.MustParseAddr(source))
		if allowed != (index < 2) {
			t.Fatalf("IPv4 attempt %d allowed = %v", index, allowed)
		}
	}
	now = now.Add(time.Second)
	if !limiter.Allow(netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("refilled IPv4 source was rejected")
	}
	for index, source := range []string{"2001:db8:1:2::1", "2001:db8:1:2::2", "2001:db8:1:2::3"} {
		allowed := limiter.Allow(netip.MustParseAddr(source))
		if allowed != (index < 2) {
			t.Fatalf("IPv6 /64 attempt %d allowed = %v", index, allowed)
		}
	}
	if limiter.Entries() != 2 || !slices.Equal(entryCounts, []int{0, 1, 2}) {
		t.Fatalf("entries = %d, changes = %v", limiter.Entries(), entryCounts)
	}
}

func TestLimiterBoundsEntriesAndEvictsOldest(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	limiter, err := New(Config{
		Rate: 0.000001, Burst: 1, MaxEntries: 2, IdleExpiration: time.Hour, Shards: 4,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	a := netip.MustParseAddr("192.0.2.1")
	b := netip.MustParseAddr("192.0.2.2")
	c := netip.MustParseAddr("192.0.2.3")
	if !limiter.Allow(a) {
		t.Fatal("first source was rejected")
	}
	now = now.Add(time.Second)
	if !limiter.Allow(b) {
		t.Fatal("second source was rejected")
	}
	now = now.Add(time.Second)
	if !limiter.Allow(c) {
		t.Fatal("third source was rejected")
	}
	if limiter.Entries() != 2 || limiterHasEntry(limiter, a) || !limiterHasEntry(limiter, b) || !limiterHasEntry(limiter, c) {
		t.Fatalf("unexpected bounded entries after eviction: count=%d, a=%v, b=%v, c=%v",
			limiter.Entries(), limiterHasEntry(limiter, a), limiterHasEntry(limiter, b), limiterHasEntry(limiter, c))
	}
}

func TestLimiterConcurrentCardinalityBound(t *testing.T) {
	var maximum atomic.Int64
	limiter, err := New(Config{Rate: 1000, Burst: 10, MaxEntries: 128, IdleExpiration: time.Minute, Shards: 16,
		OnEntriesChanged: func(entries int) {
			// The callback runs under entriesMu; it must not call Entries.
			for old := maximum.Load(); int64(entries) > old; old = maximum.Load() {
				if maximum.CompareAndSwap(old, int64(entries)) {
					break
				}
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for worker := range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			for index := range 200 {
				source := netip.AddrFrom4([4]byte{10, byte(worker), byte(index >> 8), byte(index)})
				limiter.Allow(source)
			}
		}()
	}
	group.Wait()
	if entries := limiter.Entries(); entries != 128 {
		t.Fatalf("entries = %d, want 128", entries)
	}
	if got := maximum.Load(); got != 128 {
		t.Fatalf("maximum observed cardinality = %d, want 128", got)
	}
}

func TestLimiterRevisitUpdatesEvictionOrder(t *testing.T) {
	for _, burst := range []int{1, 2} {
		t.Run(fmt.Sprintf("burst=%d", burst), func(t *testing.T) {
			now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
			limiter, err := New(Config{Rate: 0.000001, Burst: burst, MaxEntries: 2, Shards: 4,
				IdleExpiration: time.Hour, Now: func() time.Time { return now }})
			if err != nil {
				t.Fatal(err)
			}
			a, b, c := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.3")
			if !limiter.Allow(a) {
				t.Fatal("first source rejected")
			}
			now = now.Add(time.Second)
			if !limiter.Allow(b) {
				t.Fatal("second source rejected")
			}
			now = now.Add(time.Second)
			if allowed := limiter.Allow(a); allowed != (burst == 2) {
				t.Fatalf("revisit allowed = %t", allowed)
			}
			now = now.Add(time.Second)
			if !limiter.Allow(c) {
				t.Fatal("new source rejected")
			}
			if !limiterHasEntry(limiter, a) || limiterHasEntry(limiter, b) || !limiterHasEntry(limiter, c) || limiter.Entries() != 2 {
				t.Fatal("revisited source, including a denied revisit, must outlive the older source")
			}
		})
	}
}

func TestLimiterIdleExpiration(t *testing.T) {
	for _, elapsed := range []time.Duration{time.Minute - time.Nanosecond, time.Minute} {
		t.Run(elapsed.String(), func(t *testing.T) {
			now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
			limiter, err := New(Config{Rate: 0.000001, Burst: 1, MaxEntries: 2, Shards: 1,
				IdleExpiration: time.Minute, Now: func() time.Time { return now }})
			if err != nil {
				t.Fatal(err)
			}
			source := netip.MustParseAddr("192.0.2.1")
			if !limiter.Allow(source) {
				t.Fatal("first source rejected")
			}
			now = now.Add(elapsed)
			if allowed := limiter.Allow(source); allowed != (elapsed == time.Minute) {
				t.Fatalf("after %v allowed = %t", elapsed, allowed)
			}
		})
	}
	t.Run("reap on insertion", func(t *testing.T) {
		now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
		limiter, err := New(Config{Rate: 1, Burst: 1, MaxEntries: 2, Shards: 1,
			IdleExpiration: time.Minute, Now: func() time.Time { return now }})
		if err != nil {
			t.Fatal(err)
		}
		a, b, c := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.3")
		limiter.Allow(a)
		limiter.Allow(b)
		now = now.Add(time.Minute)
		if !limiter.Allow(c) || limiter.Entries() != 1 || limiterHasEntry(limiter, a) || limiterHasEntry(limiter, b) {
			t.Fatal("idle entries were not reaped at expiration")
		}
	})
}

func TestNewRejectsInvalidConfiguration(t *testing.T) {
	for _, config := range []Config{
		{Rate: -1},
		{Burst: -1},
		{MaxEntries: -1},
		{IdleExpiration: -1},
		{Shards: -1},
	} {
		if _, err := New(config); err == nil {
			t.Fatalf("invalid configuration was accepted: %#v", config)
		}
	}
}

func limiterHasEntry(limiter *Limiter, source netip.Addr) bool {
	key, ok := Normalize(source)
	if !ok {
		return false
	}
	selected := limiter.shard(key)
	selected.Lock()
	defer selected.Unlock()
	return selected.entries[key] != nil
}
