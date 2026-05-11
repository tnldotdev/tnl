// Package sourcelimiter bounds public connection starts by normalized source.
package sourcelimiter

import (
	"errors"
	"math"
	"net/netip"
	"sync"
	"time"
)

const (
	DefaultRate           = 50
	DefaultBurst          = 200
	DefaultMaxEntries     = 8192
	DefaultIdleExpiration = 10 * time.Minute
	DefaultShards         = 64
)

type Config struct {
	Rate             float64
	Burst            int
	MaxEntries       int
	IdleExpiration   time.Duration
	Shards           int
	Now              func() time.Time
	OnEntriesChanged func(int)
}

type Limiter struct {
	shards         []shard
	rate           float64
	burst          float64
	maxEntries     int
	idleExpiration time.Duration
	now            func() time.Time
	onEntries      func(int)

	entriesMu sync.Mutex
	entries   int
}

type shard struct {
	sync.Mutex
	entries map[netip.Addr]*entry
}

type entry struct {
	tokens   float64
	refillAt time.Time
	lastSeen time.Time
}

func New(config Config) (*Limiter, error) {
	if config.Rate == 0 {
		config.Rate = DefaultRate
	}
	if config.Burst == 0 {
		config.Burst = DefaultBurst
	}
	if config.MaxEntries == 0 {
		config.MaxEntries = DefaultMaxEntries
	}
	if config.IdleExpiration == 0 {
		config.IdleExpiration = DefaultIdleExpiration
	}
	if config.Shards == 0 {
		config.Shards = DefaultShards
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Rate <= 0 || math.IsNaN(config.Rate) || math.IsInf(config.Rate, 0) ||
		config.Burst <= 0 || config.MaxEntries <= 0 || config.IdleExpiration <= 0 || config.Shards <= 0 {
		return nil, errors.New("sourcelimiter: limits must be positive and finite")
	}
	limiter := &Limiter{
		shards: make([]shard, config.Shards), rate: config.Rate, burst: float64(config.Burst),
		maxEntries: config.MaxEntries, idleExpiration: config.IdleExpiration,
		now: config.Now, onEntries: config.OnEntriesChanged,
	}
	for index := range limiter.shards {
		limiter.shards[index].entries = make(map[netip.Addr]*entry)
	}
	if limiter.onEntries != nil {
		limiter.onEntries(0)
	}
	return limiter, nil
}

func (l *Limiter) Allow(source netip.Addr) bool {
	key, ok := Normalize(source)
	if !ok {
		return false
	}
	now := l.now()
	selected := l.shard(key)
	selected.Lock()
	current := selected.entries[key]
	if current != nil {
		allowed := l.consume(current, now)
		selected.Unlock()
		return allowed
	}
	selected.Unlock()
	return l.allowNew(key, now)
}

func (l *Limiter) Entries() int {
	l.entriesMu.Lock()
	defer l.entriesMu.Unlock()
	return l.entries
}

// Normalize maps IPv4-mapped addresses to IPv4 and groups IPv6 sources by /64.
func Normalize(source netip.Addr) (netip.Addr, bool) {
	if !source.IsValid() {
		return netip.Addr{}, false
	}
	source = source.WithZone("").Unmap()
	if source.Is6() {
		source = netip.PrefixFrom(source, 64).Masked().Addr()
	}
	return source, true
}

func (l *Limiter) allowNew(key netip.Addr, now time.Time) bool {
	l.entriesMu.Lock()
	selected := l.shard(key)
	selected.Lock()
	if current := selected.entries[key]; current != nil {
		allowed := l.consume(current, now)
		selected.Unlock()
		l.entriesMu.Unlock()
		return allowed
	}
	before := l.entries
	l.reapExpiredShardLocked(selected, now)
	selected.Unlock()
	if l.entries >= l.maxEntries {
		l.reapExpiredLocked(now)
	}
	if l.entries >= l.maxEntries {
		l.evictOldestLocked()
	}
	selected.Lock()
	selected.entries[key] = &entry{tokens: l.burst - 1, refillAt: now, lastSeen: now}
	selected.Unlock()
	l.entries++
	if l.entries != before && l.onEntries != nil {
		l.onEntries(l.entries)
	}
	l.entriesMu.Unlock()
	return true
}

func (l *Limiter) consume(current *entry, now time.Time) bool {
	if !current.lastSeen.Add(l.idleExpiration).After(now) {
		current.tokens = l.burst
		current.refillAt = now
	}
	if now.After(current.refillAt) {
		current.tokens = min(l.burst, current.tokens+now.Sub(current.refillAt).Seconds()*l.rate)
		current.refillAt = now
	}
	if now.After(current.lastSeen) {
		current.lastSeen = now
	}
	if current.tokens < 1 {
		return false
	}
	current.tokens--
	return true
}

func (l *Limiter) reapExpiredLocked(now time.Time) {
	for index := range l.shards {
		selected := &l.shards[index]
		selected.Lock()
		l.reapExpiredShardLocked(selected, now)
		selected.Unlock()
	}
}

func (l *Limiter) reapExpiredShardLocked(selected *shard, now time.Time) {
	for key, current := range selected.entries {
		if !current.lastSeen.Add(l.idleExpiration).After(now) {
			delete(selected.entries, key)
			l.entries--
		}
	}
}

func (l *Limiter) evictOldestLocked() {
	for index := range l.shards {
		l.shards[index].Lock()
	}
	defer func() {
		for index := len(l.shards) - 1; index >= 0; index-- {
			l.shards[index].Unlock()
		}
	}()

	var oldestKey netip.Addr
	var oldestShard *shard
	var oldestTime time.Time
	for index := range l.shards {
		selected := &l.shards[index]
		for key, current := range selected.entries {
			if oldestShard == nil || current.lastSeen.Before(oldestTime) {
				oldestKey, oldestShard = key, selected
				oldestTime = current.lastSeen
			}
		}
	}
	if oldestShard == nil {
		return
	}
	delete(oldestShard.entries, oldestKey)
	l.entries--
}

func (l *Limiter) shard(key netip.Addr) *shard {
	value := key.As16()
	var hash uint64 = 14695981039346656037
	for _, part := range value {
		hash ^= uint64(part)
		hash *= 1099511628211
	}
	return &l.shards[hash%uint64(len(l.shards))]
}
