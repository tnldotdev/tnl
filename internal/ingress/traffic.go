package ingress

import (
	"context"
	"errors"
	"math"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
)

type TrafficLimits = trafficlimits.Limits

type TrafficConfig = trafficlimits.IngressConfig

type PendingConfig = trafficlimits.PendingConfig

const maxTrafficKeys = 100_000
const maxTrafficWait = 2 * time.Second

type trafficKey struct {
	service string
	run     uint64
	id      string
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

func (b *tokenBucket) refill(rate, burst float64, now time.Time) float64 {
	if b.last.IsZero() {
		b.tokens = burst
	} else {
		b.tokens = min(burst, b.tokens+max(0, now.Sub(b.last).Seconds())*rate)
	}
	b.last = now
	return b.tokens
}

type runTraffic struct {
	limits                             TrafficLimits
	active                             int
	connections, upload, download      int64
	newConnections, uploads, downloads tokenBucket
	seen                               time.Time
	terminalCheck                      time.Time
}

type sourceTraffic struct {
	attempts    tokenBucket
	pending     tokenBucket
	active      int
	connections int
	seen        time.Time
}
type pendingTraffic struct {
	attempts tokenBucket
	active   int
	seen     time.Time
}

// trafficAdmission owns all buckets, never routing views or relay backends.
// totals stay resident for the run's lifetime; exhaustion of the bounded key
// table fails closed rather than resetting an old run's counters.
type trafficAdmission struct {
	mu                              sync.Mutex
	config                          TrafficConfig
	pending                         PendingConfig
	runs                            map[trafficKey]*runTraffic
	sources                         map[netip.Prefix]*sourceTraffic
	pendingRuns                     map[trafficKey]*pendingTraffic
	connections, uploads, downloads tokenBucket
	lastPrune                       time.Time
	lastTerminalLookup              time.Time
}

// terminalCandidates snapshots a bounded batch without holding the meter lock
// during control I/O. oldest checks come first so unknown runs cannot starve
// later runs when the table is full.
func (a *trafficAdmission) terminalCandidates(now time.Time) []ingressv1.ServiceRunReference {
	a.mu.Lock()
	defer a.mu.Unlock()
	if now.Sub(a.lastTerminalLookup) < 30*time.Second {
		return nil
	}
	keys := make([]trafficKey, 0, len(a.runs))
	for key, run := range a.runs {
		if run.active == 0 && (run.limits.TotalConnections > 0 || run.limits.TotalUploadBytes > 0 || run.limits.TotalDownloadBytes > 0) {
			keys = append(keys, key)
		}
	}
	slices.SortFunc(keys, func(left, right trafficKey) int {
		return a.runs[left].terminalCheck.Compare(a.runs[right].terminalCheck)
	})
	keys = keys[:min(len(keys), 128)]
	result := make([]ingressv1.ServiceRunReference, 0, len(keys))
	for _, key := range keys {
		a.runs[key].terminalCheck = now
		result = append(result, ingressv1.ServiceRunReference{ServiceId: key.service, ServiceRunId: key.id, RunNumber: int64(key.run)})
	}
	if len(result) != 0 {
		a.lastTerminalLookup = now
	}
	return result
}

func (a *trafficAdmission) retireTerminal(runs []ingressv1.ServiceRunReference) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, run := range runs {
		key := trafficKey{service: run.ServiceId, id: run.ServiceRunId, run: uint64(run.RunNumber)}
		if current := a.runs[key]; current != nil && current.active == 0 {
			delete(a.runs, key)
		}
	}
}

func newTrafficAdmission(c TrafficConfig, p PendingConfig) *trafficAdmission {
	return &trafficAdmission{config: c, pending: p, runs: map[trafficKey]*runTraffic{}, sources: map[netip.Prefix]*sourceTraffic{}, pendingRuns: map[trafficKey]*pendingTraffic{}}
}

func take(b *tokenBucket, rate, burst float64, now time.Time) bool {
	if b.refill(rate, burst, now) < 1 {
		return false
	}
	b.tokens--
	return true
}

func (a *trafficAdmission) source(addr netip.Addr) (func(), string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	a.prune(now)
	s := a.sourceLocked(addr)
	if s == nil || !take(&s.attempts, float64(a.config.SourceRate), float64(a.config.SourceBurst), now) {
		return nil, "source_connection_rate"
	}
	s.seen = now
	if s.connections >= a.config.SourceConnections {
		return nil, "source_connections"
	}
	s.connections++
	return sync.OnceFunc(func() { a.mu.Lock(); s.connections--; s.seen = time.Now(); a.mu.Unlock() }), ""
}

func (a *trafficAdmission) process() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return take(&a.connections, float64(a.config.ProcessRate), float64(a.config.ProcessBurst), time.Now())
}

func (a *trafficAdmission) sourceLocked(addr netip.Addr) *sourceTraffic {
	key := trafficlimits.SourceNetwork(addr)
	if !key.IsValid() {
		return nil
	}
	s := a.sources[key]
	if s == nil && len(a.sources) < maxTrafficKeys {
		s = &sourceTraffic{}
		a.sources[key] = s
	}
	return s
}

func (a *trafficAdmission) acquire(key trafficKey, limits TrafficLimits) (func(), string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	a.prune(now)
	r := a.runs[key]
	if r == nil {
		if len(a.runs) >= maxTrafficKeys {
			return nil, "traffic_keys"
		}
		r = &runTraffic{limits: limits}
		a.runs[key] = r
	}
	// approval is immutable for an exact run; refreshes never replace its budget.
	if r.limits != limits {
		return nil, "invalid_traffic_projection"
	}
	r.seen = now
	if r.active >= limits.Connections {
		return nil, "service_connections"
	}
	if limits.TotalConnections > 0 && r.connections >= limits.TotalConnections {
		return nil, "service_connection_total"
	}
	if !take(&r.newConnections, float64(limits.Rate)/limits.Period().Seconds(), float64(limits.Burst), now) {
		return nil, "service_connection_rate"
	}
	r.active++
	r.connections = min(math.MaxInt64-1, r.connections) + 1
	return sync.OnceFunc(func() { a.mu.Lock(); r.active--; r.seen = time.Now(); a.mu.Unlock() }), ""
}

func (a *trafficAdmission) acquirePending(key trafficKey, addr netip.Addr) (func(), string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	a.prune(now)
	s := a.sourceLocked(addr)
	if s == nil {
		return nil, "pending_source_capacity"
	}
	p := a.pendingRuns[key]
	if p == nil {
		if len(a.pendingRuns) >= maxTrafficKeys {
			return nil, "traffic_keys"
		}
		p = &pendingTraffic{}
		a.pendingRuns[key] = p
	}
	s.seen, p.seen = now, now
	if s.active >= a.pending.SourceConnections {
		return nil, "pending_source_connections"
	}
	if p.active >= a.pending.PublicURLConnections {
		return nil, "pending_service_connections"
	}
	if !take(&s.pending, float64(a.pending.SourceRate), float64(a.pending.SourceBurst), now) {
		return nil, "pending_source_rate"
	}
	if !take(&p.attempts, float64(a.pending.PublicURLRate), float64(a.pending.PublicURLBurst), now) {
		return nil, "pending_service_rate"
	}
	s.active++
	p.active++
	return sync.OnceFunc(func() {
		a.mu.Lock()
		s.active--
		p.active--
		s.seen = time.Now()
		p.seen = s.seen
		a.mu.Unlock()
	}), ""
}

func (a *trafficAdmission) prune(now time.Time) {
	if now.Sub(a.lastPrune) < 30*time.Second {
		return
	}
	a.lastPrune = now
	for key, s := range a.sources {
		refill := max(float64(a.config.SourceBurst)/float64(a.config.SourceRate), float64(a.pending.SourceBurst)/float64(a.pending.SourceRate))
		if s.active == 0 && s.connections == 0 && now.Sub(s.seen).Seconds() > max(120, refill) {
			delete(a.sources, key)
		}
	}
	for key, p := range a.pendingRuns {
		if p.active == 0 && now.Sub(p.seen).Seconds() > max(120, float64(a.pending.PublicURLBurst)/float64(a.pending.PublicURLRate)) {
			delete(a.pendingRuns, key)
		}
	}
	for key, r := range a.runs {
		l := r.limits
		refill := float64(l.Burst) / float64(l.Rate) * l.Period().Seconds()
		if r.active == 0 && l.TotalConnections == 0 && l.TotalUploadBytes == 0 && l.TotalDownloadBytes == 0 && now.Sub(r.seen).Seconds() > max(120, refill) {
			delete(a.runs, key)
		}
	}
}

type trafficError string

func (e trafficError) Error() string { return "ingress: " + string(e) }

func (a *trafficAdmission) bytes(ctx context.Context, key trafficKey, upload bool, size int, ordinary bool) error {
	deadline := time.Now().Add(maxTrafficWait)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		now := time.Now()
		a.mu.Lock()
		process, rate := &a.downloads, a.config.ProcessDownload
		if upload {
			process, rate = &a.uploads, a.config.ProcessUpload
		}
		available := process.refill(float64(rate), float64(rate), now)
		wait := max(0, float64(size)-available) / float64(rate)
		reason := "process_bandwidth"
		var bucket *tokenBucket
		var total *int64
		if ordinary {
			r := a.runs[key]
			if r == nil {
				a.mu.Unlock()
				return trafficError("service_traffic_missing")
			}
			bucket, total = &r.downloads, &r.download
			limit, cap := r.limits.DownloadBytes, r.limits.TotalDownloadBytes
			if upload {
				bucket, total = &r.uploads, &r.upload
				limit, cap = r.limits.UploadBytes, r.limits.TotalUploadBytes
			}
			if cap > 0 && int64(size) > cap-*total {
				a.mu.Unlock()
				return trafficError("service_byte_total")
			}
			runWait := max(0, float64(size)-bucket.refill(float64(limit), float64(limit), now)) / float64(limit)
			if runWait > wait {
				wait = runWait
				reason = "service_bandwidth"
			}
			r.seen = now
		}
		if wait <= 0 {
			process.tokens -= float64(size)
			if bucket != nil {
				bucket.tokens -= float64(size)
				*total = min(math.MaxInt64-int64(size), *total) + int64(size)
			}
			a.mu.Unlock()
			return nil
		}
		a.mu.Unlock()
		delay := max(time.Millisecond, time.Duration(wait*float64(time.Second)))
		if now.Add(delay).After(deadline) {
			return trafficError(reason)
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// budgetConn deliberately exposes neither ReaderFrom nor WriterTo, so encrypted
// copy buffers cannot bypass accounting. each write is bounded for low byte rates.
type budgetConn struct {
	net.Conn
	beforeWrite func(int) error
}

func (c *budgetConn) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		n := min(len(p), 32<<10)
		if err := c.beforeWrite(n); err != nil {
			return written, err
		}
		count, err := c.Conn.Write(p[:n])
		written += count
		if err != nil {
			return written, err
		}
		if count != n {
			return written, errors.New("ingress: short traffic write")
		}
		p = p[n:]
	}
	return written, nil
}
func (c *budgetConn) CloseWrite() error {
	if closer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return errors.ErrUnsupported
}
