package telemetry

import (
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	api "github.com/tnldotdev/tnl/pkg/api/integrations/telemetry/v1"
)

// Path names are deliberately limited to the paths in the authored contract.
// bytes are carrier bytes, including framing and retransmissions, when the
// caller measures them at a carrier. they are never application-byte totals.
type Path string

const (
	PublicUDP      Path = "public_udp"
	PublicTCP      Path = "public_tcp"
	NativeDirect   Path = "native_direct"
	NativeRelayUDP Path = "native_relay_udp"
	NativeRelayTCP Path = "native_relay_tcp"
)

type ScopeKind string

const (
	Public ScopeKind = "public_ingress"
	Native ScopeKind = "native_peer"
)

type pathCount struct {
	sent, received uint64
	duration       time.Duration
	rtt            [12]int64
	rttMeasured    bool
	measured       bool
}

// Scope belongs to one independently opted-in publication. methods only
// update bounded memory; queue writes and delivery belong to Collector.run.
type Scope struct {
	collector *Collector
	kind      ScopeKind
	epoch     int64
	started   time.Time
	paths     [3]pathCount
	fallback  [5]int64
	attempts  int64
	successes int64
	direct    [12]int64
	didDirect bool
	closed    bool
	// scopeMu protects every field after collector and kind.
}

func (c *Collector) BeginScope(kind ScopeKind, disabled bool) *Scope {
	if c == nil || c.closed.Load() || disabled || kind != Public && kind != Native {
		return nil
	}
	p := c.preference.Load()
	if p == nil || !p.Enabled {
		return nil
	}
	c.scopeMu.Lock()
	defer c.scopeMu.Unlock()
	if c.closed.Load() || len(c.scopes) >= maximumScopes || c.preference.Load() != p {
		return nil
	}
	s := &Scope{collector: c, kind: kind, epoch: p.Epoch, started: time.Now()}
	c.scopes[s] = struct{}{}
	return s
}

func (s *Scope) usable() bool {
	if s == nil || s.collector.closed.Load() || s.closed {
		return false
	}
	return s.authorized()
}

// retirement stops new measurements, not the final capture of an authorized
// window. the outbox also rechecks this epoch before persisting a report.
func (s *Scope) authorized() bool {
	p := s.collector.preference.Load()
	return p != nil && p.Enabled && p.Epoch == s.epoch
}

func (s *Scope) pathIndex(path Path) int {
	switch s.kind {
	case Public:
		switch path {
		case PublicUDP:
			return 0
		case PublicTCP:
			return 1
		}
	case Native:
		switch path {
		case NativeDirect:
			return 0
		case NativeRelayUDP:
			return 1
		case NativeRelayTCP:
			return 2
		}
	}
	return -1
}

// Observe records measurements from a real carrier. rtt <= 0 means the
// endpoint did not measure an RTT; it is omitted instead of reported as zero.
func (s *Scope) Observe(path Path, sent, received uint64, active, rtt time.Duration) {
	if s == nil {
		return
	}
	c := s.collector
	c.scopeMu.Lock()
	defer c.scopeMu.Unlock()
	if !s.usable() || active < 0 {
		return
	}
	index := s.pathIndex(path)
	if index < 0 {
		return
	}
	p := &s.paths[index]
	p.measured = true
	p.sent = saturateBytes(p.sent, sent)
	p.received = saturateBytes(p.received, received)
	if active > 0 && p.duration < 6*time.Hour {
		p.duration = min(6*time.Hour, p.duration+active)
	}
	if rtt > 0 {
		p.rttMeasured = true
		increment(&p.rtt[histogramBucket(rtt)])
	}
}

func (s *Scope) Fallback(reason api.FallbackCountReason) {
	if s == nil {
		return
	}
	index := -1
	switch reason {
	case api.UdpBlocked:
		index = 0
	case api.PathUnavailable:
		index = 1
	case api.NetworkChanged:
		index = 2
	case api.Backpressure:
		index = 3
	case api.DirectUnavailable:
		index = 4
	}
	if index < 0 {
		return
	}
	s.collector.scopeMu.Lock()
	defer s.collector.scopeMu.Unlock()
	if s.usable() {
		increment(&s.fallback[index])
	}
}

func (s *Scope) DirectAttempt(succeeded bool, establishment time.Duration) {
	if s == nil {
		return
	}
	s.collector.scopeMu.Lock()
	defer s.collector.scopeMu.Unlock()
	if !s.usable() || s.kind != Native {
		return
	}
	increment(&s.attempts)
	if succeeded {
		increment(&s.successes)
		if establishment > 0 {
			s.didDirect = true
			increment(&s.direct[histogramBucket(establishment)])
		}
	}
}

// Close retires this scope after the collector has captured its final report.
func (s *Scope) Close() {
	if s == nil {
		return
	}
	s.collector.scopeMu.Lock()
	s.closed = true
	s.collector.scopeMu.Unlock()
	s.collector.Flush()
}

func (c *Collector) resetScopes(preference clientstate.TelemetryPreference) {
	c.scopeMu.Lock()
	defer c.scopeMu.Unlock()
	for s := range c.scopes {
		s.paths = [3]pathCount{}
		s.fallback = [5]int64{}
		s.attempts, s.successes = 0, 0
		s.direct = [12]int64{}
		s.didDirect = false
		s.started = time.Now()
		s.epoch = preference.Epoch
		if s.closed {
			delete(c.scopes, s)
		}
	}
}

func (c *Collector) captureScopes(final bool) {
	c.scopeMu.Lock()
	now := time.Now()
	var reports []queuedObservation
	for s := range c.scopes {
		if !s.authorized() {
			if final || s.closed {
				delete(c.scopes, s)
			}
			continue
		}
		if !final && !s.closed && now.Sub(s.started) < time.Minute {
			continue
		}
		if event := s.snapshot(now); event != nil {
			reports = append(reports, queuedObservation{epoch: s.epoch, make: event})
		}
		s.paths = [3]pathCount{}
		s.fallback = [5]int64{}
		s.attempts, s.successes = 0, 0
		s.direct = [12]int64{}
		s.didDirect = false
		s.started = now
		if final || s.closed {
			delete(c.scopes, s)
		}
	}
	c.scopeMu.Unlock()
	for _, report := range reports {
		c.store(report)
	}
}

func (s *Scope) snapshot(now time.Time) func(string) (api.Event, error) {
	var fallbacks []api.FallbackCount
	reasons := [...]api.FallbackCountReason{api.UdpBlocked, api.PathUnavailable, api.NetworkChanged, api.Backpressure, api.DirectUnavailable}
	for i, n := range s.fallback {
		if n > 0 {
			fallbacks = append(fallbacks, api.FallbackCount{Reason: reasons[i], Count: n})
		}
	}
	duration := durationBucket(now.Sub(s.started))
	if s.kind == Public {
		paths := make([]api.PublicPathAggregate, 0, 2)
		for i, path := range [...]api.PublicPathAggregatePath{api.PublicUdp, api.PublicTcp} {
			if p := s.paths[i]; p.measured {
				paths = append(paths, api.PublicPathAggregate{Path: path, ActiveDuration: durationBucket(p.duration), Sent: volumeBucket(p.sent), Received: volumeBucket(p.received), Rtt: rttHistogram(p)})
			}
		}
		if len(paths) == 0 {
			return nil
		}
		report := api.PublicReport{Kind: api.PublicIngress, ActiveDuration: duration, Paths: paths}
		if len(fallbacks) != 0 {
			report.Fallbacks = &fallbacks
		}
		return func(id string) (api.Event, error) {
			var payload api.PublisherReport
			if err := payload.FromPublicReport(report); err != nil {
				return api.Event{}, err
			}
			var event api.Event
			err := event.FromPublisherEvent(api.PublisherEvent{EventId: id, EventVersion: api.V1, Name: api.PublisherEventNamePublisherReport, Payload: payload})
			return event, err
		}
	}
	paths := make([]api.NativePathAggregate, 0, 3)
	for i, path := range [...]api.NativePathAggregatePath{api.NativeDirect, api.NativeRelayUdp, api.NativeRelayTcp} {
		if p := s.paths[i]; p.measured {
			paths = append(paths, api.NativePathAggregate{Path: path, ActiveDuration: durationBucket(p.duration), Sent: volumeBucket(p.sent), Received: volumeBucket(p.received), Rtt: rttHistogram(p)})
		}
	}
	if len(paths) == 0 {
		return nil
	}
	report := api.NativeReport{Kind: api.NativePeer, ActiveDuration: duration, Paths: paths}
	if len(fallbacks) != 0 {
		report.Fallbacks = &fallbacks
	}
	if s.attempts > 0 {
		attempts, successes := s.attempts, s.successes
		report.DirectSetupAttempts, report.DirectSetupSuccesses = &attempts, &successes
	}
	if s.didDirect {
		histogram := make(api.Histogram, 12)
		copy(histogram, s.direct[:])
		report.DirectEstablishment = &histogram
	}
	return func(id string) (api.Event, error) {
		var payload api.PublisherReport
		if err := payload.FromNativeReport(report); err != nil {
			return api.Event{}, err
		}
		var event api.Event
		err := event.FromPublisherEvent(api.PublisherEvent{EventId: id, EventVersion: api.V1, Name: api.PublisherEventNamePublisherReport, Payload: payload})
		return event, err
	}
}

func increment(n *int64) {
	if *n < 1_000_000_000 {
		*n++
	}
}

func saturateBytes(a, b uint64) uint64 {
	if ^uint64(0)-a < b {
		return ^uint64(0)
	}
	return a + b
}

func volumeBucket(n uint64) *api.VolumeBucket {
	bucket := api.VolumeBucketLarger
	switch {
	case n == 0:
		bucket = api.VolumeBucketZero
	case n < 64<<10:
		bucket = api.VolumeBucketLt64kib
	case n < 1<<20:
		bucket = api.VolumeBucketLt1mib
	case n < 16<<20:
		bucket = api.VolumeBucketLt16mib
	case n < 256<<20:
		bucket = api.VolumeBucketLt256mib
	case n < 4<<30:
		bucket = api.VolumeBucketLt4gib
	case n < 64<<30:
		bucket = api.VolumeBucketLt64gib
	}
	return &bucket
}

func durationBucket(d time.Duration) api.DurationBucket {
	switch {
	case d < time.Second:
		return api.DurationBucketLt1s
	case d < 10*time.Second:
		return api.DurationBucketLt10s
	case d < time.Minute:
		return api.DurationBucketLt1m
	case d < 10*time.Minute:
		return api.DurationBucketLt10m
	case d < time.Hour:
		return api.DurationBucketLt1h
	case d < 6*time.Hour:
		return api.DurationBucketLt6h
	default:
		return api.DurationBucketLarger
	}
}

func histogramBucket(d time.Duration) int {
	for i, ms := range api.HistogramUpperBoundsMilliseconds() {
		if d <= time.Duration(ms)*time.Millisecond {
			return i
		}
	}
	return 11
}

func rttHistogram(p pathCount) *api.Histogram {
	if !p.rttMeasured {
		return nil
	}
	histogram := make(api.Histogram, 12)
	copy(histogram, p.rtt[:])
	return &histogram
}
