package ingress

import (
	"context"
	"errors"
	"math"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/routeusage"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
)

const (
	defaultUsageReportInterval = 10 * time.Second
	// Each server transaction retains an ingress lease and all reported session
	// locks. Bound that footprint without changing atomic replay semantics.
	usageReportPageSize = 16
)

type usageControl interface {
	ReportUsage(context.Context, usageReportBatch) error
	VisitorNetworkHashKey(time.Time) ([32]byte, bool)
}

type usageReportBatch struct {
	reports         []ingressv1.IngressUsageReport
	observedThrough *time.Time
	complete        bool
}

type usageBucketKey struct {
	routeID      string
	routeVersion uint64
	start        time.Time
}

type usageCounters struct {
	connectionAttempts        uint64
	policyDenials             uint64
	capacityDenials           uint64
	visitorStreamOpenFailures uint64
	successfulStreams         uint64
	connectionNanoseconds     uint64
	ingressBytes              uint64
	egressBytes               uint64
}

type usageBucket struct {
	key                          usageBucketKey
	counters                     usageCounters
	revision                     uint64
	mutation                     uint64
	pendingMutation              uint64
	pending                      *ingressv1.IngressUsageReport
	dirty                        bool
	final                        bool
	finalReported                bool
	visitorStreamOpenLatency     routeusage.DurationHistogram
	timeToFirstPublisherByte     routeusage.DurationHistogram
	successfulConnectionDuration routeusage.DurationHistogram
	visitors                     *routeusage.VisitorSketch
}

type usageVisitorKey struct {
	routeID string
	start   time.Time
}

// UsageReporter aggregates cumulative minute buckets for one ingress process.
type UsageReporter struct {
	control  usageControl
	interval time.Duration
	report   func(error)

	flushMu         sync.Mutex
	mu              sync.Mutex
	buckets         map[usageBucketKey]*usageBucket
	visitors        map[usageVisitorKey]*routeusage.VisitorSketch
	active          map[*usageConnection]struct{}
	observedThrough time.Time
	latestAt        time.Time
	pendingPages    []usageReportBatch
	err             error
	closed          bool
}

// NewUsageReporter constructs an in-memory ingress usage reporter.
func NewUsageReporter(control usageControl, interval time.Duration, report func(error)) (*UsageReporter, error) {
	if control == nil {
		return nil, errors.New("ingress: usage control is required")
	}
	if interval < 0 {
		return nil, errors.New("ingress: usage interval cannot be negative")
	}
	if interval == 0 {
		interval = defaultUsageReportInterval
	}
	if report == nil {
		report = func(error) {}
	}
	return &UsageReporter{
		control: control, interval: interval, report: report,
		buckets: make(map[usageBucketKey]*usageBucket), visitors: make(map[usageVisitorKey]*routeusage.VisitorSketch),
		active: make(map[*usageConnection]struct{}),
	}, nil
}

// Open starts cumulative accounting for one visitor connection.
func (r *UsageReporter) Open(routeID string, routeVersion uint64, source netip.Addr, at time.Time) UsageConnection {
	r.mu.Lock()
	at = r.normalizeAt(at)
	visitorNetworkHashKey, hasVisitorNetworkHashKey := r.control.VisitorNetworkHashKey(at)
	connection := &usageConnection{reporter: r, routeID: routeID, routeVersion: routeVersion, attemptedAt: at}
	if !r.closed {
		r.active[connection] = struct{}{}
		r.increment(connection.bucket(at), func(counters *usageCounters) *uint64 { return &counters.connectionAttempts }, 1)
		if hasVisitorNetworkHashKey {
			r.observeVisitor(routeID, source, at, visitorNetworkHashKey)
		}
	} else {
		connection.closed = true
	}
	r.mu.Unlock()
	return connection
}

// Run reports dirty usage buckets until the process context is canceled.
func (r *UsageReporter) Run(ctx context.Context) error {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := r.flush(ctx, time.Now().UTC(), false); err != nil && ctx.Err() == nil {
				r.report(err)
			}
		}
	}
}

// Close advances active accounting through now and acknowledges final reports.
// The caller must first stop and drain public ingress connections.
func (r *UsageReporter) Close(ctx context.Context) error {
	if err := r.flush(ctx, time.Now().UTC(), true); err != nil {
		return err
	}
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
	return nil
}

func (r *UsageReporter) flush(ctx context.Context, now time.Time, final bool) error {
	r.flushMu.Lock()
	defer r.flushMu.Unlock()
	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	if closed {
		return nil
	}
	now = now.UTC()
	for {
		r.mu.Lock()
		pending := len(r.pendingPages) != 0
		r.mu.Unlock()
		if !pending {
			if err := r.prepare(now, final); err != nil {
				return err
			}
		}
		r.mu.Lock()
		batch := r.pendingPages[0]
		r.mu.Unlock()
		if err := r.control.ReportUsage(ctx, batch); err != nil {
			// Idle watermarks contain no accounting state. Regenerate a rejected
			// watermark so startup does not remain pinned before lease registration.
			if len(batch.reports) == 0 && !batch.complete {
				r.mu.Lock()
				r.pendingPages = nil
				r.mu.Unlock()
			}
			return err
		}
		r.acknowledge(batch.reports)
		r.mu.Lock()
		r.pendingPages[0] = usageReportBatch{}
		r.pendingPages = r.pendingPages[1:]
		more := len(r.pendingPages) != 0
		r.mu.Unlock()
		if !more && (!final || batch.complete) {
			return nil
		}
	}
}

// prepare freezes one finite checkpoint under the mutation lock. Acknowledged
// pages never reselect live dirty buckets; mutations belong to the next checkpoint.
func (r *UsageReporter) prepare(now time.Time, final bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if now.Before(r.latestAt) {
		now = r.latestAt
	}
	now = r.normalizeAt(now)
	for connection := range r.active {
		r.advance(connection, now)
	}
	if now.After(r.observedThrough) {
		r.observedThrough = now
	}
	if r.err != nil {
		return r.err
	}
	keys := make([]usageBucketKey, 0, len(r.buckets))
	for key, bucket := range r.buckets {
		if final || !now.Before(key.start.Add(time.Minute)) {
			bucket.final = true
		}
		if bucket.pending != nil || bucket.dirty || bucket.final && !bucket.finalReported {
			keys = append(keys, key)
		}
	}
	slices.SortFunc(keys, compareUsageBucketKeys)
	reports := make([]ingressv1.IngressUsageReport, 0, len(keys))
	for _, key := range keys {
		bucket := r.buckets[key]
		if bucket.pending == nil {
			bucket.revision++
			bucketEnd := key.start.Add(time.Minute)
			observedThrough := now
			if observedThrough.After(bucketEnd) {
				observedThrough = bucketEnd
			}
			checkpoint := routeusage.Checkpoint{
				VisitorStreamOpenLatency:     bucket.visitorStreamOpenLatency,
				TimeToFirstPublisherByte:     bucket.timeToFirstPublisherByte,
				SuccessfulConnectionDuration: bucket.successfulConnectionDuration,
				VisitorNetworks:              *bucket.visitors,
			}
			report := ingressv1.IngressUsageReport{
				RouteId: key.routeID, RouteVersion: int64(key.routeVersion),
				BucketStart: key.start, BucketEnd: bucketEnd, ObservedThrough: observedThrough,
				ReportRevision:     int64(bucket.revision),
				ConnectionAttempts: int64(bucket.counters.connectionAttempts), PolicyDenials: int64(bucket.counters.policyDenials),
				CapacityDenials: int64(bucket.counters.capacityDenials), VisitorStreamOpenFailures: int64(bucket.counters.visitorStreamOpenFailures),
				SuccessfulStreams: int64(bucket.counters.successfulStreams), ConnectionNanoseconds: int64(bucket.counters.connectionNanoseconds),
				IngressBytes: int64(bucket.counters.ingressBytes), EgressBytes: int64(bucket.counters.egressBytes),
				HistogramData: checkpoint.MarshalBinary(), Final: bucket.final,
			}
			bucket.pending = &report
			bucket.pendingMutation = bucket.mutation
		}
		reports = append(reports, *bucket.pending)
	}
	for len(reports) > usageReportPageSize {
		r.pendingPages = append(r.pendingPages, usageReportBatch{reports: reports[:usageReportPageSize]})
		reports = reports[usageReportPageSize:]
	}
	r.pendingPages = append(r.pendingPages, usageReportBatch{reports: reports, observedThrough: &now, complete: final})
	return nil
}

func (r *UsageReporter) acknowledge(reports []ingressv1.IngressUsageReport) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, report := range reports {
		key := usageBucketKey{routeID: report.RouteId, routeVersion: uint64(report.RouteVersion), start: report.BucketStart}
		bucket := r.buckets[key]
		if bucket == nil || bucket.pending == nil || bucket.pending.ReportRevision != report.ReportRevision {
			continue
		}
		unchanged := bucket.mutation == bucket.pendingMutation
		bucket.pending = nil
		bucket.dirty = !unchanged
		bucket.finalReported = report.Final
		if report.Final && unchanged {
			delete(r.buckets, key)
		}
	}
	r.cleanupVisitors()
}

func (r *UsageReporter) bucket(routeID string, routeVersion uint64, at time.Time) *usageBucket {
	key := usageBucketKey{routeID: routeID, routeVersion: routeVersion, start: at.UTC().Truncate(time.Minute)}
	bucket := r.buckets[key]
	if bucket == nil {
		visitorKey := usageVisitorKey{routeID: routeID, start: key.start}
		visitors := r.visitors[visitorKey]
		if visitors == nil {
			visitors = new(routeusage.VisitorSketch)
			r.visitors[visitorKey] = visitors
		}
		bucket = &usageBucket{key: key, visitors: visitors}
		r.buckets[key] = bucket
	}
	return bucket
}

func (r *UsageReporter) observeVisitor(routeID string, source netip.Addr, at time.Time, key [32]byte) {
	start := at.UTC().Truncate(time.Minute)
	visitors := r.visitors[usageVisitorKey{routeID: routeID, start: start}]
	if visitors == nil || !visitors.Observe(key, routeID, source) {
		return
	}
	for bucketKey, bucket := range r.buckets {
		if bucketKey.routeID == routeID && bucketKey.start.Equal(start) {
			bucket.mutation++
			bucket.dirty = true
		}
	}
}

func (r *UsageReporter) cleanupVisitors() {
	used := make(map[usageVisitorKey]struct{}, len(r.visitors))
	for bucketKey := range r.buckets {
		used[usageVisitorKey{routeID: bucketKey.routeID, start: bucketKey.start}] = struct{}{}
	}
	for visitorKey := range r.visitors {
		if _, exists := used[visitorKey]; !exists {
			delete(r.visitors, visitorKey)
		}
	}
}

func (r *UsageReporter) increment(bucket *usageBucket, counter func(*usageCounters) *uint64, value uint64) {
	current := counter(&bucket.counters)
	if value > math.MaxInt64 || *current > math.MaxInt64-value {
		r.err = errors.New("ingress: usage counter exceeds signed 64-bit range")
		return
	}
	*current += value
	bucket.mutation++
	bucket.dirty = true
}

func (r *UsageReporter) advance(connection *usageConnection, at time.Time) {
	at = r.normalizeAt(at)
	if !connection.streamOpened || !at.After(connection.lastAt) {
		return
	}
	cursor := connection.lastAt
	for cursor.Before(at) {
		end := cursor.Truncate(time.Minute).Add(time.Minute)
		if end.After(at) {
			end = at
		}
		r.increment(connection.bucket(cursor), func(counters *usageCounters) *uint64 {
			return &counters.connectionNanoseconds
		}, uint64(end.Sub(cursor)))
		cursor = end
	}
	connection.lastAt = at
}

func (r *UsageReporter) normalizeAt(at time.Time) time.Time {
	at = at.UTC()
	if at.Before(r.observedThrough) {
		at = r.observedThrough
	}
	if at.After(r.latestAt) {
		r.latestAt = at
	}
	return at
}

func compareUsageBucketKeys(left, right usageBucketKey) int {
	if left.routeID < right.routeID {
		return -1
	}
	if left.routeID > right.routeID {
		return 1
	}
	if left.routeVersion < right.routeVersion {
		return -1
	}
	if left.routeVersion > right.routeVersion {
		return 1
	}
	return left.start.Compare(right.start)
}

type usageConnection struct {
	reporter           *UsageReporter
	routeID            string
	routeVersion       uint64
	attemptedAt        time.Time
	lastAt             time.Time
	streamOpened       bool
	publisherOpeningAt time.Time
	streamOpenedAt     time.Time
	publisherObserved  bool
	firstPublisherByte bool
	outcome            bool
	closed             bool
}

func (c *usageConnection) bucket(at time.Time) *usageBucket {
	return c.reporter.bucket(c.routeID, c.routeVersion, at)
}

func (c *usageConnection) PolicyDenied(at time.Time) {
	c.deny(at, func(counters *usageCounters) *uint64 { return &counters.policyDenials })
}

func (c *usageConnection) CapacityDenied(at time.Time) {
	c.deny(at, func(counters *usageCounters) *uint64 { return &counters.capacityDenials })
}

func (c *usageConnection) VisitorStreamOpening(at time.Time) {
	r := c.reporter
	r.mu.Lock()
	defer r.mu.Unlock()
	if c.closed || c.outcome || !c.publisherOpeningAt.IsZero() {
		return
	}
	c.publisherOpeningAt = r.normalizeAt(at)
}

func (c *usageConnection) VisitorStreamOpened(at time.Time) { c.observeVisitorStreamOpen(at) }

func (c *usageConnection) VisitorStreamOpenFailed(at time.Time) {
	c.observeVisitorStreamOpen(at)
	c.deny(at, func(counters *usageCounters) *uint64 { return &counters.visitorStreamOpenFailures })
}

func (c *usageConnection) StreamOpened(at time.Time) {
	r := c.reporter
	r.mu.Lock()
	defer r.mu.Unlock()
	if c.closed || c.outcome || c.streamOpened {
		return
	}
	at = r.normalizeAt(at)
	c.streamOpened = true
	c.outcome = true
	c.streamOpenedAt = at
	c.lastAt = at
	r.increment(c.bucket(at), func(counters *usageCounters) *uint64 { return &counters.successfulStreams }, 1)
}

func (c *usageConnection) AddIngress(bytes int64, at time.Time) {
	c.addBytes(bytes, 0, at)
}

func (c *usageConnection) AddEgress(bytes int64, at time.Time) {
	c.addBytes(0, bytes, at)
}

func (c *usageConnection) addBytes(ingressBytes, egressBytes int64, at time.Time) {
	if ingressBytes <= 0 && egressBytes <= 0 {
		return
	}
	r := c.reporter
	r.mu.Lock()
	defer r.mu.Unlock()
	if c.closed || !c.streamOpened {
		return
	}
	at = r.normalizeAt(at)
	r.advance(c, at)
	bucket := c.bucket(at)
	if ingressBytes > 0 {
		r.increment(bucket, func(counters *usageCounters) *uint64 { return &counters.ingressBytes }, uint64(ingressBytes))
	}
	if egressBytes > 0 {
		r.increment(bucket, func(counters *usageCounters) *uint64 { return &counters.egressBytes }, uint64(egressBytes))
		if !c.firstPublisherByte {
			r.observeDuration(
				bucket, &bucket.timeToFirstPublisherByte, at.Sub(c.attemptedAt),
			)
			c.firstPublisherByte = true
		}
	}
}

func (c *usageConnection) Close(at time.Time) {
	r := c.reporter
	r.mu.Lock()
	defer r.mu.Unlock()
	if c.closed {
		return
	}
	at = r.normalizeAt(at)
	r.advance(c, at)
	if c.streamOpened {
		bucket := c.bucket(at)
		r.observeDuration(bucket, &bucket.successfulConnectionDuration, at.Sub(c.streamOpenedAt))
	}
	c.closed = true
	delete(r.active, c)
}

func (c *usageConnection) observeVisitorStreamOpen(at time.Time) {
	r := c.reporter
	r.mu.Lock()
	defer r.mu.Unlock()
	if c.closed || c.outcome || c.publisherObserved {
		return
	}
	at = r.normalizeAt(at)
	startedAt := c.publisherOpeningAt
	if startedAt.IsZero() {
		startedAt = c.attemptedAt
	}
	bucket := c.bucket(at)
	r.observeDuration(bucket, &bucket.visitorStreamOpenLatency, at.Sub(startedAt))
	c.publisherObserved = true
}

func (r *UsageReporter) observeDuration(
	bucket *usageBucket,
	histogram *routeusage.DurationHistogram,
	duration time.Duration,
) {
	if err := histogram.Observe(duration); err != nil {
		r.err = err
		return
	}
	bucket.mutation++
	bucket.dirty = true
}

func (c *usageConnection) deny(at time.Time, counter func(*usageCounters) *uint64) {
	r := c.reporter
	r.mu.Lock()
	defer r.mu.Unlock()
	if c.closed || c.outcome || c.streamOpened {
		return
	}
	at = r.normalizeAt(at)
	c.outcome = true
	r.increment(c.bucket(at), counter, 1)
}
