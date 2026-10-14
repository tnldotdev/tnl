package ingress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/trafficlimits"
)

// TrafficLimits bounds one public URL on one ingress process. bandwidth
// directions are relative to the visitor, and count encrypted connection bytes.
type TrafficLimits = trafficlimits.Limits

type TrafficConfig struct {
	Default                        TrafficLimits
	Ceiling                        TrafficLimits
	SourceRate, SourceBurst        int
	ProcessRate, ProcessBurst      int
	ProcessUpload, ProcessDownload int64
}

func (c *TrafficConfig) resolve() error {
	if c.Default == (TrafficLimits{}) {
		c.Default = trafficlimits.Default()
	}
	if c.Ceiling == (TrafficLimits{}) {
		c.Ceiling = trafficlimits.Ceiling()
	}
	if c.SourceRate == 0 {
		c.SourceRate = 30
	}
	if c.SourceBurst == 0 {
		c.SourceBurst = 60
	}
	if c.ProcessRate == 0 {
		c.ProcessRate = 200
	}
	if c.ProcessBurst == 0 {
		c.ProcessBurst = 400
	}
	if c.ProcessUpload == 0 {
		c.ProcessUpload = 256 << 20
	}
	if c.ProcessDownload == 0 {
		c.ProcessDownload = 256 << 20
	}
	if c.Ceiling.Connections < c.Default.Connections || c.Ceiling.Rate < c.Default.Rate || c.Ceiling.Burst < c.Default.Burst ||
		c.Ceiling.UploadBytes < c.Default.UploadBytes || c.Ceiling.DownloadBytes < c.Default.DownloadBytes {
		return errors.New("ingress: traffic defaults exceed operator ceilings")
	}
	return nil
}

const (
	defaultTrafficConnections       = 32
	defaultTrafficRate              = 20
	defaultTrafficBurst             = 40
	defaultUploadBytes        int64 = 8 << 20
	defaultDownloadBytes      int64 = 16 << 20
	maxTrafficWait                  = 2 * time.Second
	trafficIdleRetention            = 2 * time.Minute
	maxTrafficKeys                  = 100_000
)

func defaultTrafficLimits() TrafficLimits {
	return TrafficLimits{Connections: defaultTrafficConnections, Rate: defaultTrafficRate,
		Burst: defaultTrafficBurst, UploadBytes: defaultUploadBytes, DownloadBytes: defaultDownloadBytes}
}

type trafficKey struct {
	url string
	run uint64
}

type trafficBucket struct {
	tokens float64
	last   time.Time
	seen   time.Time
}

var errProcessBandwidth = errors.New("ingress: process bandwidth limit reached")
var errPublicURLBandwidth = errors.New("ingress: public URL bandwidth limit reached")

// trafficAdmission is process-local. no token or source identity is stored in
// the routing table or exported as a metrics label.
type trafficAdmission struct {
	mu                             sync.Mutex
	limits                         TrafficLimits
	sourceRate, sourceBurst        int
	processRate, processBurst      int
	processUpload, processDownload int64
	sources                        map[netip.Prefix]*trafficBucket
	connections                    map[trafficKey]*trafficBucket
	upload                         map[trafficKey]*trafficBucket
	download                       map[trafficKey]*trafficBucket
	processConnections             trafficBucket
	processUploads                 trafficBucket
	processDownloads               trafficBucket
	lastPrune                      time.Time
}

func newTrafficAdmission(limits TrafficLimits, sourceRate, sourceBurst, processRate, processBurst int,
	processUpload, processDownload int64) (*trafficAdmission, error) {
	if limits.Connections < 1 || limits.Rate < 1 || limits.Burst < 1 ||
		limits.UploadBytes < 64<<10 || limits.DownloadBytes < 64<<10 ||
		sourceRate < 1 || sourceBurst < 1 || processRate < 1 || processBurst < 1 ||
		processUpload < 64<<10 || processDownload < 64<<10 {
		return nil, errors.New("ingress: traffic capacities and rates must be positive")
	}
	return &trafficAdmission{limits: limits, sourceRate: sourceRate, sourceBurst: sourceBurst,
		processRate: processRate, processBurst: processBurst, processUpload: processUpload, processDownload: processDownload,
		sources: make(map[netip.Prefix]*trafficBucket), connections: make(map[trafficKey]*trafficBucket),
		upload: make(map[trafficKey]*trafficBucket), download: make(map[trafficKey]*trafficBucket)}, nil
}

func (a *trafficAdmission) allowSource(source netip.Addr) (bool, string) {
	if !source.IsValid() || source.Zone() != "" {
		return false, "source_connection_rate"
	}
	source = source.Unmap()
	bits := source.BitLen()
	if source.Is6() {
		bits = 64
	}
	key := netip.PrefixFrom(source, bits).Masked()
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	a.prune(now)
	if !a.consume(&a.processConnections, float64(a.processRate), float64(a.processBurst), 1, now) {
		return false, "process_connection_rate"
	}
	bucket, found := a.sources[key]
	if !found {
		if len(a.sources) >= maxTrafficKeys {
			return false, "source_connection_rate"
		}
		bucket = &trafficBucket{}
		a.sources[key] = bucket
	}
	if !a.consume(bucket, float64(a.sourceRate), float64(a.sourceBurst), 1, now) {
		return false, "source_connection_rate"
	}
	return true, ""
}

func (a *trafficAdmission) allowConnection(key trafficKey, chosen ...TrafficLimits) bool {
	limits := a.limits
	if len(chosen) > 0 {
		limits = chosen[0]
	}
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	a.prune(now)
	bucket, found := a.connections[key]
	if !found {
		if len(a.connections) >= maxTrafficKeys {
			return false
		}
		bucket = &trafficBucket{}
		a.connections[key] = bucket
	}
	period := limits.RatePer
	if period == 0 {
		period = time.Second
	}
	return a.consume(bucket, float64(limits.Rate)/period.Seconds(), float64(limits.Burst), 1, now)
}

func (a *trafficAdmission) consume(bucket *trafficBucket, rate, capacity, cost float64, now time.Time) bool {
	if bucket.last.IsZero() {
		bucket.tokens = capacity
	} else if now.After(bucket.last) {
		bucket.tokens = min(capacity, bucket.tokens+now.Sub(bucket.last).Seconds()*rate)
	}
	bucket.last, bucket.seen = now, now
	if bucket.tokens < cost {
		return false
	}
	bucket.tokens -= cost
	return true
}

// the key count is bounded even when attackers rotate source addresses or
// publish runs. prune idle buckets without changing an active run's budget.
func (a *trafficAdmission) prune(now time.Time) {
	if now.Sub(a.lastPrune) < 30*time.Second {
		return
	}
	a.lastPrune = now
	for key, bucket := range a.sources {
		if now.Sub(bucket.seen) > trafficIdleRetention {
			delete(a.sources, key)
		}
	}
	for key, bucket := range a.connections {
		if now.Sub(bucket.seen) > trafficIdleRetention {
			delete(a.connections, key)
		}
	}
	for key, bucket := range a.upload {
		if now.Sub(bucket.seen) > trafficIdleRetention {
			delete(a.upload, key)
		}
	}
	for key, bucket := range a.download {
		if now.Sub(bucket.seen) > trafficIdleRetention {
			delete(a.download, key)
		}
	}
}

func (a *trafficAdmission) waitBytes(ctx context.Context, key trafficKey, upload bool, size int, chosen ...TrafficLimits) error {
	if size == 0 {
		return nil
	}
	limits := a.limits
	if len(chosen) > 0 {
		limits = chosen[0]
	}
	deadline := time.Now().Add(maxTrafficWait)
	for {
		now := time.Now()
		a.mu.Lock()
		perURL := a.download
		rate := limits.DownloadBytes
		process := &a.processDownloads
		processRate := a.processDownload
		if upload {
			perURL, rate, process, processRate = a.upload, limits.UploadBytes, &a.processUploads, a.processUpload
		}
		bucket, found := perURL[key]
		if !found {
			if len(perURL) >= maxTrafficKeys {
				a.mu.Unlock()
				return errPublicURLBandwidth
			}
			bucket = &trafficBucket{}
			perURL[key] = bucket
		}
		// check both buckets before consuming either one.
		urlTokens := a.available(bucket, float64(rate), float64(rate), now)
		processTokens := a.available(process, float64(processRate), float64(processRate), now)
		if urlTokens >= float64(size) && processTokens >= float64(size) {
			bucket.tokens -= float64(size)
			process.tokens -= float64(size)
			a.mu.Unlock()
			return nil
		}
		urlWait := time.Duration((float64(size) - urlTokens) / float64(rate) * float64(time.Second))
		processWait := time.Duration((float64(size) - processTokens) / float64(processRate) * float64(time.Second))
		wait := max(urlWait, processWait)
		a.mu.Unlock()
		if wait <= 0 {
			wait = time.Millisecond
		}
		if now.Add(wait).After(deadline) {
			if processWait >= urlWait {
				return errProcessBandwidth
			}
			return errPublicURLBandwidth
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (a *trafficAdmission) available(bucket *trafficBucket, rate, capacity float64, now time.Time) float64 {
	if bucket.last.IsZero() {
		bucket.tokens = capacity
	} else if now.After(bucket.last) {
		bucket.tokens = min(capacity, bucket.tokens+now.Sub(bucket.last).Seconds()*rate)
	}
	bucket.last, bucket.seen = now, now
	return bucket.tokens
}

// budgetConn retains the forwarding stream's half-close behavior. a rejected
// write causes streamcopy to close both directions without replay.
type budgetConn struct {
	net.Conn
	ctx         context.Context
	beforeWrite func(context.Context, int) error
}

func (c *budgetConn) Write(data []byte) (int, error) {
	if err := c.beforeWrite(c.ctx, len(data)); err != nil {
		return 0, err
	}
	return c.Conn.Write(data)
}

func (c *budgetConn) CloseWrite() error {
	if closer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return errors.ErrUnsupported
}
