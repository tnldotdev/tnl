package benchworkload

import (
	"errors"
	"math"
	"slices"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/tnldotdev/tnl/internal/observability"
	"google.golang.org/protobuf/proto"
)

// Histogram counts are cumulative and use the production duration buckets.
type Histogram struct {
	BoundsMilliseconds  []float64 `json:"bounds_milliseconds"`
	Counts              []uint64  `json:"counts"`
	Count               uint64    `json:"count"`
	SumMilliseconds     float64   `json:"sum_milliseconds"`
	MinimumMilliseconds float64   `json:"minimum_milliseconds"`
	MaximumMilliseconds float64   `json:"maximum_milliseconds"`
}

func (h *Histogram) Percentile(percentile int) *float64 {
	if h == nil || h.Count == 0 || len(h.BoundsMilliseconds) != len(h.Counts) {
		return nil
	}
	value := &dto.Histogram{SampleCount: proto.Uint64(h.Count), SampleSum: proto.Float64(h.SumMilliseconds / 1000)}
	for i, bound := range h.BoundsMilliseconds {
		value.Bucket = append(value.Bucket, &dto.Bucket{UpperBound: proto.Float64(bound / 1000), CumulativeCount: proto.Uint64(h.Counts[i])})
	}
	summaries, err := observability.DurationSummaries(nil, []*dto.MetricFamily{{Name: proto.String("tnl_benchmark_duration_seconds"), Type: dto.MetricType_HISTOGRAM.Enum(), Metric: []*dto.Metric{{Histogram: value}}}})
	if err != nil || len(summaries) != 1 {
		return nil
	}
	seconds := map[int]*float64{50: summaries[0].P50Seconds, 95: summaries[0].P95Seconds, 99: summaries[0].P99Seconds}[percentile]
	if seconds == nil {
		return nil
	}
	ms := *seconds * 1000
	return &ms
}

func (h *Histogram) Observe(duration time.Duration) {
	value := float64(duration) / float64(time.Millisecond)
	if h.Count == 0 {
		for _, bound := range observability.DurationBucketsSeconds() {
			h.BoundsMilliseconds = append(h.BoundsMilliseconds, bound*1000)
		}
		h.Counts = make([]uint64, len(h.BoundsMilliseconds))
		h.MinimumMilliseconds = value
	}
	h.Count++
	h.SumMilliseconds += value
	h.MinimumMilliseconds = min(h.MinimumMilliseconds, value)
	h.MaximumMilliseconds = max(h.MaximumMilliseconds, value)
	for i, bound := range h.BoundsMilliseconds {
		if value <= bound {
			h.Counts[i]++
		}
	}
}

func NewHistogram(samples []time.Duration) *Histogram {
	if len(samples) == 0 {
		return nil
	}
	h := new(Histogram)
	for _, sample := range samples {
		h.Observe(sample)
	}
	return h
}

func (h *Histogram) Merge(other Histogram) error {
	if other.Count == 0 {
		return nil
	}
	if len(other.BoundsMilliseconds) != len(other.Counts) || len(other.Counts) == 0 {
		return errors.New("invalid histogram layout")
	}
	for _, value := range []float64{other.SumMilliseconds, other.MinimumMilliseconds, other.MaximumMilliseconds} {
		if value < 0 || math.IsNaN(value) || math.IsInf(value, 0) {
			return errors.New("invalid histogram duration")
		}
	}
	var previous uint64
	for i, count := range other.Counts {
		if count < previous || count > other.Count || math.IsNaN(other.BoundsMilliseconds[i]) || math.IsInf(other.BoundsMilliseconds[i], 0) || (i > 0 && other.BoundsMilliseconds[i] <= other.BoundsMilliseconds[i-1]) {
			return errors.New("invalid histogram bounds or counts")
		}
		previous = count
	}
	if h.Count == 0 {
		*h = other
		h.BoundsMilliseconds = slices.Clone(other.BoundsMilliseconds)
		h.Counts = slices.Clone(other.Counts)
		return nil
	}
	if !slices.Equal(h.BoundsMilliseconds, other.BoundsMilliseconds) {
		return errors.New("histogram layouts differ")
	}
	for i, count := range other.Counts {
		h.Counts[i] += count
	}
	h.Count += other.Count
	h.SumMilliseconds += other.SumMilliseconds
	h.MinimumMilliseconds = min(h.MinimumMilliseconds, other.MinimumMilliseconds)
	h.MaximumMilliseconds = max(h.MaximumMilliseconds, other.MaximumMilliseconds)
	return nil
}

type RequestResult struct {
	URL          string        `json:"url,omitempty"`
	Scheduled    time.Time     `json:"scheduled"`
	Started      time.Time     `json:"started"`
	FirstByte    time.Time     `json:"first_body_byte,omitzero"`
	QueueDelay   time.Duration `json:"queue_delay"`
	DNS          time.Duration `json:"dns"`
	Connect      time.Duration `json:"connect"`
	TLS          time.Duration `json:"tls"`
	Duration     time.Duration `json:"duration"`
	Bytes        int64         `json:"bytes"`
	Error        string        `json:"error,omitempty"`
	Timeout      bool          `json:"timeout,omitempty"`
	QueueExpired bool          `json:"queue_expired,omitempty"`
}

type VisitorResult struct {
	StartedAt      time.Time       `json:"started_at"`
	OfferDuration  time.Duration   `json:"offer_duration"`
	DrainDuration  time.Duration   `json:"drain_duration"`
	Workers        int             `json:"workers"`
	QueueSlots     int             `json:"queue_slots"`
	Rate           int             `json:"rate"`
	Scheduled      int             `json:"scheduled"`
	Started        int             `json:"started"`
	Completed      int             `json:"completed"`
	Successes      int             `json:"successes"`
	Failures       int             `json:"failures"`
	Timeouts       int             `json:"timeouts"`
	Missed         int             `json:"missed"`
	QueueExpired   int             `json:"queue_expired"`
	Bytes          int64           `json:"bytes"`
	QueueDelay     Histogram       `json:"queue_delay"`
	DNS            Histogram       `json:"dns"`
	Connect        Histogram       `json:"connect"`
	TLS            Histogram       `json:"tls"`
	FirstByte      Histogram       `json:"first_body_byte"`
	Total          Histogram       `json:"total"`
	FailuresSample []RequestResult `json:"failure_samples,omitempty"`
}

// Observe adds one completed or queue-expired request to a local summary.
func (r *VisitorResult) Observe(request RequestResult) {
	invalid := request.QueueDelay < 0 || request.Duration < 0 || request.DNS < 0 || request.Connect < 0 || request.TLS < 0 || !request.FirstByte.IsZero() && request.FirstByte.Before(request.Scheduled)
	if invalid {
		request.Error = "invalid negative request timing: " + request.Error
	}
	if request.QueueDelay >= 0 {
		r.QueueDelay.Observe(request.QueueDelay)
	}
	if request.QueueExpired {
		r.QueueExpired++
	} else {
		r.Started++
		r.Completed++
		if request.Error != "" {
			r.Failures++
			if request.Timeout {
				r.Timeouts++
			}
		} else {
			r.Successes++
			r.Bytes += request.Bytes
			if request.DNS > 0 {
				r.DNS.Observe(request.DNS)
			}
			if request.Connect > 0 {
				r.Connect.Observe(request.Connect)
			}
			if request.TLS > 0 {
				r.TLS.Observe(request.TLS)
			}
			r.FirstByte.Observe(request.FirstByte.Sub(request.Scheduled))
			r.Total.Observe(request.Duration)
		}
	}
	if request.Error != "" && len(r.FailuresSample) < 8 {
		r.FailuresSample = append(r.FailuresSample, request)
	}
}

func (r VisitorResult) Err() error {
	if r.Failures+r.Missed+r.QueueExpired > 0 {
		return errors.New("visitor requests failed, expired in queue, or missed their offer")
	}
	return nil
}
