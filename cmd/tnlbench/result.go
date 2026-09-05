package main

import (
	"errors"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"google.golang.org/protobuf/proto"

	"github.com/tnldotdev/tnl/internal/observability"
)

const benchmarkResultSchemaVersion = 7

type benchmarkResult struct {
	SchemaVersion          int                  `json:"schema_version"`
	CellID                 string               `json:"cell_id"`
	Status                 string               `json:"status"`
	Suite                  string               `json:"suite"`
	Repetition             int                  `json:"repetition"`
	Worker                 resultWorker         `json:"worker"`
	Configuration          resultConfiguration  `json:"configuration"`
	Phases                 []phaseResult        `json:"phases"`
	Resources              []resourceSample     `json:"resources,omitempty"`
	DroppedResourceSamples int                  `json:"dropped_resource_samples,omitempty"`
	DatabaseDiagnostics    []databaseDiagnostic `json:"database_diagnostics,omitempty"`
	Cleanup                resultCleanup        `json:"cleanup"`
	Failure                *resultFailure       `json:"failure,omitempty"`
}

type resultWorker struct {
	Kind  string `json:"kind"`
	Index int    `json:"index"`
	Count int    `json:"count"`
}

type resultConfiguration struct {
	Axis                      string `json:"axis"`
	Sequence                  int    `json:"sequence"`
	Routes                    int    `json:"routes"`
	AssignedRoutes            int    `json:"assigned_routes,omitempty"`
	FreshConnectionsPerSecond int    `json:"fresh_connections_per_second,omitempty"`
	HeldStreams               int    `json:"held_streams,omitempty"`
	LifecycleChurnPerSecond   int    `json:"lifecycle_churn_per_second,omitempty"`
	AssignedLifecycleChurn    int    `json:"assigned_lifecycle_churn_per_second,omitempty"`
	AssignedFreshRate         int    `json:"assigned_fresh_connections_per_second,omitempty"`
	AssignedHeldStreams       int    `json:"assigned_held_streams,omitempty"`
	WarmupSeconds             int    `json:"warmup_seconds,omitempty"`
	DurationSeconds           int    `json:"duration_seconds,omitempty"`
	PayloadBytes              int    `json:"payload_bytes,omitempty"`
}

type phaseResult struct {
	Name                 string             `json:"name"`
	StartedAt            time.Time          `json:"started_at"`
	DurationMilliseconds float64            `json:"duration_milliseconds"`
	Attempts             int                `json:"attempts"`
	Successes            int                `json:"successes"`
	Errors               int                `json:"errors"`
	Bytes                int64              `json:"bytes"`
	AchievedRate         float64            `json:"achieved_rate,omitempty"`
	Concurrency          int                `json:"concurrency,omitempty"`
	DNS                  *durationHistogram `json:"dns,omitempty"`
	Connect              *durationHistogram `json:"connect,omitempty"`
	TLS                  *durationHistogram `json:"tls,omitempty"`
	FirstByte            *durationHistogram `json:"first_byte,omitempty"`
	Total                *durationHistogram `json:"total,omitempty"`
}

type durationHistogram struct {
	BoundsMilliseconds  []float64 `json:"bounds_milliseconds"`
	Counts              []uint64  `json:"counts"`
	Count               uint64    `json:"count"`
	SumMilliseconds     float64   `json:"sum_milliseconds"`
	MinimumMilliseconds float64   `json:"minimum_milliseconds"`
	MaximumMilliseconds float64   `json:"maximum_milliseconds"`
}

type resourceSample struct {
	Role      string              `json:"role"`
	Identity  string              `json:"identity"`
	Moment    string              `json:"moment"`
	Metrics   []*dto.MetricFamily `json:"metrics,omitempty"`
	Error     string              `json:"error,omitempty"`
	Timestamp time.Time           `json:"timestamp"`
}

type resultCleanup struct {
	RoutesDeleted  int  `json:"routes_deleted"`
	RoutesRetained int  `json:"routes_retained"`
	Exact          bool `json:"exact"`
}

type resultFailure struct {
	Message string `json:"message"`
	Stage   string `json:"stage,omitempty"`
}

func failedResult(cellID, suite string, repetition int, worker resultWorker, configuration resultConfiguration, started time.Time, err error) benchmarkResult {
	return benchmarkResult{
		SchemaVersion: benchmarkResultSchemaVersion, CellID: cellID, Status: "failed", Suite: suite,
		Repetition: repetition, Worker: worker, Configuration: configuration,
		Phases: []phaseResult{{
			Name: "worker", StartedAt: started, DurationMilliseconds: milliseconds(time.Since(started)),
			Attempts: 1, Errors: 1,
		}},
		Failure: &resultFailure{Message: err.Error(), Stage: "setup"},
	}
}

func resultFailureStage(result benchmarkResult) string {
	if result.Status == "passed" {
		return ""
	}
	if result.Failure != nil && result.Failure.Stage != "" {
		return result.Failure.Stage
	}
	for _, phase := range result.Phases {
		if phase.Name == "worker" {
			return "setup"
		}
	}
	return "measurement"
}

func newDurationHistogram(samples []time.Duration) *durationHistogram {
	if len(samples) == 0 {
		return nil
	}
	histogram := &durationHistogram{
		MinimumMilliseconds: milliseconds(samples[0]), MaximumMilliseconds: milliseconds(samples[0]),
	}
	collector := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "tnl_benchmark_duration_seconds", Buckets: observability.DurationBucketsSeconds(),
	})
	for _, sample := range samples {
		value := milliseconds(sample)
		collector.Observe(sample.Seconds())
		histogram.MinimumMilliseconds = min(histogram.MinimumMilliseconds, value)
		histogram.MaximumMilliseconds = max(histogram.MaximumMilliseconds, value)
	}
	var metric dto.Metric
	_ = collector.Write(&metric)
	histogram.Count, histogram.SumMilliseconds = metric.Histogram.GetSampleCount(), metric.Histogram.GetSampleSum()*1000
	for _, bucket := range metric.Histogram.Bucket {
		histogram.BoundsMilliseconds = append(histogram.BoundsMilliseconds, bucket.GetUpperBound()*1000)
		histogram.Counts = append(histogram.Counts, bucket.GetCumulativeCount())
	}
	return histogram
}

func mergeDurationHistogram(destination **durationHistogram, source *durationHistogram) error {
	if source == nil {
		return nil
	}
	if _, err := visitorDurationSummary(source); err != nil {
		return err
	}
	if *destination == nil {
		copy := *source
		copy.BoundsMilliseconds = append([]float64(nil), source.BoundsMilliseconds...)
		copy.Counts = append([]uint64(nil), source.Counts...)
		*destination = &copy
		return nil
	}
	merged := *destination
	if len(merged.BoundsMilliseconds) != len(source.BoundsMilliseconds) || len(merged.Counts) != len(source.Counts) {
		return errors.New("histogram layouts differ")
	}
	for index := range merged.BoundsMilliseconds {
		if merged.BoundsMilliseconds[index] != source.BoundsMilliseconds[index] {
			return errors.New("histogram bounds differ")
		}
		merged.Counts[index] += source.Counts[index]
	}
	merged.Count += source.Count
	merged.SumMilliseconds += source.SumMilliseconds
	merged.MinimumMilliseconds = min(merged.MinimumMilliseconds, source.MinimumMilliseconds)
	merged.MaximumMilliseconds = max(merged.MaximumMilliseconds, source.MaximumMilliseconds)
	return nil
}

func visitorDurationSummary(histogram *durationHistogram) (observability.DurationSummary, error) {
	if len(histogram.BoundsMilliseconds) != len(histogram.Counts) {
		return observability.DurationSummary{}, errors.New("histogram bounds and counts differ")
	}
	value := &dto.Histogram{SampleCount: proto.Uint64(histogram.Count), SampleSum: proto.Float64(histogram.SumMilliseconds / 1000)}
	for index, bound := range histogram.BoundsMilliseconds {
		value.Bucket = append(value.Bucket, &dto.Bucket{UpperBound: proto.Float64(bound / 1000), CumulativeCount: proto.Uint64(histogram.Counts[index])})
	}
	result, err := observability.DurationSummaries(nil, []*dto.MetricFamily{{
		Name: proto.String("tnl_benchmark_duration_seconds"), Type: dto.MetricType_HISTOGRAM.Enum(), Metric: []*dto.Metric{{Histogram: value}},
	}})
	if err != nil {
		return observability.DurationSummary{}, err
	}
	return result[0], nil
}

func histogramPercentile(histogram *durationHistogram, percentile int) *float64 {
	if histogram == nil || histogram.Count == 0 {
		return nil
	}
	summary, err := visitorDurationSummary(histogram)
	if err != nil {
		return nil
	}
	value := map[int]*float64{50: summary.P50Seconds, 95: summary.P95Seconds, 99: summary.P99Seconds}[percentile]
	if value == nil {
		return nil
	}
	milliseconds := *value * 1000
	return &milliseconds
}

func milliseconds(duration time.Duration) float64 {
	return float64(duration) / float64(time.Millisecond)
}
