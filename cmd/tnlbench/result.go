package main

import (
	"errors"
	"time"
)

const benchmarkResultSchemaVersion = 6

var durationBucketBoundsMilliseconds = []float64{
	1, 2, 5, 10, 20, 50, 100, 200, 500, 1_000, 2_000, 5_000, 10_000, 30_000, 60_000, 120_000,
}

type benchmarkResult struct {
	SchemaVersion int                 `json:"schema_version"`
	CellID        string              `json:"cell_id"`
	Status        string              `json:"status"`
	Suite         string              `json:"suite"`
	Repetition    int                 `json:"repetition"`
	Worker        resultWorker        `json:"worker"`
	Configuration resultConfiguration `json:"configuration"`
	Phases        []phaseResult       `json:"phases"`
	Resources     []resourceSample    `json:"resources,omitempty"`
	Cleanup       resultCleanup       `json:"cleanup"`
	Failure       *resultFailure      `json:"failure,omitempty"`
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
	Role      string             `json:"role"`
	Identity  string             `json:"identity"`
	Moment    string             `json:"moment"`
	Metrics   map[string]float64 `json:"metrics,omitempty"`
	Error     string             `json:"error,omitempty"`
	Timestamp time.Time          `json:"timestamp"`
}

type resultCleanup struct {
	RoutesDeleted  int  `json:"routes_deleted"`
	RoutesRetained int  `json:"routes_retained"`
	Exact          bool `json:"exact"`
}

type resultFailure struct {
	Message string `json:"message"`
}

func failedResult(cellID, suite string, repetition int, worker resultWorker, configuration resultConfiguration, started time.Time, err error) benchmarkResult {
	return benchmarkResult{
		SchemaVersion: benchmarkResultSchemaVersion, CellID: cellID, Status: "failed", Suite: suite,
		Repetition: repetition, Worker: worker, Configuration: configuration,
		Phases: []phaseResult{{
			Name: "worker", StartedAt: started, DurationMilliseconds: milliseconds(time.Since(started)),
			Attempts: 1, Errors: 1,
		}},
		Failure: &resultFailure{Message: err.Error()},
	}
}

func newDurationHistogram(samples []time.Duration) *durationHistogram {
	if len(samples) == 0 {
		return nil
	}
	histogram := &durationHistogram{
		BoundsMilliseconds: append([]float64(nil), durationBucketBoundsMilliseconds...),
		Counts:             make([]uint64, len(durationBucketBoundsMilliseconds)), Count: uint64(len(samples)),
		MinimumMilliseconds: milliseconds(samples[0]), MaximumMilliseconds: milliseconds(samples[0]),
	}
	for _, sample := range samples {
		value := milliseconds(sample)
		histogram.SumMilliseconds += value
		histogram.MinimumMilliseconds = min(histogram.MinimumMilliseconds, value)
		histogram.MaximumMilliseconds = max(histogram.MaximumMilliseconds, value)
		for index, bound := range histogram.BoundsMilliseconds {
			if value <= bound {
				histogram.Counts[index]++
			}
		}
	}
	return histogram
}

func mergeDurationHistogram(destination **durationHistogram, source *durationHistogram) error {
	if source == nil {
		return nil
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

func histogramPercentile(histogram *durationHistogram, percentile int) float64 {
	if histogram == nil || histogram.Count == 0 {
		return 0
	}
	rank := (histogram.Count*uint64(percentile) + 99) / 100
	for index, count := range histogram.Counts {
		if count >= rank {
			return histogram.BoundsMilliseconds[index]
		}
	}
	return histogram.MaximumMilliseconds
}

func milliseconds(duration time.Duration) float64 {
	return float64(duration) / float64(time.Millisecond)
}
