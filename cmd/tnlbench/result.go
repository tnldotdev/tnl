package main

import (
	"errors"
	"time"
)

var durationBucketBoundsMilliseconds = []float64{
	1, 2, 5, 10, 20, 50, 100, 200, 500, 1_000, 2_000, 5_000, 10_000, 30_000, 60_000, 120_000,
}

type benchmarkResult struct {
	SchemaVersion int                 `json:"schema_version"`
	CellID        string              `json:"cell_id"`
	Status        string              `json:"status"`
	Suite         string              `json:"suite"`
	Workload      string              `json:"workload"`
	Repetition    int                 `json:"repetition"`
	Shard         resultShard         `json:"shard"`
	Configuration resultConfiguration `json:"configuration"`
	Phases        []phaseResult       `json:"phases"`
	ScaleIn       map[string]any      `json:"scale_in"`
	Resources     resultResources     `json:"resources"`
	Cleanup       resultCleanup       `json:"cleanup"`
	Failure       *resultFailure      `json:"failure"`
}

type resultShard struct {
	Index int `json:"index"`
	Count int `json:"count"`
}

type resultConfiguration struct {
	Topology                     string `json:"topology"`
	Routes                       int    `json:"routes"`
	ExpectedPublisherConnections int    `json:"expected_publisher_connections"`
	Parallel                     int    `json:"parallel"`
	PayloadBytes                 int    `json:"payload_bytes"`
}

type phaseResult struct {
	Name                   string             `json:"name"`
	StartedAt              time.Time          `json:"started_at"`
	DurationMilliseconds   float64            `json:"duration_milliseconds"`
	Attempts               int                `json:"attempts"`
	Successes              int                `json:"successes"`
	Errors                 int                `json:"errors"`
	Bytes                  int64              `json:"bytes"`
	Latency                *durationHistogram `json:"latency,omitempty"`
	FirstByteLatency       *durationHistogram `json:"first_byte_latency,omitempty"`
	ThroughputMiBPerSecond float64            `json:"throughput_mib_per_second,omitempty"`
}

type durationHistogram struct {
	BoundsMilliseconds  []float64 `json:"bounds_milliseconds"`
	Counts              []uint64  `json:"counts"`
	Count               uint64    `json:"count"`
	SumMilliseconds     float64   `json:"sum_milliseconds"`
	MinimumMilliseconds float64   `json:"minimum_milliseconds"`
	MaximumMilliseconds float64   `json:"maximum_milliseconds"`
}

type resultResources struct {
	ReadyRelays   []relaySample `json:"ready_relays"`
	SettledRelays []relaySample `json:"settled_relays"`
}

type resultCleanup struct {
	ExpectedPublisherConnections int  `json:"expected_publisher_connections"`
	Exact                        bool `json:"exact"`
}

type resultFailure struct {
	Message string `json:"message"`
}

func newBenchmarkResult(flags cli, started time.Time, measured measurements, runErr error) benchmarkResult {
	result := benchmarkResult{
		SchemaVersion: 4,
		CellID:        flags.cellID(),
		Status:        "passed",
		Suite:         flags.Suite,
		Workload:      flags.Workload,
		Repetition:    flags.Repetition,
		Shard:         resultShard{Index: flags.DriverIndex, Count: flags.DriverCount},
		Configuration: resultConfiguration{
			Topology: flags.Topology, Routes: flags.Routes,
			ExpectedPublisherConnections: flags.expectedPublisherConnections(),
			Parallel:                     flags.Parallel, PayloadBytes: flags.PayloadBytes,
		},
		Phases: []phaseResult{}, ScaleIn: map[string]any{},
		Resources: resultResources{ReadyRelays: measured.ReadyRelays, SettledRelays: measured.SettledRelays},
		Cleanup:   resultCleanup{ExpectedPublisherConnections: 0, Exact: runErr == nil},
	}
	if runErr != nil {
		result.Status = "failed"
		result.Failure = &resultFailure{Message: runErr.Error()}
		result.Phases = append(result.Phases, phaseResult{
			Name: "driver", StartedAt: started, DurationMilliseconds: milliseconds(time.Since(started)),
			Attempts: 1, Errors: 1,
		})
		return result
	}
	result.Phases = append(result.Phases,
		phaseResult{
			Name: "activation", StartedAt: measured.ActivationStarted,
			DurationMilliseconds: milliseconds(measured.ActivationElapsed), Attempts: len(measured.Activation),
			Successes: len(measured.Activation), Latency: newDurationHistogram(measured.Activation),
		},
		phaseResult{
			Name: "correctness", StartedAt: measured.RequestStarted,
			DurationMilliseconds: milliseconds(measured.RequestElapsed), Attempts: len(measured.Request),
			Successes: len(measured.Request), Bytes: int64(len(measured.Request) * flags.PayloadBytes),
			Latency: newDurationHistogram(measured.Request), FirstByteLatency: newDurationHistogram(measured.FirstByte),
			ThroughputMiBPerSecond: float64(len(measured.Request)*flags.PayloadBytes) / (1024 * 1024) / measured.RequestElapsed.Seconds(),
		},
		phaseResult{
			Name: "cleanup", StartedAt: measured.CleanupStarted,
			DurationMilliseconds: milliseconds(measured.CleanupElapsed), Attempts: len(measured.Teardown),
			Successes: len(measured.Teardown), Latency: newDurationHistogram(measured.Teardown),
		},
	)
	return result
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
