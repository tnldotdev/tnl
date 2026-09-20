package main

import (
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/tnldotdev/tnl/internal/benchworkload"
)

const benchmarkResultSchemaVersion = 8

type benchmarkResult struct {
	SchemaVersion          int                  `json:"schema_version"`
	CellID                 string               `json:"cell_id"`
	Status                 string               `json:"status"`
	Worker                 resultWorker         `json:"worker"`
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

type phaseResult struct {
	Visitor              *benchworkload.VisitorResult `json:"visitor,omitempty"`
	Name                 string                       `json:"name"`
	StartedAt            time.Time                    `json:"started_at"`
	DurationMilliseconds float64                      `json:"duration_milliseconds"`
	Attempts             int                          `json:"attempts"`
	Successes            int                          `json:"successes"`
	Errors               int                          `json:"errors"`
	Concurrency          int                          `json:"concurrency,omitempty"`
	DNS                  *durationHistogram           `json:"dns,omitempty"`
	Total                *durationHistogram           `json:"total,omitempty"`
}

type durationHistogram = benchworkload.Histogram

type resourceSample struct {
	Role      string              `json:"role"`
	Identity  string              `json:"identity"`
	Moment    string              `json:"moment"`
	Metrics   []*dto.MetricFamily `json:"metrics,omitempty"`
	Error     string              `json:"error,omitempty"`
	Timestamp time.Time           `json:"timestamp"`
}

type resultCleanup struct {
	Exact bool `json:"exact"`
}

type resultFailure struct {
	Message string `json:"message"`
	Stage   string `json:"stage,omitempty"`
}

func newDurationHistogram(samples []time.Duration) *durationHistogram {
	return benchworkload.NewHistogram(samples)
}

func mergeDurationHistogram(destination **durationHistogram, source *durationHistogram) error {
	if source == nil {
		return nil
	}
	if *destination == nil {
		*destination = new(durationHistogram)
	}
	return (*destination).Merge(*source)
}

func histogramPercentile(histogram *durationHistogram, percentile int) *float64 {
	return histogram.Percentile(percentile)
}

func milliseconds(duration time.Duration) float64 {
	return float64(duration) / float64(time.Millisecond)
}
