package observability

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"slices"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"google.golang.org/protobuf/proto"
)

// DurationSummary describes observations between two process-local snapshots.
// quantiles are linear estimates within classic histogram buckets, not exact
// samples or maxima. they are nil for an empty interval or the unbounded bucket.
type DurationSummary struct {
	Name        string            `json:"name"`
	Labels      map[string]string `json:"labels"`
	Count       uint64            `json:"count"`
	SumSeconds  float64           `json:"sum_seconds"`
	MeanSeconds float64           `json:"mean_seconds"`
	P50Seconds  *float64          `json:"p50_seconds"`
	P95Seconds  *float64          `json:"p95_seconds"`
	P99Seconds  *float64          `json:"p99_seconds"`
}

type durationSeries struct {
	name   string
	labels map[string]string
	metric *dto.Metric
}

// ParseMetrics decodes Prometheus text exposition, retaining types and labels.
func ParseMetrics(reader io.Reader) ([]*dto.MetricFamily, error) {
	parser := expfmt.NewTextParser(model.UTF8Validation)
	families, err := parser.TextToMetricFamilies(reader)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(families))
	for name := range families {
		names = append(names, name)
	}
	slices.Sort(names)
	result := make([]*dto.MetricFamily, 0, len(names))
	for _, name := range names {
		result = append(result, families[name])
	}
	return result, nil
}

// DurationSummaries differences classic histogram counts, sums, and cumulative
// buckets before estimating quantiles. inputs must describe the same process;
// process_start_time_seconds and histogram creation timestamps, when present,
// also detect restarts. new lazy series start at zero. missing end series,
// changed layouts, invalid samples, and detectable resets invalidate the interval.
// all histogram families are included; callers should supply durations in seconds.
func DurationSummaries(before, after []*dto.MetricFamily) ([]DurationSummary, error) {
	start, err := measurementSeries(before)
	if err != nil {
		return nil, fmt.Errorf("baseline: %w", err)
	}
	end, err := measurementSeries(after)
	if err != nil {
		return nil, fmt.Errorf("final: %w", err)
	}
	layouts := make(map[string]*dto.Histogram)
	for _, snapshot := range []map[string]durationSeries{start, end} {
		for _, series := range snapshot {
			if histogram := series.metric.Histogram; histogram != nil {
				if previous := layouts[series.name]; previous != nil && !sameDurationLayout(previous, histogram) {
					return nil, fmt.Errorf("%s: histogram bounds changed", series.name)
				}
				layouts[series.name] = histogram
			}
		}
	}
	for key, previous := range start {
		current, ok := end[key]
		if !ok {
			return nil, fmt.Errorf("%s: missing final series", key)
		}
		if previous.metric.Gauge != nil && (current.metric.Gauge == nil || previous.metric.Gauge.GetValue() != current.metric.Gauge.GetValue()) {
			return nil, fmt.Errorf("%s: process restarted", key)
		}
	}
	keys := make([]string, 0, len(end))
	for key, series := range end {
		if series.metric.Histogram != nil {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	result := make([]DurationSummary, 0, len(keys))
	for _, key := range keys {
		current := end[key]
		summary, err := summarizeDuration(current.name, current.labels, start[key].metric.GetHistogram(), current.metric.Histogram)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", key, err)
		}
		result = append(result, summary)
	}
	return result, nil
}

func measurementSeries(families []*dto.MetricFamily) (map[string]durationSeries, error) {
	series := make(map[string]durationSeries)
	seen := make(map[string]bool)
	for _, family := range families {
		name := family.GetName()
		if family.GetType() != dto.MetricType_HISTOGRAM && name != "process_start_time_seconds" {
			continue
		}
		if name == "" || seen[name] {
			return nil, fmt.Errorf("invalid or duplicate family %q", name)
		}
		seen[name] = true
		for _, metric := range family.Metric {
			labels := make(map[string]string)
			for _, label := range metric.GetLabel() {
				if label.GetName() == "" || label.Value == nil {
					return nil, fmt.Errorf("%s: invalid label", name)
				}
				if _, exists := labels[label.GetName()]; exists {
					return nil, fmt.Errorf("%s: duplicate label %q", name, label.GetName())
				}
				labels[label.GetName()] = label.GetValue()
			}
			key, _ := json.Marshal(struct {
				Name   string
				Labels map[string]string
			}{name, labels})
			if _, exists := series[string(key)]; exists {
				return nil, fmt.Errorf("%s: duplicate series", key)
			}
			if name == "process_start_time_seconds" {
				if metric.GetGauge() == nil || metric.Gauge.Value == nil || !finiteNonnegative(metric.Gauge.GetValue()) {
					return nil, fmt.Errorf("%s: invalid process start time", key)
				}
			} else if err := validateDurationHistogram(metric.GetHistogram()); err != nil {
				return nil, fmt.Errorf("%s: %w", key, err)
			}
			series[string(key)] = durationSeries{name: name, labels: labels, metric: metric}
		}
	}
	return series, nil
}

func validateDurationHistogram(histogram *dto.Histogram) error {
	if histogram == nil || histogram.SampleCount == nil || histogram.SampleSum == nil ||
		!finiteNonnegative(histogram.GetSampleSum()) || histogram.Schema != nil || histogram.SampleCountFloat != nil {
		return fmt.Errorf("missing or unsupported duration histogram samples")
	}
	if histogram.GetSampleCount() == 0 && histogram.GetSampleSum() != 0 {
		return fmt.Errorf("empty histogram has a nonzero sum")
	}
	previousBound, previousCount := math.Inf(-1), uint64(0)
	for _, bucket := range histogram.Bucket {
		bound, count := bucket.GetUpperBound(), bucket.GetCumulativeCount()
		if bucket == nil || bucket.UpperBound == nil || bucket.CumulativeCount == nil || bucket.CumulativeCountFloat != nil ||
			math.IsNaN(bound) || bound < 0 || bound <= previousBound || count < previousCount || count > histogram.GetSampleCount() {
			return fmt.Errorf("invalid or nonmonotonic histogram buckets")
		}
		if math.IsInf(bound, 1) && count != histogram.GetSampleCount() {
			return fmt.Errorf("infinite bucket differs from sample count")
		}
		previousBound, previousCount = bound, count
	}
	if len(finiteDurationBuckets(histogram)) == 0 {
		return fmt.Errorf("histogram has no finite buckets")
	}
	return nil
}

func finiteDurationBuckets(histogram *dto.Histogram) []*dto.Bucket {
	buckets := histogram.GetBucket()
	if len(buckets) > 0 && math.IsInf(buckets[len(buckets)-1].GetUpperBound(), 1) {
		return buckets[:len(buckets)-1]
	}
	return buckets
}

func sameDurationLayout(left, right *dto.Histogram) bool {
	a, b := finiteDurationBuckets(left), finiteDurationBuckets(right)
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index].GetUpperBound() != b[index].GetUpperBound() {
			return false
		}
	}
	return true
}

func summarizeDuration(name string, labels map[string]string, before, after *dto.Histogram) (DurationSummary, error) {
	result := DurationSummary{Name: name, Labels: labels, Count: after.GetSampleCount(), SumSeconds: after.GetSampleSum()}
	buckets := finiteDurationBuckets(after)
	counts := make([]uint64, len(buckets))
	for index, bucket := range buckets {
		counts[index] = bucket.GetCumulativeCount()
	}
	if before != nil {
		previous := finiteDurationBuckets(before)
		if !proto.Equal(before.CreatedTimestamp, after.CreatedTimestamp) {
			return result, fmt.Errorf("histogram creation timestamp changed")
		}
		if after.GetSampleCount() < before.GetSampleCount() || after.GetSampleSum() < before.GetSampleSum() {
			return result, fmt.Errorf("histogram counter reset")
		}
		result.Count -= before.GetSampleCount()
		result.SumSeconds -= before.GetSampleSum()
		for index, bucket := range previous {
			if counts[index] < bucket.GetCumulativeCount() {
				return result, fmt.Errorf("histogram bucket counter reset")
			}
			counts[index] -= bucket.GetCumulativeCount()
		}
	}
	previousCount := uint64(0)
	for _, count := range counts {
		if count < previousCount || count > result.Count {
			return result, fmt.Errorf("nonmonotonic histogram bucket deltas")
		}
		previousCount = count
	}
	if result.Count == 0 {
		if result.SumSeconds != 0 {
			return result, fmt.Errorf("empty interval has a nonzero sum")
		}
		return result, nil
	}
	result.MeanSeconds = result.SumSeconds / float64(result.Count)
	result.P50Seconds = durationQuantile(buckets, counts, result.Count, 0.50)
	result.P95Seconds = durationQuantile(buckets, counts, result.Count, 0.95)
	result.P99Seconds = durationQuantile(buckets, counts, result.Count, 0.99)
	return result, nil
}

func durationQuantile(buckets []*dto.Bucket, counts []uint64, count uint64, quantile float64) *float64 {
	rank := float64(count) * quantile
	lower, previous := float64(0), uint64(0)
	for index, cumulative := range counts {
		if float64(cumulative) >= rank && cumulative > previous {
			value := lower + (buckets[index].GetUpperBound()-lower)*(rank-float64(previous))/float64(cumulative-previous)
			return &value
		}
		lower, previous = buckets[index].GetUpperBound(), cumulative
	}
	return nil
}

func finiteNonnegative(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0
}
