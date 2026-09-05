package observability

import (
	"fmt"
	"math"
	"strings"
	"testing"

	dto "github.com/prometheus/client_model/go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func durationFixture(t *testing.T, count uint64, sum float64, buckets ...uint64) []*dto.MetricFamily {
	t.Helper()
	var text strings.Builder
	text.WriteString("# TYPE tnl_operation_duration_seconds histogram\n")
	labels := `operation="POST /v1/\"routes\"\\path",outcome="success"`
	for index, count := range buckets {
		fmt.Fprintf(&text, "tnl_operation_duration_seconds_bucket{%s,le=%q} %d\n", labels, fmt.Sprint(index+1), count)
	}
	fmt.Fprintf(&text, "tnl_operation_duration_seconds_bucket{%s,le=\"+Inf\"} %d\n", labels, count)
	fmt.Fprintf(&text, "tnl_operation_duration_seconds_count{%s} %d\n", labels, count)
	fmt.Fprintf(&text, "tnl_operation_duration_seconds_sum{%s} %g\n", labels, sum)
	result, err := ParseMetrics(strings.NewReader(text.String()))
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestDurationSummariesIntervalAndLabels(t *testing.T) {
	before := durationFixture(t, 10, 10, 6, 10)
	after := durationFixture(t, 14, 15, 8, 14)
	// Gather omits the implicit +Inf bucket; text exposition includes it.
	before[0].Metric[0].Histogram.Bucket = before[0].Metric[0].Histogram.Bucket[:2]
	result, err := DurationSummaries(before, after)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("summaries = %+v", result)
	}
	got := result[0]
	if got.Name != "tnl_operation_duration_seconds" || got.Labels["operation"] != "POST /v1/\"routes\"\\path" ||
		got.Count != 4 || got.SumSeconds != 5 || got.MeanSeconds != 1.25 ||
		got.P50Seconds == nil || *got.P50Seconds != 1 || got.P95Seconds == nil || math.Abs(*got.P95Seconds-1.9) > 1e-9 ||
		got.P99Seconds == nil || math.Abs(*got.P99Seconds-1.98) > 1e-9 {
		t.Fatalf("summary = %+v", got)
	}
	// Structured identities are independent of label ordering.
	after[0].Metric[0].Label[0], after[0].Metric[0].Label[1] = after[0].Metric[0].Label[1], after[0].Metric[0].Label[0]
	if _, err := DurationSummaries(before, after); err != nil {
		t.Fatal(err)
	}
}

func TestDurationSummariesEmptyLazyAndOverflow(t *testing.T) {
	before := durationFixture(t, 4, 4, 2, 4)
	got, err := DurationSummaries(before, before)
	if err != nil || len(got) != 1 || got[0].Count != 0 || got[0].P50Seconds != nil || got[0].P95Seconds != nil || got[0].P99Seconds != nil {
		t.Fatalf("empty interval = %+v, %v", got, err)
	}
	got, err = DurationSummaries(nil, durationFixture(t, 10, 25, 5, 9))
	if err != nil || len(got) != 1 || got[0].Count != 10 || got[0].P50Seconds == nil || *got[0].P50Seconds != 1 ||
		got[0].P95Seconds != nil || got[0].P99Seconds != nil {
		t.Fatalf("lazy series with overflow = %+v, %v", got, err)
	}
}

func TestDurationSummariesRejectInvalidIntervals(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(before, after []*dto.MetricFamily) ([]*dto.MetricFamily, []*dto.MetricFamily)
	}{
		{"missing final", func(b, a []*dto.MetricFamily) ([]*dto.MetricFamily, []*dto.MetricFamily) { return b, nil }},
		{"lazy series layout", func(b, a []*dto.MetricFamily) ([]*dto.MetricFamily, []*dto.MetricFamily) {
			lazy := proto.Clone(a[0].Metric[0]).(*dto.Metric)
			lazy.Label[0].Value = proto.String("different operation")
			lazy.Histogram.Bucket[0].UpperBound = proto.Float64(0.5)
			a[0].Metric = append(a[0].Metric, lazy)
			return b, a
		}},
		{"duplicate labels", func(b, a []*dto.MetricFamily) ([]*dto.MetricFamily, []*dto.MetricFamily) {
			a[0].Metric[0].Label = append(a[0].Metric[0].Label, a[0].Metric[0].Label[0])
			return b, a
		}},
		{"duplicate series", func(b, a []*dto.MetricFamily) ([]*dto.MetricFamily, []*dto.MetricFamily) {
			a[0].Metric = append(a[0].Metric, a[0].Metric[0])
			return b, a
		}},
		{"empty interval with sum delta", func(b, _ []*dto.MetricFamily) ([]*dto.MetricFamily, []*dto.MetricFamily) {
			a := []*dto.MetricFamily{proto.Clone(b[0]).(*dto.MetricFamily)}
			a[0].Metric[0].Histogram.SampleSum = proto.Float64(5)
			return b, a
		}},
		{"layout", func(b, a []*dto.MetricFamily) ([]*dto.MetricFamily, []*dto.MetricFamily) {
			a[0].Metric[0].Histogram.Bucket[0].UpperBound = proto.Float64(0.5)
			return b, a
		}},
		{"reset", func(b, a []*dto.MetricFamily) ([]*dto.MetricFamily, []*dto.MetricFamily) { return a, b }},
		{"sum reset", func(b, a []*dto.MetricFamily) ([]*dto.MetricFamily, []*dto.MetricFamily) {
			a[0].Metric[0].Histogram.SampleSum = proto.Float64(1)
			return b, a
		}},
		{"bucket reset", func(b, a []*dto.MetricFamily) ([]*dto.MetricFamily, []*dto.MetricFamily) {
			a[0].Metric[0].Histogram.Bucket[0].CumulativeCount = proto.Uint64(1)
			return b, a
		}},
		{"nonmonotonic delta", func(b, a []*dto.MetricFamily) ([]*dto.MetricFamily, []*dto.MetricFamily) {
			a[0].Metric[0].Histogram.Bucket[0].CumulativeCount = proto.Uint64(7)
			return b, a
		}},
		{"nonmonotonic buckets", func(b, a []*dto.MetricFamily) ([]*dto.MetricFamily, []*dto.MetricFamily) {
			a[0].Metric[0].Histogram.Bucket[0].CumulativeCount = proto.Uint64(9)
			return b, a
		}},
		{"missing count", func(b, a []*dto.MetricFamily) ([]*dto.MetricFamily, []*dto.MetricFamily) {
			a[0].Metric[0].Histogram.SampleCount = nil
			return b, a
		}},
		{"missing sum", func(b, a []*dto.MetricFamily) ([]*dto.MetricFamily, []*dto.MetricFamily) {
			a[0].Metric[0].Histogram.SampleSum = nil
			return b, a
		}},
		{"nonfinite sum", func(b, a []*dto.MetricFamily) ([]*dto.MetricFamily, []*dto.MetricFamily) {
			a[0].Metric[0].Histogram.SampleSum = proto.Float64(math.NaN())
			return b, a
		}},
		{"recreated histogram", func(b, a []*dto.MetricFamily) ([]*dto.MetricFamily, []*dto.MetricFamily) {
			b[0].Metric[0].Histogram.CreatedTimestamp = &timestamppb.Timestamp{Seconds: 10}
			a[0].Metric[0].Histogram.CreatedTimestamp = &timestamppb.Timestamp{Seconds: 11}
			return b, a
		}},
		{"restarted process", func(b, a []*dto.MetricFamily) ([]*dto.MetricFamily, []*dto.MetricFamily) {
			start := func(value float64) *dto.MetricFamily {
				return &dto.MetricFamily{Name: proto.String("process_start_time_seconds"), Type: dto.MetricType_GAUGE.Enum(), Metric: []*dto.Metric{{Gauge: &dto.Gauge{Value: &value}}}}
			}
			return append(b, start(10)), append(a, start(11))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			before, after := test.edit(durationFixture(t, 4, 4, 2, 4), durationFixture(t, 8, 8, 4, 8))
			if result, err := DurationSummaries(before, after); err == nil || result != nil {
				t.Fatalf("invalid interval accepted: %+v, %v", result, err)
			}
		})
	}
}

func TestParseMetricsRejectsMalformedText(t *testing.T) {
	if _, err := ParseMetrics(strings.NewReader("tnl_operation_duration_seconds_count{operation=broken} nope\n")); err == nil {
		t.Fatal("malformed exposition accepted")
	}
}
