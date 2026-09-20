package main

import (
	"math"
	"testing"
	"time"
)

func TestDurationHistogramMergesBeforePercentiles(t *testing.T) {
	left := newDurationHistogram([]time.Duration{time.Millisecond, 2 * time.Millisecond})
	right := newDurationHistogram([]time.Duration{100 * time.Millisecond, 200 * time.Millisecond})
	if err := mergeDurationHistogram(&left, right); err != nil {
		t.Fatal(err)
	}
	p50, p95 := histogramPercentile(left, 50), histogramPercentile(left, 95)
	if left.Count != 4 || math.Abs(left.SumMilliseconds-303) > 1e-9 || p50 == nil || *p50 != 2.5 ||
		p95 == nil || math.Abs(*p95-220) > 1e-9 || left.MaximumMilliseconds != 200 {
		t.Fatalf("merged histogram = %#v", left)
	}
}

func TestDurationHistogramOverflowAndMissingSamplesAreUnavailable(t *testing.T) {
	if histogramPercentile(nil, 95) != nil {
		t.Fatal("missing histogram reported a percentile")
	}
	histogram := newDurationHistogram([]time.Duration{3 * time.Minute})
	if histogramPercentile(histogram, 95) != nil || histogram.MaximumMilliseconds != 180000 {
		t.Fatalf("overflow manufactured a percentile or lost the observed maximum: %+v", histogram)
	}
}
