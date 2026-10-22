package publicurlusage

import (
	"bytes"
	"encoding/binary"
	"math"
	"slices"
	"testing"
	"time"
)

func TestDurationHistogramBoundaries(t *testing.T) {
	// these are API boundaries, independent of the implementation's array.
	for index, boundary := range []time.Duration{
		time.Millisecond, 5 * time.Millisecond, 10 * time.Millisecond, 25 * time.Millisecond,
		50 * time.Millisecond, 100 * time.Millisecond, 250 * time.Millisecond, 500 * time.Millisecond,
		time.Second, 2500 * time.Millisecond, 5 * time.Second, 10 * time.Second, 30 * time.Second,
		time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour, 6 * time.Hour, 24 * time.Hour, 72 * time.Hour, 168 * time.Hour,
	} {
		t.Run(boundary.String(), func(t *testing.T) {
			var histogram DurationHistogram
			for _, value := range []time.Duration{boundary - 1, boundary, boundary + 1} {
				if err := histogram.Observe(value); err != nil {
					t.Fatal(err)
				}
			}
			want := make([]uint64, 22)
			want[index] = 2
			for bucket := index + 1; bucket < len(want); bucket++ {
				want[bucket] = 3
			}
			if !slices.Equal(histogram.CumulativeCounts(), want) || histogram.Count() != 3 || histogram.SumNanoseconds() != uint64(3*boundary) {
				t.Fatalf("histogram = %#v, want counts %v sum %d", histogram, want, 3*boundary)
			}
			copy := histogram.CumulativeCounts()
			copy[21] = 99
			if histogram.Count() != 3 {
				t.Fatal("CumulativeCounts aliases histogram")
			}
		})
	}
}

func TestDurationHistogramClampAndMerge(t *testing.T) {
	var first, second DurationHistogram
	for _, duration := range []time.Duration{-time.Hour, 0} {
		if err := first.Observe(duration); err != nil {
			t.Fatal(err)
		}
	}
	if first.SumNanoseconds() != 0 {
		t.Fatal("negative durations were not clamped")
	}
	for _, count := range first.CumulativeCounts() {
		if count != 2 {
			t.Fatalf("clamped count = %d", count)
		}
	}
	if err := second.Observe(time.Millisecond + 1); err != nil {
		t.Fatal(err)
	}
	if err := second.Observe(8 * 24 * time.Hour); err != nil {
		t.Fatal(err)
	}
	before := second
	if err := first.merge(second); err != nil {
		t.Fatal(err)
	}
	want := []uint64{2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 4}
	if !slices.Equal(first.CumulativeCounts(), want) || first.SumNanoseconds() != 691200001000001 || first.Count() != 4 || second != before {
		t.Fatalf("merged histogram = %#v, source = %#v", first, second)
	}
}

func TestDurationHistogramOverflowIsAtomic(t *testing.T) {
	for _, operation := range []string{"observe", "merge"} {
		t.Run(operation, func(t *testing.T) {
			apply := func(h *DurationHistogram) error {
				if operation == "observe" {
					return h.Observe(1)
				}
				var other DurationHistogram
				if err := other.Observe(1); err != nil {
					return err
				}
				return h.merge(other)
			}
			h := DurationHistogram{sumNanoseconds: math.MaxInt64 - 1}
			if err := apply(&h); err != nil || h.SumNanoseconds() != math.MaxInt64 {
				t.Fatalf("at limit = %#v, %v", h, err)
			}
			before := h
			if err := apply(&h); err == nil || h != before {
				t.Fatalf("sum overflow = %#v, %v", h, err)
			}
			for index := range 22 {
				h = DurationHistogram{}
				for bucket := index; bucket < 22; bucket++ {
					h.counts[bucket] = math.MaxInt64
				}
				before = h
				if err := apply(&h); err == nil || h != before {
					t.Fatalf("count overflow at %d = %#v, %v", index, h, err)
				}
			}
		})
	}
}

func TestParseDurationHistogramRejectsMalformedData(t *testing.T) {
	// Literal-width big-endian vector: sum 1 and all 22 counts 1.
	valid := make([]byte, 184)
	for offset := 0; offset < len(valid); offset += 8 {
		valid[offset+7] = 1
	}
	if got, err := parseDurationHistogram(valid); err != nil || got.SumNanoseconds() != 1 || got.Count() != 1 {
		t.Fatalf("valid parse = %#v, %v", got, err)
	}
	for _, test := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"short", func(b []byte) []byte { return b[:183] }},
		{"long", func(b []byte) []byte { return append(b, 0) }},
		{"unsigned sum", func(b []byte) []byte { binary.BigEndian.PutUint64(b, 1<<63); return b }},
		{"unsigned count", func(b []byte) []byte { binary.BigEndian.PutUint64(b[176:], 1<<63); return b }},
		{"decreasing counts", func(b []byte) []byte { b[23] = 0; return b }},
		{"empty populated section", func(b []byte) []byte { clear(b); return b }},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseDurationHistogram(test.mutate(bytes.Clone(valid))); err == nil {
				t.Fatal("accepted malformed histogram")
			}
		})
	}
}
