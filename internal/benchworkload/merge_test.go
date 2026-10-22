package benchworkload

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func mergeFixture() VisitorResult {
	r := VisitorResult{StartedAt: time.Unix(1, 0).UTC(), Scheduled: 1, Started: 1, Completed: 1, Failures: 1,
		FailuresSample: []RequestResult{{Error: "authored failure"}}}
	for _, h := range []*Histogram{&r.QueueDelay, &r.DNS, &r.Connect, &r.TLS, &r.FirstByte, &r.Total} {
		*h = Histogram{BoundsMilliseconds: []float64{1, 10}, Counts: []uint64{0, 1}, Count: 1, SumMilliseconds: 2, MinimumMilliseconds: 2, MaximumMilliseconds: 2}
	}
	return r
}

func TestVisitorMergeIsAtomicAndOwnsSlices(t *testing.T) {
	for _, field := range []string{"queue", "dns", "connect", "tls", "first byte", "total", "accounting"} {
		t.Run(field, func(t *testing.T) {
			destination, source := mergeFixture(), mergeFixture()
			alias := destination
			before, _ := json.Marshal(destination)
			histograms := map[string]*Histogram{"queue": &source.QueueDelay, "dns": &source.DNS, "connect": &source.Connect, "tls": &source.TLS, "first byte": &source.FirstByte, "total": &source.Total}
			if h := histograms[field]; h != nil {
				h.BoundsMilliseconds[1] = 20
			} else {
				source.Scheduled++
			}
			if err := destination.Merge(source); err == nil {
				t.Fatal("invalid aggregate accepted")
			}
			after, _ := json.Marshal(destination)
			aliasAfter, _ := json.Marshal(alias)
			if string(before) != string(after) || string(before) != string(aliasAfter) {
				t.Fatal("failed merge partially changed receiver or its backing slices")
			}
		})
	}
	destination, source := mergeFixture(), mergeFixture()
	backing := []RequestResult{{Error: "kept"}, {Error: "sentinel"}}
	destination.FailuresSample = backing[:1]
	alias := destination
	if err := destination.Merge(source); err != nil {
		t.Fatal(err)
	}
	if destination.Scheduled != 2 || destination.Total.Count != 2 || !reflect.DeepEqual(destination.Total.Counts, []uint64{0, 2}) || len(destination.FailuresSample) != 2 {
		t.Fatal("successful aggregate lost measurements")
	}
	if backing[1].Error != "sentinel" || alias.Total.Counts[1] != 1 {
		t.Fatal("successful merge mutated an existing alias")
	}
	for _, h := range []*Histogram{&destination.QueueDelay, &destination.DNS, &destination.Connect, &destination.TLS, &destination.FirstByte, &destination.Total} {
		h.BoundsMilliseconds[0] = 999
		h.Counts[0] = 999
	}
	destination.FailuresSample[0].Error = "changed"
	if alias.Total.BoundsMilliseconds[0] != 1 || source.Total.BoundsMilliseconds[0] != 1 || alias.Total.Counts[0] != 0 || source.Total.Counts[0] != 0 || alias.FailuresSample[0].Error != "kept" || source.FailuresSample[0].Error != "authored failure" {
		t.Fatal("successful aggregate retained borrowed slices")
	}
	var empty VisitorResult
	if err := empty.Merge(source); err != nil {
		t.Fatal(err)
	}
	empty.Total.BoundsMilliseconds[0] = 999
	empty.Total.Counts[0] = 999
	empty.FailuresSample[0].Error = "changed"
	if source.Total.BoundsMilliseconds[0] != 1 || source.Total.Counts[0] != 0 || source.FailuresSample[0].Error != "authored failure" {
		t.Fatal("empty aggregate borrowed source storage")
	}
}
