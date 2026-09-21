package benchworkload

import (
	"encoding/json"
	"testing"
	"time"
)

func TestSerializedPhaseUsesLocalMonotonicSchedule(t *testing.T) {
	for _, offset := range []time.Duration{-time.Second, time.Second} {
		now := time.Now()
		data, err := json.Marshal(now.Add(offset))
		if err != nil {
			t.Fatal(err)
		}
		var remote time.Time
		if err := json.Unmarshal(data, &remote); err != nil {
			t.Fatal(err)
		}
		local := localSchedule(now, remote)
		if local == local.Round(0) {
			t.Fatal("rebased epoch has no monotonic clock")
		}
		if !local.Equal(remote) || local.Sub(now) != offset {
			t.Fatal("rebase changed the intended start")
		}
	}
}

func TestRejectNegativeRequestTiming(t *testing.T) {
	row := (Visitor{}).Request(t.Context(), "https://unused.invalid", time.Now().Add(time.Second))
	var result VisitorResult
	result.Observe(row)
	if row.Error == "" || result.Err() == nil || result.Successes != 0 || result.QueueDelay.Count != 0 {
		t.Fatalf("negative sample accepted: %+v", result)
	}
	if err := result.Total.Merge(Histogram{Count: 1, Counts: []uint64{1}, BoundsMilliseconds: []float64{1}, MinimumMilliseconds: -1}); err == nil {
		t.Fatal("negative serialized histogram accepted")
	}
}
