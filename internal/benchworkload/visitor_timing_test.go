package benchworkload

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestVisitorTimingPreservesSlotsAndCollectorOrder(t *testing.T) {
	const slots = 1000
	timing := &VisitorTimings{Requests: make([]VisitorRequestTiming, slots)}
	var callbacks atomic.Int64
	rows := make([]RequestResult, 0, slots)
	result, err := runVisitors(t.Context(), VisitorConfig{Rate: 10000, Workers: 4, QueueSlots: 4, Start: time.Now().Add(-time.Second), Duration: 100 * time.Millisecond, Timing: timing, OnResult: func(row RequestResult) {
		if callbacks.Add(1) != 1 {
			t.Error("concurrent callbacks")
		}
		rows = append(rows, row)
		callbacks.Add(-1)
	}}, []string{"postgres"}, func(_ context.Context, url string, scheduled time.Time) RequestResult {
		started := time.Now()
		return RequestResult{URL: url, Scheduled: scheduled, Started: started, QueueDelay: started.Sub(scheduled), Duration: time.Since(scheduled)}
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Scheduled != slots || len(timing.Requests) != slots || result.Completed != len(rows) || result.Completed+result.Missed != slots {
		t.Fatalf("lost slots: %+v", result)
	}
	seen := make(map[int]bool)
	var missed int
	for slot, row := range timing.Requests {
		if row.Slot != slot || row.Scheduled != time.Duration(slot)*time.Second/10000 || row.Offered < row.Scheduled {
			t.Fatalf("wrong slot timing: %+v", row)
		}
		if row.Missed {
			missed++
			continue
		}
		if row.ResultIndex < 1 || row.ResultIndex > len(rows) || seen[row.ResultIndex] {
			t.Fatalf("wrong result index: %+v", row)
		}
		seen[row.ResultIndex] = true
		original := rows[row.ResultIndex-1]
		if row.Completed != original.Scheduled.Sub(timing.Start)+original.Duration {
			t.Fatal("completion no longer matches the measured endpoint")
		}
		order := []time.Duration{row.Offered, row.Started, row.Completed, row.RequestReturned, row.CollectorWaitStarted, row.CollectorAcquired, row.CallbackStarted, row.CallbackCompleted, row.CollectorUnlockStarted, row.CollectorReleased}
		for i := 1; i < len(order); i++ {
			if order[i] < order[i-1] {
				t.Fatalf("timing order reversed: %+v", row)
			}
		}
	}
	if missed != result.Missed {
		t.Fatal("missed offers lost from diagnostics")
	}
}

func TestVisitorTimingRejectsWrongCapacity(t *testing.T) {
	_, err := runVisitors(t.Context(), VisitorConfig{Rate: 2, Workers: 1, Duration: time.Second, Timing: &VisitorTimings{Requests: make([]VisitorRequestTiming, 1)}}, []string{"postgres"}, func(context.Context, string, time.Time) RequestResult {
		t.Fatal("request ran before timing capacity validation")
		return RequestResult{}
	})
	if err == nil {
		t.Fatal("accepted timing storage that would overflow")
	}
}

func TestVisitorTimingSeparatesQueryCompletionFromDeferredCleanup(t *testing.T) {
	timing := &VisitorTimings{Requests: make([]VisitorRequestTiming, 1)}
	cleanup := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := runVisitors(t.Context(), VisitorConfig{Rate: 1, Workers: 1, QueueSlots: 1, Start: time.Now().Add(-time.Second), Duration: time.Nanosecond, Timing: timing}, []string{"postgres"}, func(_ context.Context, url string, scheduled time.Time) (row RequestResult) {
			defer func() { close(cleanup); <-release }()
			started := time.Now()
			return RequestResult{URL: url, Scheduled: scheduled, Started: started, QueueDelay: started.Sub(scheduled), Duration: time.Since(scheduled)}
		})
		done <- err
	}()
	select {
	case <-cleanup:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("request did not reach deferred cleanup")
	}
	released := time.Now()
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	row := timing.Requests[0]
	boundary := released.Sub(timing.Start)
	if row.Completed > boundary || row.RequestReturned < boundary || row.RequestReturned < row.Completed {
		t.Fatalf("cleanup merged into query timing: %+v", row)
	}
}
