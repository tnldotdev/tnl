package benchworkload

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/publisher"
)

func TestActivationTimeoutRetainsPartialSuccessAndCapturesBeforeCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		var captured bool
		failedIndex := -1
		group := &Publishers{ctx: ctx, cancel: cancel, namespace: "test", failures: make(chan error, 1), config: PublisherConfig{Parallel: 1, ReadyTimeout: 30 * time.Second, StopTimeout: 10 * time.Second, OnFailure: func() {
			if ctx.Err() != nil {
				t.Error("canceled before failure snapshot")
			}
			captured = true
		}, OnActivationFailure: func(index int) {
			if ctx.Err() != nil {
				t.Error("canceled before failed publisher was identified")
			}
			failedIndex = index
		}}}
		group.run = func(ctx context.Context, c publisher.Config) error {
			if strings.Contains(c.Hostname, "r000000") {
				_ = c.Observe(publisher.Event{Type: publisher.EventReady})
			}
			<-ctx.Done()
			return ctx.Err()
		}
		started := time.Now()
		ready, err := group.Start(t.Context(), []int{0, 1, 2})
		if err == nil || len(ready) != 1 || len(group.processes) != 2 || !captured || failedIndex != 1 || time.Since(started) != 30*time.Second {
			t.Fatalf("partial activation: ready=%v started=%d captured=%t failed_index=%d err=%v", ready, len(group.processes), captured, failedIndex, err)
		}
		if _, err := group.Stop(t.Context(), []int{0, 1}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestStopBoundsConcurrencyAndPreservesJoinedErrors(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var active, peak, captures atomic.Int64
		group := &Publishers{config: PublisherConfig{Parallel: 2, StopTimeout: 10 * time.Second, OnFailure: func() { captures.Add(1) }}}
		failure := errors.New("close failed")
		for i := range 6 {
			ctx, cancel := context.WithCancel(t.Context())
			p := &publicURLProcess{index: i, cancel: cancel, done: make(chan struct{})}
			group.processes = append(group.processes, p)
			go func() {
				<-ctx.Done()
				current := active.Add(1)
				for old := peak.Load(); old < current; old = peak.Load() {
					if peak.CompareAndSwap(old, current) {
						break
					}
				}
				time.Sleep(time.Duration(i+1) * time.Second)
				active.Add(-1)
				p.err = context.Canceled
				if i == 2 || i == 3 {
					p.err = errors.Join(p.err, failure)
				}
				close(p.done)
			}()
		}
		at := time.Now()
		timings, err := group.Stop(t.Context(), []int{0, 1, 2, 3, 4, 5})
		var total time.Duration
		for _, value := range timings.Timings {
			total += value
		}
		if !errors.Is(err, failure) || peak.Load() != 2 || captures.Load() != 1 || total != 21*time.Second || time.Since(at) != 12*time.Second || timings.Successes != 4 || timings.Failures != 2 {
			t.Fatalf("stop: timings=%v peak=%d snapshots=%d err=%v", timings, peak.Load(), captures.Load(), err)
		}
	})
}

func TestStopDeadlineStillCancelsQueuedPublicURLs(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		var canceled atomic.Int64
		group := &Publishers{config: PublisherConfig{Parallel: 2, StopTimeout: 10 * time.Second}}
		for i := range 6 {
			group.processes = append(group.processes, &publicURLProcess{index: i, cancel: func() { canceled.Add(1) }, done: make(chan struct{})})
		}
		at := time.Now()
		_, err := group.Stop(ctx, []int{0, 1, 2, 3, 4, 5})
		if !errors.Is(err, context.DeadlineExceeded) || canceled.Load() != 6 || time.Since(at) != time.Second {
			t.Fatalf("stop: canceled=%d err=%v", canceled.Load(), err)
		}
	})
}
