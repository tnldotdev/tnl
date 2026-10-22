package serviceaudit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func observation() Observation {
	return Observation{EventID: NewID(), ServiceID: "url_0123456789ABCDEFGHIJKL", ServiceKind: "public_url", RunID: "pr_0123456789ABCDEFGHIJKL", RunNumber: 1, VisitorConnectionID: "vc_0123456789ABCDEFGHIJKL", SourceIP: "192.0.2.1", EventType: "http.decision", OccurredAt: time.Now().UTC(), Outcome: "allowed"}
}

func TestQueueBoundsIncludeInFlightAndJoinedShutdown(t *testing.T) {
	started := make(chan struct{})
	dropped := make(chan uint64, 1)
	q, err := NewQueue(t.Context(), QueueConfig{Capacity: 2, BatchSize: 1, Report: func(ctx context.Context, _ Batch) error {
		select {
		case <-started:
		default:
			close(started)
		}
		<-ctx.Done()
		return ctx.Err()
	}, Dropped: func(n uint64) { dropped <- n }})
	if err != nil {
		t.Fatal(err)
	}
	if !q.Observe(observation()) {
		t.Fatal("first event rejected")
	}
	<-started
	if !q.Observe(observation()) || q.Observe(observation()) {
		t.Fatal("in-flight event did not count toward capacity")
	}
	if n, b := q.Pending(); n != 2 || b <= 0 {
		t.Fatalf("pending=%d,%d", n, b)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err = q.Close(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	var total uint64
	for {
		select {
		case n := <-dropped:
			total += n
		default:
			if total != 3 {
				t.Fatalf("dropped=%d", total)
			}
			if n, b := q.Pending(); n != 0 || b != 0 {
				t.Fatal("shutdown retained memory")
			}
			return
		}
	}
}

func TestQueueRetriesStableIDsAndFlushesOnClose(t *testing.T) {
	var mu sync.Mutex
	var batches []Batch
	q, err := NewQueue(t.Context(), QueueConfig{BatchSize: 2, FlushInterval: time.Hour, RetryMin: time.Millisecond, RetryMax: time.Millisecond, Report: func(_ context.Context, b Batch) error {
		mu.Lock()
		defer mu.Unlock()
		batches = append(batches, b)
		if len(batches) == 1 {
			return errors.New("retry")
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	o := observation()
	q.Observe(o)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err = q.Close(ctx); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(batches) != 2 || len(batches[0].Events) != 1 || batches[0].Events[0] != batches[1].Events[0] {
		t.Fatalf("unstable retry: %+v", batches)
	}
	if q.Observe(observation()) {
		t.Fatal("accepted event after close")
	}
}

func TestQueuePayloadBoundAndUnsafeFields(t *testing.T) {
	q, err := NewQueue(t.Context(), QueueConfig{Capacity: 100, MaxBytes: 2048, BatchSize: 100, FlushInterval: time.Hour, Report: func(context.Context, Batch) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	for range 20 {
		q.Observe(observation())
	}
	if n, b := q.Pending(); n >= 20 || b > 2048 {
		t.Fatalf("unbounded queue %d/%d", n, b)
	}
	for _, secret := range []string{"Bearer secret", "-----BEGIN PRIVATE KEY-----", "/oauth?token=secret", "SELECT password FROM users", "ssh root@host command"} {
		o := observation()
		o.Reason = secret
		if o.Validate() == nil || q.Observe(o) {
			t.Fatal("accepted arbitrary audit reason")
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err = q.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPReporterDoesNotExposeSecretsInErrors(t *testing.T) {
	const secret = "never-log-this-token-or-body"
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+secret {
			t.Error("missing authentication")
		}
		http.Error(w, secret, http.StatusServiceUnavailable)
	}))
	defer s.Close()
	report := HTTPReporter(s.Client(), func(context.Context) (Destination, error) {
		return Destination{URL: s.URL + "/" + secret, Bearer: secret, PublishRunNumber: 1}, nil
	})
	err := report(t.Context(), Batch{Events: []Observation{observation()}})
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("unsafe reporter error: %v", err)
	}
}

func TestParentCancellationFlushesAndJoins(t *testing.T) {
	parent, cancel := context.WithCancel(t.Context())
	reported := make(chan Batch, 1)
	q, err := NewQueue(parent, QueueConfig{FlushInterval: time.Hour, Report: func(ctx context.Context, b Batch) error {
		if ctx.Err() != nil {
			t.Error("flush inherited cancelled lifecycle")
		}
		reported <- b
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	q.Observe(observation())
	cancel()
	ctx, stop := context.WithTimeout(t.Context(), time.Second)
	defer stop()
	if err = q.Close(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case b := <-reported:
		if len(b.Events) != 1 {
			t.Fatal("lost shutdown batch")
		}
	default:
		t.Fatal("cancellation discarded accepted event")
	}
}

func TestShutdownHasIndependentBoundAndPermanentRejectionsDrop(t *testing.T) {
	q, err := NewQueue(t.Context(), QueueConfig{ShutdownTimeout: 20 * time.Millisecond, RetryMin: time.Millisecond, RetryMax: time.Millisecond, Report: func(ctx context.Context, _ Batch) error { <-ctx.Done(); return ctx.Err() }})
	if err != nil {
		t.Fatal(err)
	}
	q.Observe(observation())
	if err = q.Close(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unbounded shutdown result %v", err)
	}
	if n, _ := q.Pending(); n != 0 {
		t.Fatal("shutdown retained accepted memory")
	}
	var dropped uint64
	q, err = NewQueue(t.Context(), QueueConfig{Report: func(context.Context, Batch) error { return ErrRejected }, Dropped: func(n uint64) { dropped += n }})
	if err != nil {
		t.Fatal(err)
	}
	q.Observe(observation())
	if err = q.Close(t.Context()); err != nil || dropped != 1 {
		t.Fatalf("permanent batch retried or disappeared: %d %v", dropped, err)
	}
}

func TestHTTPReporterRequiresAcknowledgementForEveryEvent(t *testing.T) {
	for _, body := range []string{`{}`, `{"accepted":0,"duplicates":0}`, `{"accepted":1,"duplicates":0} trailing`, `{"accepted":-1,"duplicates":2}`} {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }))
		report := HTTPReporter(s.Client(), func(context.Context) (Destination, error) { return Destination{URL: s.URL}, nil })
		if err := report(t.Context(), Batch{Events: []Observation{observation()}}); err == nil || errors.Is(err, ErrRejected) {
			t.Errorf("false acknowledgement: %s", body)
		}
		s.Close()
	}
}

func TestQueueIsolatesPermanentRejectionAndRetriesStableAcknowledgements(t *testing.T) {
	for _, badIndex := range []int{0, 2, 4} {
		t.Run(fmt.Sprint(badIndex), func(t *testing.T) {
			events := make([]Observation, 5)
			for i := range events {
				events[i] = observation()
			}
			badID := events[badIndex].EventID
			stored := map[string]Observation{}
			calls, duplicateAcks, invalidSingletons := 0, 0, 0
			ambiguous := true
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				var batch Batch
				if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
					t.Error(err)
					w.WriteHeader(500)
					return
				}
				for _, o := range batch.Events {
					if o.EventID == badID {
						if len(batch.Events) == 1 {
							invalidSingletons++
						}
						w.WriteHeader(403)
						return
					}
				}
				accepted, duplicates := 0, 0
				for _, o := range batch.Events {
					if previous, ok := stored[o.EventID]; ok {
						if previous != o {
							t.Error("retry changed event facts")
						}
						duplicates++
					} else {
						stored[o.EventID] = o
						accepted++
					}
				}
				if ambiguous {
					ambiguous = false
					// commit succeeded but the response was lost. the next
					// acknowledgement must classify these as duplicates.
					w.WriteHeader(503)
					return
				}
				duplicateAcks += duplicates
				_ = json.NewEncoder(w).Encode(map[string]int{"accepted": accepted, "duplicates": duplicates})
			}))
			defer s.Close()
			var dropped uint64
			q, err := NewQueue(t.Context(), QueueConfig{FlushInterval: time.Hour, BatchSize: MaxBatch,
				RetryMin: time.Millisecond, RetryMax: time.Millisecond,
				Dropped: func(n uint64) { dropped += n },
				Report:  HTTPReporter(s.Client(), func(context.Context) (Destination, error) { return Destination{URL: s.URL}, nil })})
			if err != nil {
				t.Fatal(err)
			}
			for _, o := range events {
				if !q.Observe(o) {
					t.Fatal("queue rejected valid syntax")
				}
			}
			if err = q.Close(t.Context()); err != nil {
				t.Fatal(err)
			}
			s.Close()
			if len(stored) != len(events)-1 || dropped != 1 || invalidSingletons != 1 || duplicateAcks < 1 || calls > 2*len(events) {
				t.Fatalf("isolation/ack counts stored=%d dropped=%d rejected=%d duplicates=%d calls=%d", len(stored), dropped, invalidSingletons, duplicateAcks, calls)
			}
			if n, b := q.Pending(); n != 0 || b != 0 {
				t.Fatalf("split retained memory: %d/%d", n, b)
			}
		})
	}
}

func TestQueueRetryBudgetLetsLaterEventsProgress(t *testing.T) {
	bad, good := observation(), observation()
	calls := map[string]int{}
	var dropped uint64
	q, err := NewQueue(t.Context(), QueueConfig{BatchSize: 1, MaxAttempts: 3, RetryMin: time.Millisecond, RetryMax: time.Millisecond,
		Report: func(_ context.Context, b Batch) error {
			id := b.Events[0].EventID
			calls[id]++
			if id == bad.EventID {
				return errors.New("transient failure")
			}
			return nil
		}, Dropped: func(n uint64) { dropped += n }})
	if err != nil {
		t.Fatal(err)
	}
	q.Observe(bad)
	q.Observe(good)
	if err = q.Close(t.Context()); err != nil || calls[bad.EventID] != 3 || calls[good.EventID] != 1 || dropped != 1 {
		t.Fatalf("queue starved after retries: calls=%v dropped=%d err=%v", calls, dropped, err)
	}
}

func TestHTTPReporterRejectionClassification(t *testing.T) {
	for _, status := range []int{400, 401, 403, 404, 409, 410, 413, 429, 500, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }))
			defer s.Close()
			err := HTTPReporter(s.Client(), func(context.Context) (Destination, error) { return Destination{URL: s.URL}, nil })(t.Context(), Batch{Events: []Observation{observation()}})
			permanent := status < 429
			if err == nil || errors.Is(err, ErrRejected) != permanent {
				t.Fatalf("status %d: %v", status, err)
			}
		})
	}
}

func TestQueueAllRejectedPartitionsAreBounded(t *testing.T) {
	calls := 0
	var dropped uint64
	q, err := NewQueue(t.Context(), QueueConfig{FlushInterval: time.Hour, Report: func(context.Context, Batch) error {
		calls++
		return ErrRejected
	}, Dropped: func(n uint64) { dropped += n }})
	if err != nil {
		t.Fatal(err)
	}
	for range MaxBatch {
		if !q.Observe(observation()) {
			t.Fatal("queue rejected valid syntax")
		}
	}
	if err = q.Close(t.Context()); err != nil || calls != 2*MaxBatch-1 || dropped != MaxBatch {
		t.Fatalf("rejection partitions were not bounded: calls=%d dropped=%d %v", calls, dropped, err)
	}
}
