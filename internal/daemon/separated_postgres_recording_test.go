package daemon

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/benchworkload"
)

func TestPostgresRecordingBounds(t *testing.T) {
	for _, mode := range []string{"live", "buffered"} {
		for _, tc := range []struct {
			rate     int
			duration time.Duration
			want     int
		}{{2000, time.Minute, 120000}, {10000, 100 * time.Second, postgresLoadMaxSamples}, {1, time.Second + 1, 2}} {
			got, err := postgresRecordingSamples(mode, tc.rate, tc.duration)
			if err != nil || got != tc.want {
				t.Fatalf("%s: samples=%d err=%v", mode, got, err)
			}
		}
	}
	for _, tc := range []struct {
		mode     string
		rate     int
		duration time.Duration
	}{{"unknown", 1, time.Second}, {"live", 0, time.Second}, {"buffered", 10001, time.Second}, {"buffered", 10000, 100*time.Second + 1}, {"live", 1, 6 * time.Minute}} {
		if _, err := postgresRecordingSamples(tc.mode, tc.rate, tc.duration); err == nil {
			t.Fatalf("accepted %+v", tc)
		}
	}
	for _, limit := range []int{0, -1, postgresLoadMaxSamples + 1} {
		if _, err := newPostgresRecording("buffered", limit, io.Discard); err == nil {
			t.Fatalf("accepted limit %d", limit)
		}
	}
	if _, err := newPostgresRecording("unknown", 1, io.Discard); err == nil {
		t.Fatal("accepted unknown mode")
	}
	var partial bytes.Buffer
	r, err := newPostgresRecording("buffered", 1, &partial)
	if err != nil {
		t.Fatal(err)
	}
	r.Record(benchworkload.RequestResult{})
	r.Record(benchworkload.RequestResult{})
	if r.Flush() == nil || len(r.rows) != 1 || cap(r.rows) != 1 {
		t.Fatal("overflow silently accepted or storage grew")
	}
	var retained benchworkload.RequestResult
	if err := json.NewDecoder(&partial).Decode(&retained); err != nil {
		t.Fatalf("overflow discarded the retained failure artifact: %v", err)
	}
}

func TestPostgresRecordingPreservesEveryResult(t *testing.T) {
	var expected bytes.Buffer
	var summary benchworkload.VisitorResult
	rows := make([]benchworkload.RequestResult, 120)
	for i := range rows {
		now := time.Now()
		rows[i] = benchworkload.RequestResult{URL: "postgres", Scheduled: now, Started: now.Add(time.Microsecond), QueueDelay: time.Microsecond, Duration: 2 * time.Microsecond}
		if i == 7 {
			rows[i].Error, rows[i].Timeout = "test failure", true
		}
		if i == 9 {
			rows[i].QueueExpired, rows[i].Error = true, "queue expired"
		}
		summary.Observe(rows[i])
		if err := json.NewEncoder(&expected).Encode(rows[i]); err != nil {
			t.Fatal(err)
		}
	}
	for _, mode := range []string{"live", "buffered"} {
		t.Run(mode, func(t *testing.T) {
			var output bytes.Buffer
			r, err := newPostgresRecording(mode, len(rows), &output)
			if err != nil {
				t.Fatal(err)
			}
			var backing *benchworkload.RequestResult
			if mode == "buffered" {
				backing = &r.rows[:cap(r.rows)][0]
			}
			for _, row := range rows {
				r.Record(row)
			}
			if mode == "buffered" && (output.Len() != 0 || cap(r.rows) != len(rows) || &r.rows[0] != backing) {
				t.Fatal("buffered recording wrote early or reallocated")
			}
			if err := r.Flush(); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(output.Bytes(), expected.Bytes()) {
				t.Fatal("raw result data or order changed")
			}
			var got benchworkload.VisitorResult
			decoder := json.NewDecoder(&output)
			for range rows {
				var row benchworkload.RequestResult
				if err := decoder.Decode(&row); err != nil {
					t.Fatal(err)
				}
				got.Observe(row)
			}
			if got.Completed != summary.Completed || got.Failures != 1 || got.Timeouts != 1 || got.QueueExpired != 1 || got.Successes != summary.Successes {
				t.Fatalf("result accounting changed: %+v", got)
			}
		})
	}
}

type postgresBlockingWriter struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	bytes.Buffer
}

func (w *postgresBlockingWriter) Write(data []byte) (int, error) {
	w.once.Do(func() { close(w.entered); <-w.release })
	return w.Buffer.Write(data)
}

func TestPostgresRecordingBlockedWriteBoundary(t *testing.T) {
	for _, mode := range []string{"live", "buffered"} {
		t.Run(mode, func(t *testing.T) {
			w := &postgresBlockingWriter{entered: make(chan struct{}), release: make(chan struct{})}
			var release sync.Once
			defer release.Do(func() { close(w.release) })
			r, err := newPostgresRecording(mode, 1, w)
			if err != nil {
				t.Fatal(err)
			}
			// a completed row larger than the buffer deterministically reaches Write.
			row := benchworkload.RequestResult{URL: strings.Repeat("postgres", 700), Duration: time.Microsecond}
			recorded := make(chan struct{})
			go func() { r.Record(row); close(recorded) }()
			wait := func(ch <-chan struct{}) {
				t.Helper()
				select {
				case <-ch:
				case <-time.After(5 * time.Second):
					t.Fatal("recording boundary did not progress")
				}
			}
			if mode == "live" {
				wait(w.entered)
				select {
				case <-recorded:
					t.Fatal("live callback returned while its write was blocked")
				default:
				}
				release.Do(func() { close(w.release) })
				wait(recorded)
				if err := r.Flush(); err != nil {
					t.Fatal(err)
				}
			} else {
				wait(recorded)
				select {
				case <-w.entered:
					t.Fatal("buffered collection touched the writer")
				default:
				}
				flushed := make(chan error, 1)
				go func() { flushed <- r.Flush() }()
				wait(w.entered)
				release.Do(func() { close(w.release) })
				if err := <-flushed; err != nil {
					t.Fatal(err)
				}
			}
			var got benchworkload.RequestResult
			if err := json.NewDecoder(&w.Buffer).Decode(&got); err != nil || got.URL != row.URL || got.Duration != row.Duration {
				t.Fatalf("lost completed result: %v", err)
			}
		})
	}
}

type postgresErrorWriter struct{ err error }

func (w postgresErrorWriter) Write([]byte) (int, error) { return 0, w.err }

func TestPostgresRecordingWriteErrorsAndTimings(t *testing.T) {
	want := errors.New("test write failure")
	for _, mode := range []string{"live", "buffered"} {
		for _, timing := range []bool{false, true} {
			r, err := newPostgresRecording(mode, 1, postgresErrorWriter{want})
			if err != nil {
				t.Fatal(err)
			}
			if timing {
				r.enableTiming(1, postgresErrorWriter{want})
				r.timing.Visitor.Start = time.Now()
			}
			r.Record(benchworkload.RequestResult{URL: strings.Repeat("postgres", 700)})
			if err := r.Flush(); !errors.Is(err, want) {
				t.Fatalf("%s timing=%t swallowed error: %v", mode, timing, err)
			}
			if timing {
				if len(r.timing.Writes) != 1 {
					t.Fatalf("writes=%d", len(r.timing.Writes))
				}
				w := r.timing.Writes[0]
				if !w.Failed || w.DuringRun != (mode == "live") || w.Completed < w.Started || w.ResultIndex != 1 {
					t.Fatalf("wrong write timing: %+v", w)
				}
			}
		}
	}
	w := &postgresRecordingTiming{output: io.Discard}
	if _, err := w.Write([]byte("overflow")); err == nil {
		t.Fatal("timing overflow did not fail")
	}
}
