package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime/trace"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

var postgresLateTestChild = flag.String("tnl-postgres-late-test-child", "", "isolated late-diagnostic recorder test")

func TestPostgresLateValidation(t *testing.T) {
	for _, tc := range []struct {
		workload, mode string
		timing, valid  bool
	}{
		{"postgres", "off", false, true},
		{"public-url", "off", false, true},
		{"postgres", "sample", true, true},
		{"postgres", "trace", true, true},
		{"postgres", "sample", false, false},
		{"postgres", "trace", false, false},
		{"connect", "sample", true, false},
		{"postgres", "unknown", true, false},
	} {
		if err := validatePostgresLateDiagnostics(tc.workload, tc.timing, tc.mode); (err == nil) != tc.valid {
			t.Fatalf("%+v: %v", tc, err)
		}
	}
}

func TestPostgresLateTargetObserverAbortedSetup(t *testing.T) {
	var queries, closes int
	sampler := newPostgresTargetSampler(func(context.Context) (string, []postgresTargetActivity, error) {
		queries++
		t.Error("aborted setup must not sample")
		return "", nil, nil
	}, func(ctx context.Context) error {
		closes++
		if _, bounded := ctx.Deadline(); !bounded {
			t.Error("observer cleanup must be bounded before Start too")
		}
		return nil
	})
	directory := filepath.Join(t.TempDir(), "target-aborted")
	if err := sampler.Finish(directory); err != nil {
		t.Fatal(err)
	}
	if err := sampler.Finish(directory); err != nil || queries != 0 || closes != 1 {
		t.Fatalf("aborted observer cleanup: queries=%d closes=%d error=%v", queries, closes, err)
	}
}

func TestPostgresLateOff(t *testing.T) {
	if flag.Lookup("tnl-postgres-load-late-diagnostics").DefValue != "off" {
		t.Fatal("diagnostics must default to off")
	}
	d := startPostgresLateDiagnostic(t.Context(), postgresLateConfig{Mode: "off"})
	if d != nil {
		t.Fatal("off must not allocate a diagnostic")
	}
	d.Observe(0, 0, time.Second, 0, time.Second)
	if err := d.Finish(filepath.Join(t.TempDir(), "unused")); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresLateProcessParser(t *testing.T) {
	fields := strings.Fields("R 0 0 0 0 0 0 0 0 0 0 101 202 0 0 0 0 7 0 999")
	fixture := "123 (worker ) name () " + strings.Join(fields, " ")
	p, err := parsePostgresLateProcess(fixture)
	if err != nil || p != (postgresLateProcess{PID: 123, UserTicks: 101, SystemTicks: 202, Threads: 7, StartTimeTicks: 999}) {
		t.Fatalf("process=%+v error=%v", p, err)
	}
	for _, text := range []string{"", "123 worker", "123 (worker) R", strings.Replace(fixture, "101", "bad", 1), strings.Replace(fixture, "123", "bad", 1)} {
		if _, err := parsePostgresLateProcess(text); err == nil {
			t.Fatalf("accepted malformed process stat %q", text)
		}
	}
}

func TestPostgresLateCounterParser(t *testing.T) {
	for _, test := range []struct {
		text string
		want map[string]uint64
	}{
		{"usage_usec 12\nthrottled_usec 4\nnr_throttled 2\n", map[string]uint64{"usage_usec": 12, "throttled_usec": 4, "nr_throttled": 2}},
		{"max 3\noom 0\n", map[string]uint64{"max": 3, "oom": 0}},
		{"some avg10=0.12 avg60=0.02 avg300=0.00 total=17\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=2\n", map[string]uint64{"some_total_usec": 17, "full_total_usec": 2}},
	} {
		got, err := parsePostgresLateCounters(test.text)
		if err != nil || !reflect.DeepEqual(got, test.want) {
			t.Fatalf("counters=%v error=%v want=%v", got, err, test.want)
		}
	}
	for _, text := range []string{"", "usage_usec", "usage_usec bad", "usage_usec -1", "usage_usec 1 extra", "some avg10=0.00"} {
		if _, err := parsePostgresLateCounters(text); err == nil {
			t.Fatalf("accepted malformed counters %q", text)
		}
	}
}

func TestPostgresLateWriterBound(t *testing.T) {
	w := &postgresLateWriter{data: make([]byte, 5)}
	if n, err := w.Write([]byte("abc")); n != 3 || err != nil {
		t.Fatalf("first write=%d %v", n, err)
	}
	if n, err := w.Write([]byte("def")); n != 2 || !errors.Is(err, errPostgresLateTraceLimit) {
		t.Fatalf("bounded write=%d %v", n, err)
	}
	if string(w.data) != "abcde" || w.used != 5 || cap(w.data) != 5 {
		t.Fatalf("writer grew or discarded partial output: %+v", w)
	}
	if n, err := w.Write([]byte("x")); n != 0 || !errors.Is(err, errPostgresLateTraceLimit) {
		t.Fatalf("full write=%d %v", n, err)
	}
	if n, err := w.Write(nil); n != 0 || err != nil {
		t.Fatalf("empty write=%d %v", n, err)
	}
}

func TestPostgresLateTrigger(t *testing.T) {
	newDiagnostic := func() *postgresLateDiagnostic {
		return &postgresLateDiagnostic{cfg: postgresLateConfig{Start: time.Now().Add(-10 * time.Second)}, trigger: make(chan postgresLateTrigger, 1)}
	}
	d := newDiagnostic()
	d.Observe(1, time.Second, 3*time.Second, 0, 0)
	d.Observe(2, 2*time.Second, 2*time.Second+25*time.Millisecond, 0, 0)
	if d.claimed.Load() {
		t.Fatal("warm-up or exact-threshold event triggered")
	}
	var workers sync.WaitGroup
	for slot := range 32 {
		workers.Go(func() { d.Observe(slot, 3*time.Second, 3*time.Second+26*time.Millisecond, 0, 0) })
	}
	workers.Wait()
	if len(d.trigger) != 1 {
		t.Fatalf("got %d triggers", len(d.trigger))
	}
	e := <-d.trigger
	if e.Kind != "query" || e.TriggerLag != e.Observed-e.Completed || e.TriggerLag < 0 || e.MarkerEmitted {
		t.Fatalf("invalid trigger: %+v", e)
	}
	d = newDiagnostic()
	d.Observe(7, 3*time.Second, 3*time.Second+time.Millisecond, 4*time.Second, 4*time.Second+26*time.Millisecond)
	if e := <-d.trigger; e.Kind != "callback" || e.Slot != 7 {
		t.Fatalf("invalid callback trigger: %+v", e)
	}
}

func TestPostgresLateSamplerCancellationAndReceipt(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	d := startPostgresLateDiagnostic(ctx, postgresLateConfig{Mode: "sample", Start: time.Now().Add(time.Hour), Duration: time.Minute})
	directory := filepath.Join(t.TempDir(), "diagnostics")
	if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("wrote before Finish: %v", err)
	}
	cancel()
	if err := d.Finish(directory); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error=%v", err)
	}
	for _, done := range []chan struct{}{d.sampleDone, d.traceDone} {
		select {
		case <-done:
		default:
			t.Fatal("Finish did not join its goroutines")
		}
	}
	r := readPostgresLateReceipt(t, directory)
	if !r.Cancelled || r.SampleCount != 0 || r.Error == "" || r.SampleLimit < 650 {
		t.Fatalf("receipt=%+v", r)
	}
	if err := d.Finish(directory); !errors.Is(err, context.Canceled) {
		t.Fatalf("Finish not idempotent: %v", err)
	}
	for _, path := range []string{directory, filepath.Join(directory, "receipt.json"), filepath.Join(directory, "samples.json")} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("artifact not private: %s %v", path, err)
		}
	}
}

func TestPostgresLateCounterFailures(t *testing.T) {
	d := startPostgresLateDiagnostic(t.Context(), postgresLateConfig{Mode: "sample", Start: time.Now().Add(time.Hour), Duration: time.Minute})
	root := t.TempDir()
	if got := d.counters(filepath.Join(root, "unsupported")); got != nil {
		t.Fatalf("missing optional interface: %v", got)
	}
	bad := filepath.Join(root, "malformed")
	if err := os.WriteFile(bad, []byte("usage_usec not-a-number\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for range 20 {
		d.counters(bad)
	}
	d.fail(errors.New("separate capture failure"))
	directory := filepath.Join(root, "diagnostics")
	if err := d.Finish(directory); err == nil {
		t.Fatal("counter failures must fail requested diagnostics")
	}
	r := readPostgresLateReceipt(t, directory)
	if !strings.Contains(r.Error, "invalid counter value") || !strings.Contains(r.Error, "separate capture failure") || len(r.Issues) != 2 || len(r.Notes) != 5 {
		t.Fatalf("failure receipt=%+v", r)
	}
}

func TestPostgresLateInvalidConfig(t *testing.T) {
	for _, cfg := range []postgresLateConfig{{Mode: "unknown"}, {Mode: "sample"}, {Mode: "sample", Start: time.Now(), Duration: 6 * time.Minute}} {
		d := startPostgresLateDiagnostic(t.Context(), cfg)
		directory := filepath.Join(t.TempDir(), "diagnostics")
		if err := d.Finish(directory); err == nil {
			t.Fatal("invalid config succeeded")
		}
		if r := readPostgresLateReceipt(t, directory); r.Error == "" {
			t.Fatal("invalid config lost its receipt")
		}
	}
}

func TestPostgresLateNotify(t *testing.T) {
	for _, mode := range []string{"completed", "failed", "cancelled", "deadline-exceeded", "no-event"} {
		t.Run(mode, func(t *testing.T) {
			type notifyKey struct{}
			ctx, cancel := context.WithTimeout(context.WithValue(t.Context(), notifyKey{}, "parent-value"), 5*time.Second)
			defer cancel()
			notifyFailure := errors.New("synthetic notification failure")
			calls := make(chan postgresLateTrigger, 1)
			release := make(chan struct{})
			cfg := postgresLateConfig{Mode: "sample", Start: time.Now().Add(time.Hour), Duration: time.Minute, Notify: func(ctx context.Context, e postgresLateTrigger) error {
				if _, ok := ctx.Deadline(); !ok || ctx.Value(notifyKey{}) != "parent-value" {
					return errors.New("notification lost its deadline or parent context")
				}
				calls <- e
				select {
				case <-ctx.Done():
					// even a nil callback result cannot erase context cancellation.
					return nil
				case <-release:
					if mode == "failed" {
						return notifyFailure
					}
					return nil
				}
			}}
			d := startPostgresLateDiagnostic(ctx, cfg)
			var notified postgresLateTrigger
			if mode != "no-event" {
				workerDone := make(chan struct{})
				go func() {
					d.Observe(31, 3*time.Second, 3*time.Second+26*time.Millisecond, 0, 0)
					close(workerDone)
				}()
				select {
				case <-workerDone:
				case <-time.After(time.Second):
					t.Fatal("Observe waited for the notification callback")
				}
				select {
				case notified = <-calls:
				case <-time.After(time.Second):
					t.Fatal("capture did not begin notification promptly")
				}
				switch mode {
				case "completed", "failed":
					close(release)
				case "cancelled":
					cancel()
				}
			}
			directory := filepath.Join(t.TempDir(), "diagnostics")
			err := d.Finish(directory)
			r := readPostgresLateReceipt(t, directory)
			wantStatus := mode
			var wantErr error
			switch mode {
			case "no-event":
				wantStatus = "not-requested"
			case "failed":
				wantErr = notifyFailure
			case "cancelled":
				wantErr = context.Canceled
			case "deadline-exceeded":
				wantErr = context.DeadlineExceeded
			}
			if !errors.Is(err, wantErr) || r.NotifyStatus != wantStatus || r.Cancelled != (mode == "cancelled") || len(calls) != 0 {
				t.Fatalf("notification error=%v receipt=%+v", err, r)
			}
			if mode == "no-event" {
				if r.Trigger != nil || r.NotifyTimeout != 0 || r.NotifyStarted != 0 || r.NotifyCompleted != 0 {
					t.Fatalf("idle capture invoked notification: %+v", r)
				}
			} else if r.Trigger == nil || *r.Trigger != notified || r.NotifyTimeout != postgresLateNotifyTimeout || r.NotifyDeadline-r.NotifyStarted > postgresLateNotifyTimeout || r.NotifyDeadline <= r.NotifyStarted || r.NotifyStarted < notified.Observed || r.NotifyCompleted < r.NotifyStarted || (wantErr != nil && !strings.Contains(r.Error, "notify late-diagnostic trigger")) {
				t.Fatalf("notification lost event, bounds, or failure receipt: %+v", r)
			}
			data, err := os.ReadFile(filepath.Join(directory, "receipt.json"))
			if err != nil || strings.Contains(string(data), `"Notify":`) || r.Config.Notify != nil {
				t.Fatalf("callback leaked into receipt config: %v\n%s", err, data)
			}
		})
	}
}

func TestPostgresLateFlightRecorder(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"capture", "callback", "cancelled-tail", "cancelled-pending", "notify-failed", "bounded-output", "no-event", "start-failed"} {
		t.Run(mode, func(t *testing.T) {
			// do not inherit -test.trace: the child owns its real flight recorder.
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestPostgresLateFlightRecorderChild$", "-test.count=1", "-tnl-postgres-late-test-child="+mode)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("isolated recorder: %v\n%s", err, output)
			}
		})
	}
}

func TestPostgresLateFlightRecorderChild(t *testing.T) {
	if *postgresLateTestChild == "" {
		t.Skip("only run in an isolated subprocess")
	}
	mode := *postgresLateTestChild
	if mode == "start-failed" {
		other := trace.NewFlightRecorder(trace.FlightRecorderConfig{})
		if err := other.Start(); err != nil {
			t.Fatal(err)
		}
		defer other.Stop()
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	cfg := postgresLateConfig{Phase: "near-phase-end", Mode: "trace", Start: time.Now().Add(-3*time.Second - 50*time.Millisecond), Duration: 3*time.Second + 100*time.Millisecond}
	if mode == "no-event" || mode == "start-failed" {
		// a future epoch isolates startup/idle checks from platform proc support.
		cfg.Start, cfg.Duration = time.Now().Add(time.Hour), time.Minute
	}
	notifyFailure := errors.New("synthetic trigger notification failed")
	notifyCalls := make(chan postgresLateTrigger, 1)
	if mode == "capture" || mode == "cancelled-tail" || mode == "cancelled-pending" || mode == "notify-failed" {
		cfg.Notify = func(ctx context.Context, e postgresLateTrigger) error {
			trace.Log(context.Background(), "postgres-late-test-notify", "slot=17")
			notifyCalls <- e
			if mode == "cancelled-tail" {
				<-ctx.Done()
				return ctx.Err()
			}
			if mode == "notify-failed" {
				return notifyFailure
			}
			return ctx.Err()
		}
	}
	d := startPostgresLateDiagnostic(ctx, cfg)
	if mode == "bounded-output" {
		// shrink before publishing an event; capture cannot access the buffer yet.
		d.traceBytes = d.traceBytes[:64:64]
	}
	if mode != "no-event" {
		var workers sync.WaitGroup
		workers.Go(func() {
			trace.Log(context.Background(), "postgres-late-test-worker", "slot=17")
			if mode == "cancelled-pending" {
				// cancellation before enqueue must not make capture discard the winner.
				cancel()
			}
			if mode == "callback" {
				d.Observe(17, 3*time.Second, 3*time.Second+time.Millisecond, 3*time.Second, 3*time.Second+26*time.Millisecond)
			} else {
				d.Observe(17, 3*time.Second, 3*time.Second+26*time.Millisecond, 0, 0)
			}
			if mode == "capture" || mode == "callback" || mode == "cancelled-tail" || mode == "notify-failed" {
				// the synthetic episode ends after the nominal phase boundary. Run
				// would join this worker before Finish, which must retain the tail.
				timer := time.NewTimer(75 * time.Millisecond)
				<-timer.C
				trace.Log(context.Background(), "postgres-late-test-episode-end", "slot=17")
				if mode == "cancelled-tail" {
					cancel()
				}
			}
		})
		workers.Wait()
	}
	directory := filepath.Join(t.TempDir(), "diagnostics")
	finishStarted := time.Now()
	err := d.Finish(directory)
	finishDuration := time.Since(finishStarted)
	r := readPostgresLateReceipt(t, directory)
	for _, done := range []chan struct{}{d.sampleDone, d.traceDone} {
		select {
		case <-done:
		default:
			t.Fatal("Finish did not join a diagnostic owner")
		}
	}
	if d.samples != nil || d.traceBytes != nil {
		t.Fatal("Finish retained diagnostic buffers")
	}
	if cfg.Notify != nil {
		wantStatus := "completed"
		if mode == "notify-failed" {
			wantStatus = "failed"
		} else if strings.HasPrefix(mode, "cancelled-") {
			wantStatus = "cancelled"
		}
		if len(notifyCalls) != 1 || r.Trigger == nil || <-notifyCalls != *r.Trigger || r.NotifyStatus != wantStatus || r.NotifyTimeout != postgresLateNotifyTimeout || r.NotifyStarted < r.Trigger.Observed || r.NotifyCompleted < r.NotifyStarted || r.NotifyCompleted > r.PostTriggerCompleted || r.NotifyCompleted > r.SnapshotStarted || r.NotifyStarted >= r.Trigger.Observed+postgresLatePostTrigger {
			t.Fatalf("notification was late, lost its event, or skipped the local capture: %+v", r)
		}
	} else if r.NotifyStatus != "not-requested" || r.NotifyTimeout != 0 {
		t.Fatalf("notification was not optional: %+v", r)
	}
	switch mode {
	case "capture", "callback", "cancelled-tail", "cancelled-pending", "notify-failed":
		cancelled := strings.HasPrefix(mode, "cancelled-")
		wantStatus, wantTailStatus, wantFile := "captured", "completed", "visitor.trace"
		if cancelled {
			wantStatus, wantTailStatus, wantFile = "captured-partial", "cancelled", "visitor.trace.partial"
		}
		if (err != nil) != (cancelled || mode == "notify-failed") || (cancelled && !errors.Is(err, context.Canceled)) || (mode == "notify-failed" && !errors.Is(err, notifyFailure)) || r.Cancelled != cancelled || r.TracePartial != cancelled || r.TraceStatus != wantStatus || r.TraceFile != wantFile || r.Trigger == nil || r.Trigger.Slot != 17 || r.TraceBytes == 0 || r.TraceBytes > postgresLateTraceLimit || r.SnapshotCompleted < r.SnapshotStarted {
			t.Fatalf("capture error=%v receipt=%+v", err, r)
		}
		e := r.Trigger
		if r.PostTriggerRequested != postgresLatePostTrigger || r.PostTriggerStarted != e.Observed || r.PostTriggerDeadline != e.Observed+postgresLatePostTrigger || r.PostTriggerActual != r.PostTriggerCompleted-e.Observed || r.PostTriggerStatus != wantTailStatus || r.SnapshotStarted < r.PostTriggerCompleted || !e.MarkerEmitted || r.MarkerStarted != e.MarkerStarted || r.MarkerCompleted != e.MarkerCompleted || r.MarkerStarted < e.Observed || r.MarkerCompleted < r.MarkerStarted || !strings.Contains(r.MarkerStatus, "unverified") || !strings.Contains(r.Coverage, "unverified") {
			t.Fatalf("invalid capture bounds or marker receipt: %+v", r)
		}
		if cancelled {
			if r.PostTriggerActual >= postgresLatePostTrigger || finishDuration >= postgresLatePostTrigger {
				t.Fatalf("cancellation did not shorten tail: Finish=%s receipt=%+v", finishDuration, r)
			}
		} else if r.PostTriggerActual < postgresLatePostTrigger || r.SnapshotStarted < r.PostTriggerDeadline || r.MarkerCompleted >= cfg.Duration || r.PostTriggerCompleted <= cfg.Duration {
			t.Fatalf("normal phase end cut short capture: %+v", r)
		}
		logs := readPostgresLateTraceLogs(t, filepath.Join(directory, r.TraceFile))
		worker, winner := logs["postgres-late-test-worker"], logs["postgres-late-outlier"]
		if len(worker) != 1 || len(winner) != 1 || worker[0].Goroutine != winner[0].Goroutine || winner[0].Task != 0 || worker[0].Time >= winner[0].Time {
			t.Fatalf("winner was not on the actual worker GoID without a new task: worker=%+v winner=%+v", worker, winner)
		}
		if cfg.Notify != nil {
			notified := logs["postgres-late-test-notify"]
			if len(notified) != 1 || notified[0].Goroutine == winner[0].Goroutine || notified[0].Time <= winner[0].Time {
				t.Fatalf("notification was not on the background capture owner: winner=%+v notification=%+v", winner, notified)
			}
		}
		wantKind := "query"
		if mode == "callback" {
			wantKind = "callback"
		}
		wantMessage := fmt.Sprintf("phase=%s slot=17 kind=%s started_ns=%d completed_ns=%d observed_ns=%d marker_ns=%d", cfg.Phase, wantKind, e.Started, e.Completed, e.Observed, e.MarkerStarted)
		if e.Kind != wantKind || winner[0].Message != wantMessage {
			t.Fatalf("winner lost exact slot/kind/phase offsets: %+v want=%q", winner, wantMessage)
		}
		if mode != "cancelled-pending" {
			end := logs["postgres-late-test-episode-end"]
			if len(end) != 1 || end[0].Goroutine != winner[0].Goroutine || end[0].Time-winner[0].Time < int64(50*time.Millisecond) {
				t.Fatalf("real recorder missed the post-trigger episode end: winner=%+v end=%+v", winner, end)
			}
		}
	case "bounded-output":
		if !errors.Is(err, errPostgresLateTraceLimit) || r.TraceStatus != "capture-failed" || !r.TracePartial || r.TraceFile != "visitor.trace.partial" || r.TraceBytes != 64 || r.PostTriggerStatus != "completed" || r.PostTriggerActual < postgresLatePostTrigger {
			t.Fatalf("bounded capture error=%v receipt=%+v", err, r)
		}
		info, err := os.Stat(filepath.Join(directory, r.TraceFile))
		if err != nil || info.Size() != 64 || info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("bounded partial artifact: %v %v", info, err)
		}
	case "no-event":
		if err != nil || r.TraceStatus != "no-event" || r.Trigger != nil || r.TraceFile != "" || r.TraceBytes != 0 || r.PostTriggerRequested != 0 || r.PostTriggerStatus != "not-requested" || r.MarkerStatus != "not-emitted" || finishDuration >= postgresLatePostTrigger {
			t.Fatalf("no-event error=%v receipt=%+v", err, r)
		}
	case "start-failed":
		if err == nil || r.TraceStatus != "start-failed" || !strings.Contains(r.Error, "start flight recorder") || r.Trigger == nil || r.Trigger.MarkerEmitted || r.TraceBytes != 0 || r.TraceFile != "" || r.PostTriggerRequested != 0 || r.MarkerStatus != "not-emitted" {
			t.Fatalf("startup error=%v receipt=%+v", err, r)
		}
	default:
		t.Fatal(fmt.Errorf("unknown child mode %q", *postgresLateTestChild))
	}
}

type postgresLateTraceLog struct {
	Goroutine, Time, Task int64
	Message               string
}

func readPostgresLateTraceLogs(t *testing.T, path string) map[string][]postgresLateTraceLog {
	t.Helper()
	// parse the real snapshot rather than treating MinAge or call bounds as proof.
	output, err := exec.CommandContext(t.Context(), "go", "tool", "trace", "-d=parsed", path).CombinedOutput()
	if err != nil {
		t.Fatalf("parse flight recorder output: %v\n%s", err, output)
	}
	pattern := regexp.MustCompile(`(?m)^M=-?\d+ P=-?\d+ G=(\d+) Log Time=(\d+) Task=(\d+) Category="([^"]*)" Message=(.*)$`)
	logs := make(map[string][]postgresLateTraceLog)
	for _, match := range pattern.FindAllStringSubmatch(string(output), -1) {
		values := [3]int64{}
		for index := range values {
			values[index], err = strconv.ParseInt(match[index+1], 10, 64)
			if err != nil {
				t.Fatal(err)
			}
		}
		message, err := strconv.Unquote(match[5])
		if err != nil {
			t.Fatal(err)
		}
		logs[match[4]] = append(logs[match[4]], postgresLateTraceLog{Goroutine: values[0], Time: values[1], Task: values[2], Message: message})
	}
	return logs
}

func readPostgresLateReceipt(t *testing.T, directory string) postgresLateReceipt {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(directory, "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	var r postgresLateReceipt
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatal(err)
	}
	return r
}
