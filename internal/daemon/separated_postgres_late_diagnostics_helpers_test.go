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
	"runtime/trace"
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
	if e.Kind != "query" || e.TriggerLag != e.Observed-e.Completed || e.TriggerLag < 0 {
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

func TestPostgresLateFlightRecorder(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"capture", "no-event", "start-failed"} {
		t.Run(mode, func(t *testing.T) {
			// do not inherit -test.trace: the child owns its real flight recorder.
			cmd := exec.CommandContext(t.Context(), executable, "-test.run=^TestPostgresLateFlightRecorderChild$", "-test.count=1", "-tnl-postgres-late-test-child="+mode)
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
	if *postgresLateTestChild == "start-failed" {
		other := trace.NewFlightRecorder(trace.FlightRecorderConfig{})
		if err := other.Start(); err != nil {
			t.Fatal(err)
		}
		defer other.Stop()
	}
	// a future epoch keeps sampler fixtures independent of platform proc support.
	d := startPostgresLateDiagnostic(t.Context(), postgresLateConfig{Mode: "trace", Start: time.Now().Add(time.Hour), Duration: time.Minute})
	if *postgresLateTestChild == "capture" {
		d.Observe(17, 3*time.Second, 3*time.Second+26*time.Millisecond, 0, 0)
	}
	directory := filepath.Join(t.TempDir(), "diagnostics")
	err := d.Finish(directory)
	r := readPostgresLateReceipt(t, directory)
	switch *postgresLateTestChild {
	case "capture":
		if err != nil || r.TraceStatus != "captured" || r.Trigger == nil || r.Trigger.Slot != 17 || r.TraceBytes == 0 || r.TraceBytes > postgresLateTraceLimit || r.SnapshotCompleted < r.SnapshotStarted {
			t.Fatalf("capture error=%v receipt=%+v", err, r)
		}
		data, err := os.ReadFile(filepath.Join(directory, r.TraceFile))
		if err != nil || !strings.HasPrefix(string(data), "go 1.") {
			t.Fatalf("missing raw trace: %v", err)
		}
	case "no-event":
		if err != nil || r.TraceStatus != "no-event" || r.Trigger != nil || r.TraceFile != "" || r.TraceBytes != 0 {
			t.Fatalf("no-event error=%v receipt=%+v", err, r)
		}
	case "start-failed":
		if err == nil || r.TraceStatus != "start-failed" || !strings.Contains(r.Error, "start flight recorder") {
			t.Fatalf("startup error=%v receipt=%+v", err, r)
		}
	default:
		t.Fatal(fmt.Errorf("unknown child mode %q", *postgresLateTestChild))
	}
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
