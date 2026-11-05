package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/metrics"
	"runtime/pprof"
	"runtime/trace"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
)

var postgresLoadDiagnostics = flag.String("tnl-postgres-load-diagnostics", "off", "publisher diagnostics: off, metrics, cpu, contention, or trace; use separate diagnostic runs")

const publisherDiagnosticGuard = time.Second

// attach the owner before starting publishers. close it only after stopping and
// joining them. off returns the original context and a nil, no-op owner.
func setupSeparatedPublisherDiagnostics(t *testing.T, ctx context.Context) (context.Context, *separatedPublisherDiagnostics) {
	t.Helper()
	if *postgresLoadDiagnostics == "off" {
		return ctx, nil
	}
	if !publisherDiagnosticName(*separatedComponent) {
		t.Fatal("publisher diagnostics require a simple separated component name")
	}
	ctx, diagnostics, err := newSeparatedPublisherDiagnostics(ctx, *postgresLoadDiagnostics, filepath.Join("/results", "publisher-diagnostics-"+*separatedComponent))
	if err != nil {
		t.Fatal(err)
	}
	return ctx, diagnostics
}

type separatedPublisherDiagnostics struct {
	mode, directory string
	owner           *observability.Metrics
	ctx             context.Context
	cancel          context.CancelFunc
	mu              sync.Mutex
	closed          bool
	// tests use this barrier to cancel only after the runtime writer has started.
	recordingStarted func()
}

func newSeparatedPublisherDiagnostics(ctx context.Context, mode, directory string) (context.Context, *separatedPublisherDiagnostics, error) {
	switch mode {
	case "off":
		return ctx, nil, nil
	case "metrics", "cpu", "contention", "trace":
	default:
		return ctx, nil, errors.New("-tnl-postgres-load-diagnostics must be off, metrics, cpu, contention, or trace")
	}
	// refuse stale directories rather than overwriting an earlier diagnostic run.
	if err := os.Mkdir(directory, 0o700); err != nil {
		return ctx, nil, err
	}
	owner := observability.New("publisher") // local only; no collector or listener
	ctx, cancel := context.WithCancel(observability.WithMetrics(ctx, owner))
	return ctx, &separatedPublisherDiagnostics{mode: mode, directory: directory, owner: owner, ctx: ctx, cancel: cancel}, nil
}

func (d *separatedPublisherDiagnostics) Close(t *testing.T) {
	if d == nil {
		return
	}
	t.Helper()
	d.cancel()
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.closed {
		d.closed = true
		if err := d.owner.Shutdown(context.Background()); err != nil {
			t.Errorf("publisher diagnostics shutdown: %v", err)
		}
	}
}

// capture is synchronous in the isolated publisher process while visitors run
// elsewhere. never put it on a visitor's scheduling or request path.
func (d *separatedPublisherDiagnostics) Capture(t *testing.T, ctx context.Context, phase string, start time.Time, duration time.Duration) {
	if d == nil {
		return
	}
	t.Helper()
	if err := d.capture(ctx, phase, start, duration); err != nil && err != context.Canceled {
		t.Errorf("publisher diagnostics: %v", err)
	}
}

type publisherDiagnosticReadBounds struct {
	Started   time.Time `json:"read_started"`
	Completed time.Time `json:"read_completed"`
}

type publisherDiagnosticSnapshot struct {
	publisherDiagnosticReadBounds
	Values map[string]float64 `json:"runtime"`
}

type publisherDiagnosticCapture struct {
	Mode                 string                        `json:"mode"`
	MetricsOwnerAttached bool                          `json:"metrics_owner_attached"`
	AllocationSampleRate int                           `json:"allocation_sample_rate_bytes"`
	Phase                string                        `json:"phase"`
	PhaseStart           time.Time                     `json:"phase_start"`
	PhaseDuration        time.Duration                 `json:"phase_duration_ns"`
	StopGuard            time.Duration                 `json:"stop_guard_ns"`
	WindowLimit          time.Duration                 `json:"window_limit_ns"`
	PreparationStarted   time.Time                     `json:"preparation_started"`
	PreparationCompleted time.Time                     `json:"preparation_completed"`
	StartRequested       time.Time                     `json:"recording_start_requested"`
	Started              time.Time                     `json:"recording_start_completed"`
	StopTarget           time.Time                     `json:"recording_stop_target"`
	StopRequested        time.Time                     `json:"recording_stop_requested"`
	Flushed              time.Time                     `json:"recording_stop_and_flush_completed"`
	MetadataWriteStarted time.Time                     `json:"metadata_write_started"`
	Cancelled            bool                          `json:"cancelled"`
	MetricsBefore        publisherDiagnosticReadBounds `json:"metrics_before"`
	MetricsAfter         publisherDiagnosticReadBounds `json:"metrics_after"`
	Before               publisherDiagnosticSnapshot   `json:"before"`
	After                publisherDiagnosticSnapshot   `json:"after"`
	Delta                map[string]float64            `json:"runtime_delta"`
	Notes                string                        `json:"notes"`
}

const publisherDiagnosticNotes = "metrics is the instrumented diagnostic baseline; off has no owner and is not the production telemetry default. " +
	"off-vs-metrics includes owner instrumentation, gathers, allocation snapshots, and artifact writes, not just metric recording. " +
	"compare cpu/contention/trace against metrics in separate runs. " +
	"runtime_delta uses the before/after runtime read bounds; it includes profiler startup, stop/flush, and contention after-profile writes, not just steady traffic. " +
	"metric read bounds bracket Gather; metrics and allocation artifact writes are outside the runtime counter interval but can perturb the warm phase. " +
	"recording_start_completed follows startup; recording_stop_requested precedes stopping and flushing; metadata_write_started excludes the metadata write itself. " +
	"runtime CPU counters are estimates, not process CPU usage; gauge deltas may be negative. " +
	"allocs, mutex, and block profiles are cumulative snapshots (use pprof -base), not reset window totals; allocs may lag GC. " +
	"no forced GC, SQL, credentials, or payload capture."

func (d *separatedPublisherDiagnostics) capture(ctx context.Context, phase string, start time.Time, duration time.Duration) (err error) {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return errors.New("publisher diagnostics already closed")
	}
	if !publisherDiagnosticName(phase) || start.IsZero() || duration <= publisherDiagnosticGuard {
		return errors.New("publisher diagnostics need a simple phase name, start, and duration longer than the stop guard")
	}
	ctx, cancel := context.WithCancel(ctx)
	stopOwner := context.AfterFunc(d.ctx, cancel)
	defer stopOwner()
	defer cancel()
	if err := waitPublisherDiagnostic(ctx, start); err != nil {
		return err
	}
	directory := filepath.Join(d.directory, phase)
	if err := os.Mkdir(directory, 0o700); err != nil {
		return err
	}
	record := publisherDiagnosticCapture{
		Mode: d.mode, Phase: phase, PhaseStart: start, PhaseDuration: duration,
		MetricsOwnerAttached: true, AllocationSampleRate: runtime.MemProfileRate,
		StopGuard: publisherDiagnosticGuard, WindowLimit: 10 * time.Second,
		Notes: publisherDiagnosticNotes,
	}
	if d.mode == "trace" {
		record.WindowLimit = 2 * time.Second
	}
	if d.mode == "contention" {
		record.Notes += "; mutex fraction=1 and block rate=1ns during recording only; restore previous mutex fraction and set block rate=0 before writing after profiles"
	}
	defer func() {
		record.MetadataWriteStarted = time.Now()
		record.Cancelled = ctx.Err() != nil
		if writeErr := writePublisherDiagnosticJSON(directory, "capture.json", record); writeErr != nil {
			err = errors.Join(err, writeErr)
		}
	}()
	record.PreparationStarted = time.Now()
	if record.MetricsBefore, err = d.snapshot(directory, "before"); err != nil {
		return err
	}
	if d.mode == "contention" {
		if err := writePublisherDiagnosticProfiles(directory, "before", "mutex", "block"); err != nil {
			return err
		}
	}
	record.PreparationCompleted = time.Now()
	stopBy := start.Add(duration - publisherDiagnosticGuard)
	if !time.Now().Before(stopBy) {
		return errors.New("publisher diagnostics missed the phase recording window")
	}
	record.Before = readPublisherDiagnosticRuntime()
	err = recordPublisherDiagnosticWindow(ctx, directory, d.mode, minTime(stopBy, time.Now().Add(record.WindowLimit)), &record, d.recordingStarted)
	record.After = readPublisherDiagnosticRuntime()
	record.Delta = make(map[string]float64, len(record.Before.Values))
	for name, before := range record.Before.Values {
		record.Delta[name] = record.After.Values[name] - before
	}
	var afterErr error
	record.MetricsAfter, afterErr = d.snapshot(directory, "after")
	if afterErr != nil {
		err = errors.Join(err, afterErr)
	}
	return err
}

func recordPublisherDiagnosticWindow(ctx context.Context, directory, mode string, stopBy time.Time, record *publisherDiagnosticCapture, onStarted func()) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	record.StartRequested = time.Now()
	record.StopTarget = stopBy
	stop := func() error { return nil }
	switch mode {
	case "cpu", "trace":
		name, start, finish := "cpu.pb.gz", pprof.StartCPUProfile, pprof.StopCPUProfile
		if mode == "trace" {
			name, start, finish = "trace.out", trace.Start, trace.Stop
		}
		file, err := os.OpenFile(filepath.Join(directory, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		if err := start(file); err != nil {
			return errors.Join(err, file.Close())
		}
		stop = func() error { finish(); return file.Close() }
	case "contention":
		previous := runtime.SetMutexProfileFraction(1)
		runtime.SetBlockProfileRate(1)
		stop = func() error {
			runtime.SetMutexProfileFraction(previous)
			// the block rate has no getter. this isolated test process owns it.
			runtime.SetBlockProfileRate(0)
			return writePublisherDiagnosticProfiles(directory, "after", "mutex", "block")
		}
	}
	defer func() {
		record.StopRequested = time.Now()
		if stopErr := stop(); stopErr != nil {
			err = errors.Join(err, stopErr)
		}
		record.Flushed = time.Now()
	}()
	record.Started = time.Now()
	if onStarted != nil {
		onStarted()
	}
	return waitPublisherDiagnostic(ctx, stopBy)
}

func (d *separatedPublisherDiagnostics) snapshot(directory, when string) (publisherDiagnosticReadBounds, error) {
	bounds := publisherDiagnosticReadBounds{Started: time.Now()}
	families, err := d.owner.Gather()
	bounds.Completed = time.Now()
	if err != nil {
		return bounds, err
	}
	return bounds, errors.Join(writePublisherDiagnosticJSON(directory, when+"-metrics.json", families), writePublisherDiagnosticProfiles(directory, when, "allocs"))
}

func readPublisherDiagnosticRuntime() publisherDiagnosticSnapshot {
	names := []string{
		"/cpu/classes/user:cpu-seconds", "/cpu/classes/gc/total:cpu-seconds",
		"/gc/heap/allocs:bytes", "/gc/heap/allocs:objects", "/gc/heap/frees:bytes", "/gc/heap/frees:objects",
		"/gc/cycles/total:gc-cycles", "/memory/classes/heap/objects:bytes", "/memory/classes/heap/stacks:bytes",
		"/sched/goroutines:goroutines", "/sched/gomaxprocs:threads", "/sync/mutex/wait/total:seconds",
	}
	samples := make([]metrics.Sample, len(names))
	for index, name := range names {
		samples[index].Name = name
	}
	result := publisherDiagnosticSnapshot{publisherDiagnosticReadBounds: publisherDiagnosticReadBounds{Started: time.Now()}, Values: make(map[string]float64, len(samples))}
	metrics.Read(samples)
	result.Completed = time.Now()
	for _, sample := range samples {
		switch sample.Value.Kind() {
		case metrics.KindUint64:
			result.Values[sample.Name] = float64(sample.Value.Uint64())
		case metrics.KindFloat64:
			result.Values[sample.Name] = sample.Value.Float64()
		}
	}
	return result
}

func writePublisherDiagnosticJSON(directory, name string, value any) error {
	return writePublisherDiagnostic(directory, name, func(writer io.Writer) error { return json.NewEncoder(writer).Encode(value) })
}

func writePublisherDiagnosticProfiles(directory, when string, names ...string) error {
	var err error
	for _, name := range names {
		err = errors.Join(err, writePublisherDiagnostic(directory, when+"-"+name+".pb.gz", func(writer io.Writer) error {
			return pprof.Lookup(name).WriteTo(writer, 0)
		}))
	}
	return err
}

func writePublisherDiagnostic(directory, name string, write func(io.Writer) error) error {
	file, err := os.OpenFile(filepath.Join(directory, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	return errors.Join(write(file), file.Close())
}

func waitPublisherDiagnostic(ctx context.Context, until time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	timer := time.NewTimer(time.Until(until))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return ctx.Err()
	}
}

func publisherDiagnosticName(name string) bool {
	return name != "" && len(name) <= 80 && strings.Trim(name, "abcdefghijklmnopqrstuvwxyz0123456789-") == ""
}
