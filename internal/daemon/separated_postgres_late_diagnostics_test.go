package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/metrics"
	"runtime/trace"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var postgresLoadLateDiagnostics = flag.String("tnl-postgres-load-late-diagnostics", "off", "test-only late PostgreSQL diagnostics: off, sample, or trace")

const postgresLateInterval = 100 * time.Millisecond
const postgresLateTraceLimit = 16 << 20
const postgresLatePostTrigger = time.Second
const postgresLateNotifyTimeout = 2 * time.Second

func validatePostgresLateDiagnostics(workload string, timing bool, mode string) error {
	if mode != "off" && mode != "sample" && mode != "trace" {
		return errors.New("PostgreSQL late diagnostics must be off, sample, or trace")
	}
	if mode != "off" && (workload != "postgres" || !timing) {
		return errors.New("PostgreSQL late diagnostics require the postgres workload and timing enabled")
	}
	return nil
}

type postgresLateConfig struct {
	Phase        string
	Start        time.Time // the visitor's local monotonic phase epoch
	Duration     time.Duration
	ConnectorPID int
	Mode         string // empty selects the test flag

	// Notify runs on the capture owner and must honor context cancellation.
	Notify func(context.Context, postgresLateTrigger) error `json:"-"`
}

type postgresLateProcess struct {
	PID                                    int
	UserTicks, SystemTicks, StartTimeTicks uint64
	Threads                                uint64
}

type postgresLateSample struct {
	Intended, Started, Completed, Lateness time.Duration
	Skipped                                int64
	Visitor, Connector                     postgresLateProcess
	CgroupCPU, MemoryEvents                map[string]uint64
	CgroupCPUPressure, VMCPUPressure       map[string]uint64
	GCCycles, HeapBytes, GOMAXPROCS        uint64
	GCCPUSeconds                           float64
}

type postgresLateTrigger struct {
	Slot                           int
	Kind                           string
	Started, Completed, Observed   time.Duration
	TriggerLag                     time.Duration
	MarkerStarted, MarkerCompleted time.Duration
	MarkerEmitted                  bool
}

type postgresLateReceipt struct {
	Config                                   postgresLateConfig
	VisitorPID                               int
	SampleCount, SampleLimit, TraceBytes     int
	SampleInterval, MaximumSamplingLateness  time.Duration
	Trigger                                  *postgresLateTrigger
	TraceStatus, TraceFile, Coverage         string
	SnapshotStarted, SnapshotCompleted       time.Duration
	MarkerStarted, MarkerCompleted           time.Duration
	MarkerStatus                             string
	NotifyStarted, NotifyCompleted           time.Duration
	NotifyTimeout, NotifyDeadline            time.Duration
	NotifyStatus                             string
	PostTriggerRequested, PostTriggerActual  time.Duration
	PostTriggerStarted, PostTriggerDeadline  time.Duration
	PostTriggerCompleted                     time.Duration
	PostTriggerStatus                        string
	TracePartial                             bool
	Cancelled                                bool
	Notes                                    []string
	Issues                                   []string
	Error                                    string
	KernelSnapshotCount, KernelSnapshotLimit int
	KernelSnapshotSkipped                    int
	KernelSnapshotFile, KernelSnapshotNotes  string
}

type postgresLateDiagnostic struct {
	cfg                   postgresLateConfig
	receipt               postgresLateReceipt
	samples               []postgresLateSample
	kernels               []postgresKernelSnapshot
	trigger               chan postgresLateTrigger
	sampleDone, traceDone chan struct{}
	cancel                context.CancelFunc
	parent                context.Context
	claimed               atomic.Bool
	finish                sync.Once
	mu                    sync.Mutex
	err, finishErr        error
	traceBytes            []byte
	traceActive           bool // immutable after startup; Observe never calls the recorder
}

// start before Run; call Finish after every worker (including Observe) joins.
// startup failures remain in the receipt and are returned by Finish.
func startPostgresLateDiagnostic(ctx context.Context, cfg postgresLateConfig) *postgresLateDiagnostic {
	if cfg.Mode == "" {
		cfg.Mode = *postgresLoadLateDiagnostics
	}
	if cfg.Mode == "off" {
		return nil
	}
	sampleCtx, cancel := context.WithCancel(ctx)
	d := &postgresLateDiagnostic{cfg: cfg, parent: ctx, cancel: cancel, trigger: make(chan postgresLateTrigger, 1), sampleDone: make(chan struct{}), traceDone: make(chan struct{})}
	d.receipt = postgresLateReceipt{Config: cfg, VisitorPID: os.Getpid(), SampleInterval: postgresLateInterval, TraceStatus: "not-requested", MarkerStatus: "not-emitted", NotifyStatus: "not-requested", PostTriggerStatus: "not-requested", Coverage: "unverified; parse the trace externally to establish actual coverage", Notes: []string{
		"offsets and durations are nanoseconds; process CPU counters are raw clock ticks; process start ticks identify PID reuse",
		"cgroup CPU includes visitor, connector, sampler, and snapshot work; VM PSI describes the Linux VM, not the macOS host",
		"100ms sampling cannot resolve a 25ms stall; sampling lateness includes pauses of the visitor runtime itself",
		"no connector Go GC or goroutine scheduling counters; no main-thread schedstat is claimed as process-wide scheduling",
	}}
	if (cfg.Mode != "sample" && cfg.Mode != "trace") || cfg.Start.IsZero() || cfg.Duration <= 0 || cfg.Duration > 5*time.Minute || cfg.ConnectorPID < 0 {
		d.fail(errors.New("invalid late-diagnostic mode, epoch, duration (maximum 5m), or connector PID"))
		d.claimed.Store(true)
		close(d.sampleDone)
		close(d.traceDone)
		return d
	}
	// include the request deadline's drain allowance, notification, and capture tail;
	// notification overlaps the tail deadline. never grow while serving load.
	tailAllowance := postgresLatePostTrigger
	if cfg.Notify != nil {
		tailAllowance = max(tailAllowance, postgresLateNotifyTimeout)
		d.note("trigger notification runs before the tail wait on the capture owner; its callback must honor the parent context and 2s timeout; notification failures do not discard the local trace")
	}
	d.samples = make([]postgresLateSample, 0, int((cfg.Duration+5*time.Second+tailAllowance)/postgresLateInterval)+2)
	d.receipt.SampleLimit = cap(d.samples)
	d.kernels = make([]postgresKernelSnapshot, 0, postgresKernelSnapshotLimit)
	d.receipt.KernelSnapshotLimit, d.receipt.KernelSnapshotNotes = postgresKernelSnapshotLimit, postgresKernelNotes
	var recorder *trace.FlightRecorder
	if cfg.Mode == "trace" {
		d.traceBytes = make([]byte, postgresLateTraceLimit)
		d.note("flight recorder MinAge=5s and MaxBytes=8MiB are hints, not coverage or hard memory bounds; output is capped at 16MiB; snapshotting perturbs the runtime")
		d.note("the winning Observe caller emits a log on its existing worker GoID, not a new task; marker call bounds and requested/actual tail offsets do not prove trace retention; parse the trace externally")
		d.note("the tail deadline is 1s after observation, not after worker drain; cancellation shortens the tail but still requests a best-effort snapshot; runtime scheduling, WriteTo, and Stop can delay completion")
		recorder = trace.NewFlightRecorder(trace.FlightRecorderConfig{MinAge: 5 * time.Second, MaxBytes: 8 << 20})
		if err := recorder.Start(); err != nil {
			d.fail(fmt.Errorf("start flight recorder: %w", err))
			d.receipt.TraceStatus, recorder = "start-failed", nil
		} else {
			d.receipt.TraceStatus = "no-event"
			d.traceActive = true
		}
	}
	go d.sample(sampleCtx)
	go d.capture(ctx, recorder)
	return d
}

// Observe does no I/O or snapshotting. only the first qualifying event is sent.
func (d *postgresLateDiagnostic) Observe(slot int, queryStarted, queryCompleted, callbackStarted, callbackCompleted time.Duration) {
	if d == nil || d.claimed.Load() {
		return
	}
	e := postgresLateTrigger{Slot: slot, Kind: "query", Started: queryStarted, Completed: queryCompleted}
	if queryStarted < 2*time.Second || queryCompleted-queryStarted <= 25*time.Millisecond {
		e.Kind, e.Started, e.Completed = "callback", callbackStarted, callbackCompleted
		if callbackStarted < 2*time.Second || callbackCompleted-callbackStarted <= 25*time.Millisecond {
			return
		}
	}
	if !d.claimed.CompareAndSwap(false, true) {
		return
	}
	e.Observed = time.Since(d.cfg.Start)
	e.TriggerLag = e.Observed - e.Completed
	if d.traceActive {
		e.MarkerStarted = time.Since(d.cfg.Start)
		trace.Logf(context.Background(), "postgres-late-outlier", "phase=%s slot=%d kind=%s started_ns=%d completed_ns=%d observed_ns=%d marker_ns=%d", d.cfg.Phase, e.Slot, e.Kind, e.Started, e.Completed, e.Observed, e.MarkerStarted)
		e.MarkerCompleted = time.Since(d.cfg.Start)
		e.MarkerEmitted = true
	}
	select {
	case d.trigger <- e:
	default:
	}
}

func (d *postgresLateDiagnostic) capture(ctx context.Context, recorder *trace.FlightRecorder) {
	defer close(d.traceDone)
	if recorder != nil {
		defer recorder.Stop()
	}
	// Finish closes trigger only after every Observe caller joins. even a cancelled
	// context must not discard an event still being enqueued by the winning worker.
	e, ok := <-d.trigger
	if !ok {
		return
	}
	d.receipt.Trigger = &e
	d.receipt.MarkerStarted, d.receipt.MarkerCompleted = e.MarkerStarted, e.MarkerCompleted
	if e.MarkerEmitted {
		d.receipt.MarkerStatus = "emitted-on-observer-worker; retention-and-GoID-correlation-unverified"
	}
	if d.cfg.Notify != nil {
		notifyCtx, cancel := context.WithTimeout(ctx, postgresLateNotifyTimeout)
		deadline, _ := notifyCtx.Deadline()
		d.receipt.NotifyTimeout, d.receipt.NotifyDeadline = postgresLateNotifyTimeout, deadline.Sub(d.cfg.Start)
		d.receipt.NotifyStarted = time.Since(d.cfg.Start)
		err := d.cfg.Notify(notifyCtx, e)
		if err == nil {
			err = notifyCtx.Err()
		}
		d.receipt.NotifyCompleted = time.Since(d.cfg.Start)
		cancel()
		d.receipt.NotifyStatus = "completed"
		if err != nil {
			d.receipt.NotifyStatus = "failed"
			if errors.Is(err, context.Canceled) {
				d.receipt.NotifyStatus = "cancelled"
			} else if errors.Is(err, context.DeadlineExceeded) {
				d.receipt.NotifyStatus = "deadline-exceeded"
			}
			d.fail(fmt.Errorf("notify late-diagnostic trigger: %w", err))
		}
	}
	if recorder == nil {
		return
	}
	d.receipt.PostTriggerRequested = postgresLatePostTrigger
	d.receipt.PostTriggerStarted = e.Observed
	d.receipt.PostTriggerDeadline = e.Observed + postgresLatePostTrigger
	deadline := d.cfg.Start.Add(d.receipt.PostTriggerDeadline)
	timer := time.NewTimer(max(0, time.Until(deadline)))
	d.receipt.PostTriggerStatus = "completed"
	select {
	case <-timer.C:
	case <-ctx.Done():
		if time.Now().Before(deadline) {
			d.receipt.PostTriggerStatus = "cancelled"
			d.receipt.TracePartial = true
		}
	}
	timer.Stop()
	d.receipt.PostTriggerCompleted = time.Since(d.cfg.Start)
	d.receipt.PostTriggerActual = max(0, d.receipt.PostTriggerCompleted-e.Observed)
	d.receipt.SnapshotStarted = time.Since(d.cfg.Start)
	w := &postgresLateWriter{data: d.traceBytes}
	_, err := recorder.WriteTo(w)
	d.receipt.SnapshotCompleted = time.Since(d.cfg.Start)
	d.receipt.TraceBytes = w.used
	d.traceBytes = d.traceBytes[:w.used]
	d.receipt.TraceStatus, d.receipt.TraceFile = "captured", "visitor.trace"
	if d.receipt.TracePartial {
		d.receipt.TraceStatus, d.receipt.TraceFile = "captured-partial", "visitor.trace.partial"
	}
	if err != nil {
		d.receipt.TraceStatus, d.receipt.TraceFile = "capture-failed", "visitor.trace.partial"
		d.receipt.TracePartial = true
		d.fail(fmt.Errorf("snapshot flight recorder: %w", err))
	}
}

func (d *postgresLateDiagnostic) sample(ctx context.Context) {
	defer close(d.sampleDone)
	values := []metrics.Sample{{Name: "/gc/cycles/total:gc-cycles"}, {Name: "/memory/classes/heap/objects:bytes"}, {Name: "/cpu/classes/gc/total:cpu-seconds"}, {Name: "/sched/gomaxprocs:threads"}}
	timer := time.NewTimer(max(0, time.Until(d.cfg.Start)))
	defer timer.Stop()
	var identities [2]uint64
	for index := int64(0); index < int64(cap(d.samples)); {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		s := postgresLateSample{Intended: time.Duration(index) * postgresLateInterval, Started: time.Since(d.cfg.Start)}
		s.Lateness = max(0, s.Started-s.Intended)
		if runtime.GOOS == "linux" {
			for i, pid := range []int{os.Getpid(), d.cfg.ConnectorPID} {
				if pid == 0 {
					continue
				}
				data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
				var p postgresLateProcess
				if err == nil {
					p, err = parsePostgresLateProcess(string(data))
				}
				if err == nil && identities[i] != 0 && p.StartTimeTicks != identities[i] {
					err = errors.New("process identity changed")
				}
				if err != nil {
					d.fail(fmt.Errorf("sample PID %d: %w", pid, err))
				} else {
					identities[i] = p.StartTimeTicks
					if i == 0 {
						s.Visitor = p
					} else {
						s.Connector = p
					}
				}
			}
			s.CgroupCPU = d.counters("/sys/fs/cgroup/cpu.stat")
			s.MemoryEvents = d.counters("/sys/fs/cgroup/memory.events")
			s.CgroupCPUPressure = d.counters("/sys/fs/cgroup/cpu.pressure")
			s.VMCPUPressure = d.counters("/proc/pressure/cpu")
		} else {
			d.note("proc/cgroup/PSI counters unavailable on " + runtime.GOOS)
		}
		metrics.Read(values)
		s.GCCycles, s.HeapBytes, s.GCCPUSeconds, s.GOMAXPROCS = values[0].Value.Uint64(), values[1].Value.Uint64(), values[2].Value.Float64(), values[3].Value.Uint64()
		if runtime.GOOS == "linux" {
			d.snapshotKernel("/proc", s)
		}
		s.Completed = time.Since(d.cfg.Start)
		s.Skipped = max(0, int64(s.Completed/postgresLateInterval)-index)
		d.samples = append(d.samples, s)
		d.receipt.MaximumSamplingLateness = max(d.receipt.MaximumSamplingLateness, s.Lateness)
		index = max(index+1, int64(s.Completed/postgresLateInterval)+1)
		timer.Reset(max(0, time.Until(d.cfg.Start.Add(time.Duration(index)*postgresLateInterval))))
	}
	d.fail(errors.New("late-diagnostic sampling window exhausted before Finish"))
}

func (d *postgresLateDiagnostic) counters(path string) map[string]uint64 {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		d.note("optional Linux interface unavailable: " + path)
		return nil
	}
	var values map[string]uint64
	if err == nil {
		values, err = parsePostgresLateCounters(string(data))
	}
	if err != nil {
		d.fail(fmt.Errorf("sample %s: %w", path, err))
	}
	return values
}

func parsePostgresLateProcess(text string) (postgresLateProcess, error) {
	var p postgresLateProcess
	left, right := strings.IndexByte(text, '('), strings.LastIndexByte(text, ')')
	if left < 1 || right <= left {
		return p, errors.New("invalid proc stat framing")
	}
	fields := strings.Fields(text[right+1:])
	if len(fields) < 20 {
		return p, errors.New("short proc stat")
	}
	var err error
	if p.PID, err = strconv.Atoi(strings.TrimSpace(text[:left])); err != nil {
		return p, errors.New("invalid proc PID")
	}
	for index, value := range map[int]*uint64{11: &p.UserTicks, 12: &p.SystemTicks, 17: &p.Threads, 19: &p.StartTimeTicks} {
		if *value, err = strconv.ParseUint(fields[index], 10, 64); err != nil {
			return p, fmt.Errorf("invalid proc stat field %d", index+3)
		}
	}
	return p, nil
}

func parsePostgresLateCounters(text string) (map[string]uint64, error) {
	values := make(map[string]uint64)
	for line := range strings.SplitSeq(strings.TrimSpace(text), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, errors.New("invalid counter row")
		}
		key, raw := fields[0], fields[1]
		if key == "some" || key == "full" {
			raw = ""
			for _, field := range fields[1:] {
				if strings.HasPrefix(field, "total=") {
					raw = strings.TrimPrefix(field, "total=")
				}
			}
			key += "_total_usec"
		} else if len(fields) != 2 {
			return nil, errors.New("invalid counter column count")
		}
		value, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			return nil, errors.New("invalid counter value")
		}
		values[key] = value
	}
	return values, nil
}

var errPostgresLateTraceLimit = errors.New("trace exceeds 16MiB output limit")

type postgresLateWriter struct {
	data []byte
	used int
}

func (w *postgresLateWriter) Write(p []byte) (int, error) {
	n := copy(w.data[w.used:], p)
	w.used += n
	if n != len(p) {
		return n, errPostgresLateTraceLimit
	}
	return n, nil
}

func (d *postgresLateDiagnostic) fail(err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, existing := range d.receipt.Issues {
		if existing == err.Error() {
			return
		}
	}
	if len(d.receipt.Issues) >= 16 {
		return
	}
	if len(d.receipt.Issues) == 15 {
		err = errors.New("additional diagnostic errors omitted after 15 distinct failures")
	}
	d.receipt.Issues = append(d.receipt.Issues, err.Error())
	d.err = errors.Join(d.err, err)
}

func (d *postgresLateDiagnostic) note(note string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, existing := range d.receipt.Notes {
		if existing == note {
			return
		}
	}
	d.receipt.Notes = append(d.receipt.Notes, note)
}

// Finish is idempotent, joins all work, and only then writes private artifacts.
// directory must not exist; partial traces and failures still get a receipt.
func (d *postgresLateDiagnostic) Finish(directory string) error {
	if d == nil {
		return nil
	}
	d.finish.Do(func() {
		defer func() { d.samples, d.kernels, d.traceBytes = nil, nil, nil }()
		close(d.trigger)
		// normal workload completion is not capture cancellation. keep sampling
		// through any remaining tail, then join both owners before exporting.
		<-d.traceDone
		d.cancel()
		<-d.sampleDone
		d.receipt.Cancelled = d.parent.Err() != nil
		d.err = errors.Join(d.err, d.parent.Err())
		if err := os.Mkdir(directory, 0o700); err != nil {
			d.finishErr = errors.Join(d.err, fmt.Errorf("create diagnostic directory (receipt unavailable): %w", err))
			return
		}
		write := func(name string, value any) error {
			f, err := os.OpenFile(filepath.Join(directory, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return err
			}
			if raw, ok := value.([]byte); ok {
				_, err = f.Write(raw)
			} else {
				err = json.NewEncoder(f).Encode(value)
			}
			return errors.Join(err, f.Close())
		}
		d.err = errors.Join(d.err, write("samples.json", d.samples))
		d.receipt.KernelSnapshotCount, d.receipt.KernelSnapshotFile = len(d.kernels), "kernel-snapshots.json"
		d.err = errors.Join(d.err, write(d.receipt.KernelSnapshotFile, d.kernels))
		if d.receipt.TraceFile != "" {
			d.err = errors.Join(d.err, write(d.receipt.TraceFile, d.traceBytes))
		}
		d.receipt.SampleCount = len(d.samples)
		if d.err != nil {
			d.receipt.Error = d.err.Error()
		}
		d.finishErr = errors.Join(d.err, write("receipt.json", d.receipt))
	})
	return d.finishErr
}
