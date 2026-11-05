package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime/trace"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/benchworkload"
)

type postgresPublisherLateBounds struct {
	Started, Completed time.Duration
}

type postgresPublisherLateReceipt struct {
	Phase, Component                     string
	PublisherPID                         int
	PhaseStart, LocalEpoch               time.Time
	RebaseStarted, RebaseCompleted       time.Time
	RebaseReadWidth, Duration            time.Duration
	WaitTimeout, WaitDeadline            time.Duration
	Arm, TriggerRead, FinalTriggerRead   postgresPublisherLateBounds
	Marker, Hold, Snapshot, Stop         postgresPublisherLateBounds
	SnapshotMarker                       postgresPublisherLateBounds
	FinishedRead, ExportWait, Export     postgresPublisherLateBounds
	Received, MarkerPhaseNS              time.Duration
	SnapshotPhaseNS                      time.Duration
	PostTriggerRequested, HoldDeadline   time.Duration
	PostTriggerActual                    time.Duration
	Trigger                              *postgresLateTrigger
	Finished, ExportAuthorized           bool
	TracePartial, Cancelled              bool
	TraceBytes, TraceLimit               int
	TraceStatus, TraceFile, MarkerStatus string
	HoldStatus, ExportStatus, Coverage   string
	Notes                                []string
	Error                                string
}

type postgresPublisherLate struct {
	coordination *benchworkload.Coordination
	epoch        time.Time
	ctx          context.Context
	cancel       context.CancelFunc
	done         chan struct{}
	receipt      postgresPublisherLateReceipt
	traceBytes   []byte
	err          error
	finish       sync.Once
	finishErr    error
}

// start synchronously arms before returning. a non-nil owner returned with an
// error can still be joined/exported with Finish after cancelling ctx on abort.
// the caller owns mode validation and must not also enable publisher trace mode.
func startPostgresPublisherLate(ctx context.Context, coordination *benchworkload.Coordination, phase connectLoadPhase, component string) (*postgresPublisherLate, error) {
	if coordination == nil || !publisherDiagnosticName(phase.Name) || !publisherDiagnosticName(component) || phase.Start.IsZero() || phase.Duration <= 0 || phase.Duration > 5*time.Minute {
		return nil, errors.New("publisher late recorder needs coordination, simple phase/component names, an epoch, and a duration in (0, 5m]")
	}
	// phase.Start crossed JSON and has no monotonic reading. rebase once using
	// local wall time, then use only the resulting local monotonic clock.
	before := time.Now()
	epoch := before.Add(phase.Start.Sub(before))
	after := time.Now()
	waitTimeout := phase.Duration + 15*time.Second
	runCtx, cancel := context.WithTimeout(ctx, waitTimeout)
	deadline, _ := runCtx.Deadline()
	d := &postgresPublisherLate{coordination: coordination, epoch: epoch, ctx: runCtx, cancel: cancel, done: make(chan struct{})}
	d.receipt = postgresPublisherLateReceipt{
		Phase: phase.Name, Component: component, PublisherPID: os.Getpid(),
		PhaseStart: phase.Start, LocalEpoch: epoch, RebaseStarted: before, RebaseCompleted: after,
		RebaseReadWidth: after.Sub(before), Duration: phase.Duration, WaitTimeout: waitTimeout, WaitDeadline: deadline.Sub(epoch),
		TraceLimit: postgresLateTraceLimit, TraceStatus: "no-event", MarkerStatus: "not-emitted", HoldStatus: "not-requested", ExportStatus: "not-requested",
		Coverage: "unverified; inspect the trace externally to establish retained history, marker, and post-trigger coverage",
		Notes: []string{
			"all offsets/durations are nanoseconds relative to a locally rebased monotonic phase epoch; wall-clock reads and their bounds do not establish exact cross-process clock alignment or network delay",
			"Trigger preserves the visitor payload without translating its offsets; Received and MarkerPhaseNS use the publisher epoch; do not subtract them as exact cross-process durations",
			"flight recorder MinAge=5s and MaxBytes=8MiB are hints, not coverage or hard memory bounds; output is capped at 16MiB; arming, trace markers, WriteTo, and Stop perturb the publisher runtime",
			"publisher receipt/snapshot markers are emitted on the recorder owner, not a query/stream worker; SnapshotPhaseNS precedes WriteTo with its own call bounds; no SQL, credentials, query bodies, or wire bytes are recorded by this helper",
			"the tail requests 1s after publisher receipt, even beyond phase end; scheduling, WriteTo, and Stop have no hard wall-time bound; cancellation requests a best-effort partial snapshot",
			"Hold bounds bracket the actual wait; PostTriggerActual runs from Received through wait completion and includes marker work; coordinator waits share a duration+15s timeout from startup, capped by the parent deadline",
			"existing publisher metrics/allocation diagnostics can write during the first 10s; use a matched metrics baseline; this helper adds no sampler or production instrumentation",
			"successful disk export requires late-finished and the resource-after-capture export barrier; abort exports are not evidence that the resource guard passed; Export bounds exclude the final receipt write",
		},
	}
	d.traceBytes = make([]byte, postgresLateTraceLimit)
	d.receipt.Arm.Started = time.Since(epoch)
	recorder := trace.NewFlightRecorder(trace.FlightRecorderConfig{MinAge: 5 * time.Second, MaxBytes: 8 << 20})
	err := recorder.Start()
	d.receipt.Arm.Completed = time.Since(epoch)
	if err != nil {
		d.receipt.TraceStatus = "start-failed"
		d.err = fmt.Errorf("start publisher flight recorder: %w", err)
	} else if d.receipt.Arm.Completed >= 0 {
		d.receipt.TraceStatus = "late-arm"
		d.err = errors.New("publisher flight recorder armed at or after phase start; pre-phase coverage unavailable")
		d.stop(recorder)
	} else if err := runCtx.Err(); err != nil {
		d.receipt.TraceStatus = "start-cancelled"
		d.err = err
		d.stop(recorder)
	}
	if d.err != nil {
		close(d.done)
		return d, d.err
	}
	go d.run(recorder)
	return d, nil
}

type postgresPublisherLateEvent struct {
	trigger  postgresLateTrigger
	finished bool
	bounds   postgresPublisherLateBounds
	err      error
}

func (d *postgresPublisherLate) run(recorder *trace.FlightRecorder) {
	waitCtx, cancel := context.WithCancel(d.ctx)
	trigger, finished := make(chan postgresPublisherLateEvent, 1), make(chan postgresPublisherLateEvent, 1)
	var waiters sync.WaitGroup
	wait := func(name string, isTrigger bool, output chan<- postgresPublisherLateEvent) {
		defer waiters.Done()
		e := postgresPublisherLateEvent{bounds: postgresPublisherLateBounds{Started: time.Since(d.epoch)}}
		if isTrigger {
			e.err = d.coordination.Wait(waitCtx, name, &e.trigger)
		} else {
			e.err = d.coordination.Wait(waitCtx, name, &e.finished)
		}
		e.bounds.Completed = time.Since(d.epoch)
		output <- e
	}
	waiters.Add(2)
	go wait(d.receipt.Phase+".late-trigger", true, trigger)
	go wait(d.receipt.Phase+".late-finished", false, finished)
	defer func() {
		cancel()
		waiters.Wait()
		d.err = errors.Join(d.err, d.ctx.Err())
		d.receipt.Cancelled = d.ctx.Err() != nil
		if d.err != nil && d.receipt.TraceBytes > 0 {
			d.partial()
		}
		close(d.done)
	}()
	var event postgresLateTrigger
	hasEvent := false
	finishedRead := false
	select {
	case e := <-trigger:
		d.receipt.TriggerRead = e.bounds
		d.err = e.err
		event, hasEvent = e.trigger, e.err == nil
	case e := <-finished:
		finishedRead = true
		d.acceptFinished(e)
		if d.err == nil {
			// late-finished is published only after visitor Finish joins Notify.
			// a delayed trigger HTTP response must not turn a real event into no-event.
			d.receipt.FinalTriggerRead.Started = time.Since(d.epoch)
			hasEvent, d.err = d.coordination.Get(d.ctx, d.receipt.Phase+".late-trigger", &event)
			d.receipt.FinalTriggerRead.Completed = time.Since(d.epoch)
			d.receipt.TriggerRead = d.receipt.FinalTriggerRead
		}
	}
	if hasEvent {
		d.receipt.Trigger = &event
		d.receipt.Received = d.receipt.TriggerRead.Completed
		d.receipt.Marker.Started = time.Since(d.epoch)
		d.receipt.MarkerPhaseNS = d.receipt.Marker.Started
		trace.Logf(context.Background(), "postgres-publisher-late-outlier", "phase=%s component=%s slot=%d kind=%s visitor_started_ns=%d visitor_completed_ns=%d visitor_observed_ns=%d publisher_phase_ns=%d", d.receipt.Phase, d.receipt.Component, event.Slot, event.Kind, event.Started, event.Completed, event.Observed, d.receipt.MarkerPhaseNS)
		d.receipt.Marker.Completed = time.Since(d.epoch)
		d.receipt.MarkerStatus = "emitted-on-recorder-owner; retention-and-cross-process-alignment-unverified"
		d.receipt.PostTriggerRequested = postgresLatePostTrigger
		d.receipt.Hold.Started = time.Since(d.epoch)
		d.receipt.HoldDeadline = d.receipt.Received + postgresLatePostTrigger
		d.receipt.HoldStatus = "completed"
		if err := waitPublisherDiagnostic(d.ctx, d.epoch.Add(d.receipt.HoldDeadline)); err != nil {
			d.err = errors.Join(d.err, err)
			d.receipt.HoldStatus = "cancelled"
		}
		d.receipt.Hold.Completed = time.Since(d.epoch)
		d.receipt.PostTriggerActual = d.receipt.Hold.Completed - d.receipt.Received
	}
	if hasEvent || d.err != nil {
		d.snapshot(recorder)
	}
	d.stop(recorder)
	if !finishedRead {
		d.acceptFinished(<-finished)
	}
}

func (d *postgresPublisherLate) acceptFinished(e postgresPublisherLateEvent) {
	d.receipt.FinishedRead = e.bounds
	d.err = errors.Join(d.err, e.err)
	if e.err == nil {
		if !e.finished {
			d.err = errors.Join(d.err, errors.New("publisher late-finished sentinel was not true"))
		} else {
			d.receipt.Finished = true
		}
	}
}

func (d *postgresPublisherLate) snapshot(recorder *trace.FlightRecorder) {
	d.receipt.SnapshotMarker.Started = time.Since(d.epoch)
	d.receipt.SnapshotPhaseNS = d.receipt.SnapshotMarker.Started
	slot := -1
	if d.receipt.Trigger != nil {
		slot = d.receipt.Trigger.Slot
	}
	trace.Logf(context.Background(), "postgres-publisher-late-snapshot", "phase=%s component=%s slot=%d publisher_phase_ns=%d", d.receipt.Phase, d.receipt.Component, slot, d.receipt.SnapshotPhaseNS)
	d.receipt.SnapshotMarker.Completed = time.Since(d.epoch)
	d.receipt.Snapshot.Started = time.Since(d.epoch)
	w := &postgresLateWriter{data: d.traceBytes}
	_, err := recorder.WriteTo(w)
	d.receipt.Snapshot.Completed = time.Since(d.epoch)
	d.receipt.TraceBytes = w.used
	d.traceBytes = d.traceBytes[:w.used]
	d.receipt.TraceStatus, d.receipt.TraceFile = "captured", "publisher.trace"
	if err != nil {
		d.err = errors.Join(d.err, fmt.Errorf("snapshot publisher flight recorder: %w", err))
		d.receipt.TraceStatus = "capture-failed"
	}
	if d.err != nil || d.ctx.Err() != nil {
		d.partial()
	}
}

func (d *postgresPublisherLate) partial() {
	d.receipt.TracePartial, d.receipt.TraceFile = true, "publisher.trace.partial"
	if d.receipt.TraceStatus == "captured" {
		d.receipt.TraceStatus = "captured-partial"
	}
}

func (d *postgresPublisherLate) stop(recorder *trace.FlightRecorder) {
	d.receipt.Stop.Started = time.Since(d.epoch)
	recorder.Stop()
	d.receipt.Stop.Completed = time.Since(d.epoch)
}

// Finish joins without cancelling normal recording or its post-trigger tail.
// call after existing publisher Capture, before publisher-diagnostics-done.
// directory should be /results/publisher-late-<phase>-<component> and must not
// exist. ctx cancellation/deadline bounds coordinator waits and shortens the
// tail; runtime WriteTo/Stop themselves cannot be interrupted safely.
func (d *postgresPublisherLate) Finish(directory string) error {
	if d == nil {
		return nil
	}
	d.finish.Do(func() {
		defer d.cancel()
		defer func() { d.traceBytes = nil }()
		<-d.done
		d.receipt.ExportWait.Started = time.Since(d.epoch)
		var authorized bool
		err := d.ctx.Err()
		if err == nil {
			err = d.coordination.Wait(d.ctx, d.receipt.Phase+".export", &authorized)
			if err == nil && !authorized {
				err = errors.New("publisher export barrier was not true")
			}
		}
		d.receipt.ExportWait.Completed = time.Since(d.epoch)
		d.err = errors.Join(d.err, err)
		d.receipt.ExportAuthorized = err == nil && authorized
		d.receipt.ExportStatus = "authorized"
		if !d.receipt.ExportAuthorized {
			d.receipt.ExportStatus = "abort-best-effort; resource-guard-unconfirmed"
		}
		d.receipt.Cancelled = d.receipt.Cancelled || d.ctx.Err() != nil
		if d.err != nil && d.receipt.TraceBytes > 0 {
			d.partial()
		}
		d.receipt.Export.Started = time.Since(d.epoch)
		if err := os.Mkdir(directory, 0o700); err != nil {
			d.finishErr = errors.Join(d.err, fmt.Errorf("create publisher late directory (receipt unavailable): %w", err))
			return
		}
		if d.receipt.TraceFile != "" {
			d.err = errors.Join(d.err, writePublisherDiagnostic(directory, d.receipt.TraceFile, func(w io.Writer) error {
				_, err := w.Write(d.traceBytes)
				return err
			}))
		}
		d.receipt.Export.Completed = time.Since(d.epoch)
		if d.err != nil {
			d.receipt.Error = d.err.Error()
		}
		d.finishErr = errors.Join(d.err, writePublisherDiagnosticJSON(directory, "receipt.json", d.receipt))
	})
	return d.finishErr
}
