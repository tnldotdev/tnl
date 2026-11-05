package runtimetrace

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/trace"
	"time"
)

type Bounds struct{ Started, Completed time.Duration }

type Receipt struct {
	Phase, Component, GOOS, GOARCH                   string
	PID                                              int
	PhaseStart, LocalEpoch                           time.Time
	RebaseStarted, RebaseCompleted                   time.Time
	Duration, RebaseReadWidth                        time.Duration
	Arm, Read, Marker, Hold, SnapshotMarker          Bounds
	Snapshot, Stop, Export                           Bounds
	TriggerRead, ExportRead                          Bounds
	Received, MarkerPhaseNS, SnapshotPhaseNS         time.Duration
	PostTriggerRequested, PostTriggerActual          time.Duration
	Event                                            *Event
	TraceBytes, TraceLimit, Commands                 int
	TraceStatus, TraceFile, HoldStatus, ExportStatus string
	Partial, Cancelled, ExportAuthorized             bool
	Coverage, Notes, Error                           string
}

type recorderOwner struct {
	epoch          time.Time
	recorder       *trace.FlightRecorder
	data           []byte
	receipt        Receipt
	err            error
	exported       bool
	directoryOwned bool
}

// Run owns both descriptors, one synchronous command loop, and the process-wide
// recorder. EOF/cancellation/errors snapshot before stopping and attempt private
// partial artifacts, without inventing a trigger or export authorization.
// only explicit EXPORT authorizes normal artifact writes. runtime WriteTo/Stop
// cannot safely be interrupted; context cancellation closes blocked pipe I/O.
func Run(ctx context.Context, commands, replies *os.File, directory string) (result error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	closeIO := func() { _ = commands.Close(); _ = replies.Close() }
	stopClose := context.AfterFunc(ctx, closeIO)
	defer stopClose()
	defer closeIO()
	d := &recorderOwner{epoch: time.Now()}
	d.receipt = Receipt{PID: os.Getpid(), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, TraceLimit: TraceLimit, TraceStatus: "not-armed", ExportStatus: "not-requested", Coverage: "unverified; parse retained history, markers, and tail externally", Notes: "offsets use one locally rebased monotonic epoch, not exact cross-process clock conversion; MinAge=5s and MaxBytes=8MiB are hints, output cap=16MiB; recorder work perturbs this runtime; markers run on the recorder owner, not a query worker; 1s tail requested from local receipt; scheduling, WriteTo and Stop have no hard wall-time bound; export bounds exclude final receipt write; no SQL, payload, credentials, or arguments are recorded by this helper"}
	defer func() {
		if ctx.Err() != nil {
			d.fail("recorder context cancelled")
			d.receipt.Cancelled = true
		}
		d.abort(ctx)
		if !d.exported {
			d.export(directory, false)
		}
		result = d.err
	}()
	decoder := NewDecoder(commands)
	var timeout *time.Timer
	defer func() {
		if timeout != nil {
			timeout.Stop()
		}
	}()
	for n := 1; n <= MaxCommands; n++ {
		var c Command
		readStarted := time.Now()
		err := decoder.Read(&c)
		readCompleted := time.Now()
		read := Bounds{Started: readStarted.Sub(d.epoch), Completed: readCompleted.Sub(d.epoch)}
		if err != nil {
			if errors.Is(err, io.EOF) {
				d.fail("command pipe EOF before export")
			} else {
				d.fail("command frame read failed")
			}
			return nil
		}
		d.receipt.Commands = n
		err = c.Validate()
		if err == nil && c.ID != n {
			err = errors.New("command ID out of order")
		}
		if err != nil {
			d.fail(err.Error())
		} else {
			switch c.Kind {
			case Arm:
				if n != 1 {
					d.fail("arm must be first and unique")
					break
				}
				// JSON timestamps have no monotonic reading. rebase exactly once;
				// retain read bounds without claiming exact clock alignment.
				before := time.Now()
				d.epoch = before.Add(c.Start.Sub(before))
				after := time.Now()
				d.receipt.Phase, d.receipt.Component = c.Phase, c.Component
				d.receipt.PhaseStart, d.receipt.LocalEpoch = c.Start, d.epoch
				d.receipt.RebaseStarted, d.receipt.RebaseCompleted = before, after
				d.receipt.RebaseReadWidth, d.receipt.Duration = after.Sub(before), c.Duration
				d.receipt.Read = Bounds{Started: readStarted.Sub(d.epoch), Completed: readCompleted.Sub(d.epoch)}
				d.arm()
				timeout = time.AfterFunc(c.Duration+15*time.Second, cancel)
			case Trigger:
				d.receipt.TriggerRead = read
				if d.recorder == nil || d.receipt.Event != nil || d.err != nil {
					d.fail("trigger requires one healthy armed recorder")
					break
				}
				d.capture(ctx, c.Event)
			case Export:
				d.receipt.ExportRead = read
				if d.receipt.Phase == "" {
					d.fail("export before arm")
				}
				d.stop()
				d.export(directory, true)
			}
		}
		if d.err != nil {
			d.abort(ctx)
		}
		kind := c.Kind
		if kind != Arm && kind != Trigger && kind != Export {
			kind = "" // never echo invalid input, even in the private reply.
		}
		r := Reply{ID: c.ID, Kind: kind, Receipt: &d.receipt}
		if d.err != nil {
			r.Error = d.err.Error()
		}
		if WriteFrame(replies, r) != nil {
			d.fail("reply pipe write failed")
			// retain the acknowledgement failure if an export already happened.
			if d.directoryOwned {
				d.writeReceipt(directory)
			}
			return nil
		}
		if c.Kind == Export && err == nil {
			return nil
		}
	}
	d.fail("command limit exceeded before export")
	return nil
}

func (d *recorderOwner) fail(message string) {
	// messages are fixed, bounded labels, never decoded input or OS paths.
	if d.err == nil {
		d.err = errors.New(message)
	} else if len(d.err.Error()) < 500 {
		d.err = errors.Join(d.err, errors.New(message))
	}
	d.receipt.Error = d.err.Error()
}

func (d *recorderOwner) arm() {
	d.data = make([]byte, TraceLimit)
	d.receipt.Arm.Started = time.Since(d.epoch)
	r := trace.NewFlightRecorder(trace.FlightRecorderConfig{MinAge: 5 * time.Second, MaxBytes: 8 << 20})
	if r.Start() != nil {
		d.fail("start native flight recorder failed")
		d.receipt.TraceStatus = "start-failed"
	} else {
		d.recorder = r
		d.receipt.TraceStatus = "no-event"
	}
	d.receipt.Arm.Completed = time.Since(d.epoch)
	if d.recorder != nil && d.receipt.Arm.Completed >= 0 {
		d.fail("native flight recorder armed at or after phase start")
		d.receipt.TraceStatus = "late-arm"
	}
}

func (d *recorderOwner) capture(ctx context.Context, event *Event) {
	d.receipt.Event = event
	d.receipt.Received = time.Since(d.epoch)
	d.receipt.Marker.Started = time.Since(d.epoch)
	d.receipt.MarkerPhaseNS = d.receipt.Marker.Started
	trace.Logf(ctx, "postgres-native-late-outlier", "phase=%s component=%s slot=%d kind=%s visitor_started_ns=%d visitor_completed_ns=%d visitor_observed_ns=%d native_phase_ns=%d", d.receipt.Phase, d.receipt.Component, event.Slot, event.Kind, event.Started, event.Completed, event.Observed, d.receipt.MarkerPhaseNS)
	d.receipt.Marker.Completed = time.Since(d.epoch)
	d.receipt.PostTriggerRequested = PostTrigger
	d.receipt.Hold.Started = time.Since(d.epoch)
	timer := time.NewTimer(max(0, time.Until(d.epoch.Add(d.receipt.Received+PostTrigger))))
	d.receipt.HoldStatus = "completed"
	select {
	case <-timer.C:
	case <-ctx.Done():
		d.receipt.Cancelled = true
		d.receipt.HoldStatus = "cancelled"
		d.fail("native trace tail cancelled")
	}
	timer.Stop()
	d.receipt.Hold.Completed = time.Since(d.epoch)
	d.receipt.PostTriggerActual = d.receipt.Hold.Completed - d.receipt.Received
	d.snapshot(ctx, d.err != nil || ctx.Err() != nil)
	d.stop()
}

// snapshot is synchronous and can run with a cancelled context: runtime WriteTo
// is not interruptible. a retained snapshot is never taken a second time.
func (d *recorderOwner) snapshot(ctx context.Context, partial bool) {
	if d.recorder == nil || d.receipt.TraceFile != "" {
		return
	}
	d.receipt.SnapshotMarker.Started = time.Since(d.epoch)
	d.receipt.SnapshotPhaseNS = d.receipt.SnapshotMarker.Started
	if d.receipt.Event == nil {
		trace.Logf(ctx, "postgres-native-late-abort-snapshot", "phase=%s component=%s native_phase_ns=%d", d.receipt.Phase, d.receipt.Component, d.receipt.SnapshotPhaseNS)
	} else {
		trace.Logf(ctx, "postgres-native-late-snapshot", "phase=%s component=%s slot=%d native_phase_ns=%d", d.receipt.Phase, d.receipt.Component, d.receipt.Event.Slot, d.receipt.SnapshotPhaseNS)
	}
	d.receipt.SnapshotMarker.Completed = time.Since(d.epoch)
	d.receipt.Snapshot.Started = time.Since(d.epoch)
	w := &boundedWriter{data: d.data}
	_, err := d.recorder.WriteTo(w)
	d.receipt.Snapshot.Completed = time.Since(d.epoch)
	d.data = d.data[:w.used]
	d.receipt.TraceBytes, d.receipt.TraceFile = w.used, "native.trace"
	d.receipt.TraceStatus = "captured"
	if err != nil {
		d.fail("snapshot native flight recorder failed")
		d.receipt.TraceStatus = "capture-failed"
	}
	if partial || err != nil {
		d.partial()
	}
}

func (d *recorderOwner) partial() {
	d.receipt.Partial = true
	d.receipt.TraceFile = "native.trace.partial"
	if d.receipt.TraceStatus == "captured" {
		d.receipt.TraceStatus = "captured-partial"
	}
}

func (d *recorderOwner) abort(ctx context.Context) {
	d.snapshot(ctx, true)
	d.stop()
}

func (d *recorderOwner) stop() {
	if d.recorder == nil {
		return
	}
	d.receipt.Stop.Started = time.Since(d.epoch)
	d.recorder.Stop()
	d.receipt.Stop.Completed = time.Since(d.epoch)
	d.recorder = nil
}

func (d *recorderOwner) export(directory string, authorized bool) {
	d.exported = true
	d.receipt.ExportAuthorized = authorized
	d.receipt.ExportStatus = "authorized"
	if !authorized {
		d.receipt.ExportStatus = "abort-best-effort; resource-guard-unconfirmed"
	}
	if d.err != nil && d.receipt.TraceFile != "" {
		d.partial()
	}
	d.receipt.Export.Started = time.Since(d.epoch)
	if os.Mkdir(directory, 0o700) != nil {
		d.fail("create private native trace directory failed; receipt retained in reply")
		d.receipt.Export.Completed = time.Since(d.epoch)
		return
	}
	d.directoryOwned = true
	if d.receipt.TraceFile != "" {
		if writePrivate(directory, d.receipt.TraceFile, d.data) != nil {
			d.fail("write native trace artifact failed")
			d.receipt.Partial = true
			d.receipt.TraceStatus = "export-failed"
		}
	}
	d.receipt.Export.Completed = time.Since(d.epoch)
	d.writeReceipt(directory)
	d.data = nil
}

func (d *recorderOwner) writeReceipt(directory string) {
	b, err := json.MarshalIndent(d.receipt, "", "  ")
	if err != nil {
		d.fail("encode native trace receipt failed")
		return
	}
	// replace only our own receipt after a reply error; never follow a symlink.
	temporary := "receipt.pending.json"
	if writePrivate(directory, temporary, append(b, '\n')) != nil || os.Rename(filepath.Join(directory, temporary), filepath.Join(directory, "receipt.json")) != nil {
		d.fail("write native trace receipt failed; receipt retained in reply")
	}
}

func writePrivate(directory, name string, data []byte) error {
	f, err := os.OpenFile(filepath.Join(directory, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	return errors.Join(writeErr, f.Close())
}

type boundedWriter struct {
	data []byte
	used int
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	n := copy(w.data[w.used:], p)
	w.used += n
	if n != len(p) {
		return n, errors.New("trace output limit exceeded")
	}
	return n, nil
}
