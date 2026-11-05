package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/trace"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/benchworkload"
)

var postgresPublisherLateTestChild = flag.String("tnl-postgres-publisher-late-test-child", "", "isolated publisher late-recorder test")

func TestPostgresPublisherLateRecorder(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"capture", "sentinel-first", "no-event", "cancelled-tail", "cancelled-wait", "deadline-wait", "start-failed", "late-arm", "bounded-output", "existing-directory", "export-cancelled"} {
		t.Run(mode, func(t *testing.T) {
			// each child owns its real recorder; do not inherit -test.trace.
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestPostgresPublisherLateRecorderChild$", "-test.count=1", "-tnl-postgres-publisher-late-test-child="+mode)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("isolated publisher recorder: %v\n%s", err, output)
			}
		})
	}
}

func TestPostgresPublisherLateInvalid(t *testing.T) {
	coordination, err := benchworkload.NewCoordination("http://127.0.0.1:1", "test")
	if err != nil {
		t.Fatal(err)
	}
	valid := connectLoadPhase{Name: "phase", Start: time.Now().Add(time.Hour), Duration: time.Second}
	for _, phase := range []connectLoadPhase{{}, {Name: "../phase", Start: valid.Start, Duration: time.Second}, {Name: valid.Name, Duration: time.Second}, {Name: valid.Name, Start: valid.Start, Duration: 6 * time.Minute}} {
		if d, err := startPostgresPublisherLate(t.Context(), coordination, phase, "publisher"); err == nil || d != nil {
			t.Fatalf("invalid phase accepted: %+v owner=%v error=%v", phase, d, err)
		}
	}
	if d, err := startPostgresPublisherLate(t.Context(), nil, valid, "publisher"); err == nil || d != nil {
		t.Fatalf("nil coordination accepted: owner=%v error=%v", d, err)
	}
	if d, err := startPostgresPublisherLate(t.Context(), coordination, valid, "../publisher"); err == nil || d != nil {
		t.Fatalf("invalid component accepted: owner=%v error=%v", d, err)
	}
	if err := (*postgresPublisherLate)(nil).Finish("unused"); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresPublisherLateRecorderChild(t *testing.T) {
	mode := *postgresPublisherLateTestChild
	if mode == "" {
		t.Skip("only run in an isolated subprocess")
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	phase := connectLoadPhase{Name: "late-phase", Start: time.Now().Add(300 * time.Millisecond), Duration: 200 * time.Millisecond}
	if mode == "deadline-wait" {
		deadlineCtx, deadlineCancel := context.WithDeadline(ctx, phase.Start.Add(100*time.Millisecond))
		defer deadlineCancel()
		ctx = deadlineCtx
	}
	coordinator := benchworkload.NewCoordinator()
	handler := coordinator.Handler("test-token")
	blocked, exited := make(chan struct{}), make(chan struct{})
	var blockedOnce sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mode == "sentinel-first" && r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, ".late-trigger") && r.URL.Query().Get("wait") == "1" {
			// Notify has committed the event, but its waiting HTTP reader is delayed.
			// late-finished wins; the nonwaiting Get must retrieve that exact event.
			blockedOnce.Do(func() { close(blocked) })
			<-r.Context().Done()
			close(exited)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	defer func() {
		cancel()
		server.Close()
	}()
	coordination, err := benchworkload.NewCoordination(server.URL, "test-token")
	if err != nil {
		t.Fatal(err)
	}
	if mode == "start-failed" {
		other := trace.NewFlightRecorder(trace.FlightRecorderConfig{})
		if err := other.Start(); err != nil {
			t.Fatal(err)
		}
		defer other.Stop()
	}
	if mode == "late-arm" {
		phase.Start = time.Now().Add(-time.Millisecond)
	}
	d, startErr := startPostgresPublisherLate(ctx, coordination, phase, "publisher-0")
	if d == nil {
		t.Fatal(startErr)
	}
	startupFailure := mode == "start-failed" || mode == "late-arm"
	if (startErr != nil) != startupFailure {
		t.Fatalf("startup error=%v receipt=%+v", startErr, d.receipt)
	}
	if mode == "bounded-output" {
		// no trigger can be delivered until the driver below starts.
		d.traceBytes = d.traceBytes[:64:64]
	}
	directory := filepath.Join(t.TempDir(), "publisher-late-"+phase.Name+"-publisher-0")
	if mode == "existing-directory" {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "receipt.json"), []byte("preserve"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	event := postgresLateTrigger{Slot: 17, Kind: "query", Started: 30 * time.Millisecond, Completed: 60 * time.Millisecond, Observed: 61 * time.Millisecond, TriggerLag: time.Millisecond, MarkerStarted: 62 * time.Millisecond, MarkerCompleted: 63 * time.Millisecond, MarkerEmitted: true}
	driverDone := make(chan error, 1)
	go func() {
		put := func(suffix string, value any) error {
			return coordination.Put(t.Context(), phase.Name+suffix, value)
		}
		if startupFailure {
			driverDone <- put(".export", true)
			return
		}
		if err := waitPublisherDiagnostic(ctx, phase.Start); err != nil {
			driverDone <- err
			return
		}
		if mode == "cancelled-wait" {
			cancel()
			driverDone <- nil
			return
		}
		if mode == "deadline-wait" {
			<-ctx.Done()
			driverDone <- nil
			return
		}
		if mode == "no-event" || mode == "existing-directory" || mode == "export-cancelled" {
			if err := waitPublisherDiagnostic(ctx, phase.Start.Add(phase.Duration)); err != nil {
				driverDone <- err
				return
			}
		} else {
			trace.Log(context.Background(), "postgres-publisher-late-test-before", "slot=17")
			if err := put(".late-trigger", event); err != nil {
				driverDone <- err
				return
			}
			if mode == "cancelled-tail" {
				if err := waitPublisherDiagnostic(ctx, phase.Start.Add(100*time.Millisecond)); err != nil {
					driverDone <- err
					return
				}
				cancel()
				driverDone <- nil
				return
			}
			if mode == "sentinel-first" {
				<-blocked
			} else {
				// the requested publisher tail must retain an actual marker well
				// beyond phase end, not just report a requested duration.
				if err := waitPublisherDiagnostic(ctx, phase.Start.Add(800*time.Millisecond)); err != nil {
					driverDone <- err
					return
				}
				trace.Log(context.Background(), "postgres-publisher-late-test-tail", "slot=17")
				if err := waitPublisherDiagnostic(ctx, phase.Start.Add(1100*time.Millisecond)); err != nil {
					driverDone <- err
					return
				}
			}
		}
		if err := put(".late-finished", true); err != nil {
			driverDone <- err
			return
		}
		<-d.done
		if mode != "existing-directory" {
			if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
				driverDone <- fmt.Errorf("artifacts appeared before export authorization: %v", err)
				return
			}
		}
		if mode == "export-cancelled" {
			cancel()
			driverDone <- nil
			return
		}
		if err := waitPublisherDiagnostic(ctx, time.Now().Add(50*time.Millisecond)); err != nil {
			driverDone <- err
			return
		}
		driverDone <- put(".export", true)
	}()
	// call immediately: this must join, not cancel, the pending phase and tail.
	finishStarted := time.Now()
	err = d.Finish(directory)
	finishDuration := time.Since(finishStarted)
	if driverErr := <-driverDone; driverErr != nil {
		t.Fatal(driverErr)
	}
	select {
	case <-d.done:
	default:
		t.Fatal("Finish did not join recorder and HTTP waiters")
	}
	if d.traceBytes != nil {
		t.Fatal("Finish retained the trace output buffer")
	}
	if mode != "start-failed" {
		// a new consumer must be able to start after Finish joins Stop.
		next := trace.NewFlightRecorder(trace.FlightRecorderConfig{})
		if err := next.Start(); err != nil {
			t.Fatalf("Finish left the recorder active: %v", err)
		}
		next.Stop()
	}
	repeatedDirectory := filepath.Join(t.TempDir(), "must-not-exist")
	if repeated := d.Finish(repeatedDirectory); repeated != err {
		t.Fatalf("Finish not idempotent: first=%v repeated=%v", err, repeated)
	}
	if _, err := os.Stat(repeatedDirectory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("repeated Finish wrote another directory: %v", err)
	}
	if mode == "existing-directory" {
		data, readErr := os.ReadFile(filepath.Join(directory, "receipt.json"))
		if !errors.Is(err, os.ErrExist) || readErr != nil || string(data) != "preserve" {
			t.Fatalf("existing artifacts were not preserved: error=%v read=%v data=%q", err, readErr, data)
		}
		return
	}
	r := readPostgresPublisherLateReceipt(t, directory)
	assertPostgresPublisherLatePermissions(t, directory)
	if !strings.Contains(r.Coverage, "unverified") || r.Arm.Completed < r.Arm.Started || r.RebaseReadWidth < 0 || r.WaitTimeout != phase.Duration+15*time.Second || r.TraceLimit != postgresLateTraceLimit {
		t.Fatalf("invalid startup/coverage bounds: %+v", r)
	}
	cancelled := strings.HasPrefix(mode, "cancelled-") || mode == "export-cancelled" || mode == "deadline-wait"
	if cancelled {
		cause := context.Canceled
		if mode == "deadline-wait" {
			cause = context.DeadlineExceeded
			if r.WaitDeadline > 150*time.Millisecond {
				t.Fatalf("coordinator waits did not inherit the parent deadline: %+v", r)
			}
		}
		if !errors.Is(err, cause) || !r.Cancelled || r.ExportAuthorized || !strings.Contains(r.ExportStatus, "resource-guard-unconfirmed") {
			t.Fatalf("abort error=%v receipt=%+v", err, r)
		}
	} else if !r.ExportAuthorized || r.Export.Started < r.ExportWait.Completed {
		t.Fatalf("export bypassed the barrier: error=%v receipt=%+v", err, r)
	}
	if startupFailure {
		wantStatus := "start-failed"
		if mode == "late-arm" {
			wantStatus = "late-arm"
		}
		if err == nil || r.TraceStatus != wantStatus || r.TraceBytes != 0 || r.TraceFile != "" || r.MarkerStatus != "not-emitted" {
			t.Fatalf("startup failure error=%v receipt=%+v", err, r)
		}
		return
	}
	if !cancelled && !r.Finished {
		t.Fatalf("Finish did not join the visitor final sentinel: %+v", r)
	}
	if mode == "no-event" || mode == "export-cancelled" {
		if (!cancelled && err != nil) || r.TraceStatus != "no-event" || r.Trigger != nil || r.TraceBytes != 0 || r.TraceFile != "" || r.PostTriggerRequested != 0 || r.MarkerStatus != "not-emitted" || finishDuration >= time.Second {
			t.Fatalf("no-event error=%v Finish=%s receipt=%+v", err, finishDuration, r)
		}
		return
	}
	if mode == "cancelled-wait" || mode == "deadline-wait" {
		if !r.TracePartial || r.TraceBytes == 0 || r.TraceStatus != "captured-partial" || r.Trigger != nil || r.MarkerStatus != "not-emitted" {
			t.Fatalf("cancelled waiting did not preserve a best-effort snapshot: %+v", r)
		}
		return
	}
	if r.Trigger == nil || *r.Trigger != event || r.PostTriggerRequested != time.Second || r.Hold.Started < r.Marker.Completed || r.HoldDeadline != r.Received+time.Second || r.PostTriggerActual != r.Hold.Completed-r.Received || r.Snapshot.Started < r.Hold.Completed || r.Stop.Started < r.Snapshot.Completed || r.Stop.Completed < r.Stop.Started || r.Marker.Started < r.Received || r.MarkerPhaseNS != r.Marker.Started || r.Marker.Completed < r.Marker.Started {
		t.Fatalf("event payload or lifecycle bounds lost: %+v", r)
	}
	if mode == "cancelled-tail" {
		if r.HoldStatus != "cancelled" || r.PostTriggerActual >= time.Second || !r.TracePartial || r.TraceStatus != "captured-partial" || r.TraceBytes == 0 || r.TraceFile != "publisher.trace.partial" {
			t.Fatalf("cancel did not shorten and preserve the tail: %+v", r)
		}
		return
	}
	if r.HoldStatus != "completed" || r.PostTriggerActual < time.Second || r.Snapshot.Started < r.HoldDeadline || r.Hold.Completed <= phase.Duration {
		t.Fatalf("normal Finish shortened the post-trigger tail: %+v", r)
	}
	if mode == "bounded-output" {
		if !errors.Is(err, errPostgresLateTraceLimit) || r.TraceStatus != "capture-failed" || !r.TracePartial || r.TraceBytes != 64 || r.TraceFile != "publisher.trace.partial" {
			t.Fatalf("bounded capture error=%v receipt=%+v", err, r)
		}
		data, readErr := os.ReadFile(filepath.Join(directory, r.TraceFile))
		if readErr != nil || len(data) != 64 {
			t.Fatalf("bounded output size=%d error=%v", len(data), readErr)
		}
		return
	}
	if err != nil || r.TraceStatus != "captured" || r.TracePartial || r.TraceBytes == 0 || r.TraceBytes > postgresLateTraceLimit || r.TraceFile != "publisher.trace" {
		t.Fatalf("capture error=%v receipt=%+v", err, r)
	}
	logs := readPostgresLateTraceLogs(t, filepath.Join(directory, r.TraceFile))
	marker := logs["postgres-publisher-late-outlier"]
	wantMessage := fmt.Sprintf("phase=%s component=publisher-0 slot=17 kind=query visitor_started_ns=%d visitor_completed_ns=%d visitor_observed_ns=%d publisher_phase_ns=%d", phase.Name, event.Started, event.Completed, event.Observed, r.MarkerPhaseNS)
	if len(marker) != 1 || marker[0].Task != 0 || marker[0].Message != wantMessage || !strings.Contains(r.MarkerStatus, "unverified") {
		t.Fatalf("actual trace marker=%+v expected=%q receipt=%+v", marker, wantMessage, r)
	}
	snapshot := logs["postgres-publisher-late-snapshot"]
	wantSnapshot := fmt.Sprintf("phase=%s component=publisher-0 slot=17 publisher_phase_ns=%d", phase.Name, r.SnapshotPhaseNS)
	if len(snapshot) != 1 || snapshot[0].Goroutine != marker[0].Goroutine || snapshot[0].Message != wantSnapshot || snapshot[0].Time-marker[0].Time < int64(950*time.Millisecond) || r.SnapshotPhaseNS != r.SnapshotMarker.Started || r.SnapshotMarker.Started < r.Hold.Completed || r.SnapshotMarker.Completed < r.SnapshotMarker.Started || r.Snapshot.Started < r.SnapshotMarker.Completed {
		t.Fatalf("actual snapshot marker/bounds missing: snapshot=%+v marker=%+v receipt=%+v", snapshot, marker, r)
	}
	if mode == "sentinel-first" {
		if r.FinalTriggerRead.Completed == 0 {
			t.Fatal("finished-first did not do the final nonwaiting trigger read")
		}
		select {
		case <-exited:
		case <-time.After(time.Second):
			t.Fatal("delayed trigger waiter was not cancelled/joined")
		}
	} else {
		before, tail := logs["postgres-publisher-late-test-before"], logs["postgres-publisher-late-test-tail"]
		if len(before) != 1 || len(tail) != 1 || before[0].Time >= marker[0].Time || tail[0].Time-marker[0].Time < int64(700*time.Millisecond) || tail[0].Goroutine == marker[0].Goroutine {
			t.Fatalf("real trace lost history or post-trigger coverage: before=%+v marker=%+v tail=%+v", before, marker, tail)
		}
	}
}

func readPostgresPublisherLateReceipt(t *testing.T, directory string) postgresPublisherLateReceipt {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(directory, "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	var receipt postgresPublisherLateReceipt
	if err := json.Unmarshal(data, &receipt); err != nil {
		t.Fatal(err)
	}
	return receipt
}

func assertPostgresPublisherLatePermissions(t *testing.T, directory string) {
	t.Helper()
	info, err := os.Stat(directory)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("directory permissions: %v %v", info, err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("artifact permissions: %v %v", info, err)
		}
	}
}
