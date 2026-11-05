package runtimetrace

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/trace"
	"strconv"
	"strings"
	"testing"
	"time"
)

var recorderChild = flag.String("tnl-native-recorder-child", "", "isolated fixture recorder test")
var recorderDirectory = flag.String("tnl-native-recorder-directory", "", "isolated fixture recorder artifacts")

func TestRecorder(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"capture", "no-event", "late-arm", "start-failed", "never-armed", "invalid-command", "invalid-command-abort", "oversized-frame", "max-frames", "eof", "cancel", "cancel-tail", "post-capture-eof", "reply-error", "existing-directory", "bounded-output", "abort-bounded-output", "abort-zero-output", "write-error"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			directory := filepath.Join(t.TempDir(), "native")
			if mode == "existing-directory" {
				if err := os.Mkdir(directory, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(directory, "receipt.json"), []byte("preserve"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cr, cw, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			rr, rw, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer cr.Close()
			defer cw.Close()
			defer rr.Close()
			defer rw.Close()
			markerRead, markerWrite, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer markerRead.Close()
			defer markerWrite.Close()
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestRecorderChild$", "-test.count=1", "-tnl-native-recorder-child="+mode, "-tnl-native-recorder-directory="+directory)
			cmd.ExtraFiles = []*os.File{cr, rw, markerWrite}
			var output strings.Builder
			cmd.Stdout, cmd.Stderr = &output, &output
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			_ = cr.Close()
			_ = rw.Close()
			_ = markerWrite.Close()
			decoder := NewDecoder(rr)
			send := func(c Command) Reply {
				t.Helper()
				if err := WriteFrame(cw, c); err != nil {
					t.Fatal(err)
				}
				var reply Reply
				kind := c.Kind
				if kind != Arm && kind != Trigger && kind != Export {
					kind = ""
				}
				if err := decoder.Read(&reply); err != nil || reply.ID != c.ID || reply.Kind != kind {
					t.Fatalf("reply %+v: %v", reply, err)
				}
				return reply
			}
			phaseStart := time.Now().Add(3 * time.Second)
			if mode == "late-arm" {
				phaseStart = time.Now().Add(-time.Second)
			}
			if mode != "never-armed" {
				arm := send(Command{ID: 1, Kind: Arm, Phase: "connect-postgres-warm", Component: "visitor-1", Start: phaseStart, Duration: time.Second})
				if (arm.Error != "") != (mode == "late-arm" || mode == "start-failed") {
					t.Fatalf("arm: %+v", arm)
				}
			}
			if abortMarkerMode(mode) {
				if _, err := io.ReadFull(markerRead, make([]byte, 1)); err != nil {
					t.Fatal(err)
				}
			}
			var exported Reply
			var triggered Reply
			switch mode {
			case "capture", "bounded-output", "post-capture-eof":
				event := &Event{Slot: 17108, Kind: "query", Started: time.Second, Completed: time.Second + 31929*time.Microsecond, Observed: time.Second + 32*time.Millisecond}
				// queue EXPORT while the synchronous child holds its tail.
				if err := WriteFrame(cw, Command{ID: 2, Kind: Trigger, Event: event}); err != nil {
					t.Fatal(err)
				}
				if mode != "post-capture-eof" {
					if err := WriteFrame(cw, Command{ID: 3, Kind: Export}); err != nil {
						t.Fatal(err)
					}
				}
				if err := decoder.Read(&triggered); err != nil || triggered.Kind != Trigger {
					t.Fatalf("trigger reply: %+v %v", triggered, err)
				}
				if mode == "post-capture-eof" {
					_ = cw.Close()
				} else {
					if err := decoder.Read(&exported); err != nil || exported.Kind != Export {
						t.Fatalf("export reply: %+v %v", exported, err)
					}
				}
			case "invalid-command", "invalid-command-abort":
				r := send(Command{ID: 2, Kind: "secret SQL"})
				if r.Error == "" || strings.Contains(r.Error, "secret SQL") || r.Kind != "" {
					t.Fatalf("unsafe invalid ACK: %+v", r)
				}
				if mode == "invalid-command-abort" {
					_ = cw.Close()
				} else {
					exported = send(Command{ID: 3, Kind: Export})
				}
			case "max-frames":
				for i := 2; i <= MaxCommands; i++ {
					send(Command{ID: i, Kind: Arm})
				}
			case "oversized-frame":
				_, _ = io.WriteString(cw, strings.Repeat("x", MaxFrameBytes+1)+"\n")
			case "eof", "never-armed", "abort-bounded-output", "abort-zero-output":
				_ = cw.Close()
			case "reply-error":
				_ = rr.Close()
				_ = WriteFrame(cw, Command{ID: 2, Kind: Export})
			case "cancel":
				// the child cancels while waiting synchronously for another frame.
			case "cancel-tail":
				if err := WriteFrame(cw, Command{ID: 2, Kind: Trigger, Event: &Event{Slot: 17108, Kind: "query"}}); err != nil {
					t.Fatal(err)
				}
			default:
				exported = send(Command{ID: 2, Kind: Export})
			}
			if err := cmd.Wait(); err != nil {
				t.Fatalf("child: %v\n%s", err, output.String())
			}
			if mode == "existing-directory" {
				b, _ := os.ReadFile(filepath.Join(directory, "receipt.json"))
				if string(b) != "preserve" || exported.Error == "" || exported.Receipt == nil {
					t.Fatalf("existing artifact overwritten, or error receipt lost: %+v %q", exported, b)
				}
				return
			}
			b, err := os.ReadFile(filepath.Join(directory, "receipt.json"))
			if err != nil {
				t.Fatal(err)
			}
			var receipt Receipt
			if err := json.Unmarshal(b, &receipt); err != nil {
				t.Fatal(err)
			}
			if receipt.GOOS != runtime.GOOS || receipt.GOARCH != runtime.GOARCH || receipt.PID != cmd.Process.Pid || receipt.TraceBytes > TraceLimit || receipt.Commands > MaxCommands || receipt.Arm.Completed < receipt.Arm.Started || receipt.Read.Completed < receipt.Read.Started {
				t.Fatalf("invalid receipt: %+v", receipt)
			}
			wantError := mode != "capture" && mode != "no-event"
			if (receipt.Error != "") != wantError {
				t.Fatalf("error preservation: %+v", receipt)
			}
			if strings.Contains(receipt.Error, "secret SQL") {
				t.Fatalf("input leaked into error receipt: %q", receipt.Error)
			}
			if mode == "capture" {
				if exported.Error != "" || receipt.TraceStatus != "captured" || receipt.Event == nil || receipt.Event.Slot != 17108 || receipt.PostTriggerActual < PostTrigger || receipt.Snapshot.Started < receipt.Hold.Completed || receipt.Stop.Started < receipt.Snapshot.Completed || receipt.Export.Started < receipt.Stop.Completed || !receipt.ExportAuthorized || receipt.HoldStatus != "completed" {
					t.Fatalf("capture bounds: %+v", receipt)
				}
				parseTrace(t, filepath.Join(directory, receipt.TraceFile))
			}
			if mode == "no-event" && (receipt.TraceFile != "" || receipt.TraceStatus != "no-event" || receipt.TraceBytes != 0 || receipt.Stop.Completed < receipt.Stop.Started) {
				t.Fatalf("no event: %+v", receipt)
			}
			if mode == "bounded-output" && (receipt.TraceBytes != 64 || !receipt.Partial || receipt.TraceFile != "native.trace.partial") {
				t.Fatalf("output cap: %+v", receipt)
			}
			if mode == "cancel-tail" && (receipt.HoldStatus != "cancelled" || !receipt.Partial || !receipt.Cancelled || receipt.TraceBytes == 0) {
				t.Fatalf("cancelled tail not retained: %+v", receipt)
			}
			if abortMarkerMode(mode) {
				if receipt.TraceStatus != "captured-partial" || !receipt.Partial || receipt.TraceFile != "native.trace.partial" || receipt.TraceBytes == 0 || receipt.Event != nil || receipt.ExportAuthorized || receipt.Stop.Started < receipt.Snapshot.Completed || receipt.Export.Started < receipt.Stop.Completed || receipt.PostTriggerRequested != 0 || receipt.PostTriggerActual != 0 {
					t.Fatalf("abort discarded history or invented a trigger/authorization: %+v", receipt)
				}
				parseAbortTrace(t, filepath.Join(directory, receipt.TraceFile))
			}
			if mode == "never-armed" || mode == "start-failed" {
				if receipt.TraceFile != "" || receipt.TraceBytes != 0 || receipt.Snapshot != (Bounds{}) || receipt.Stop != (Bounds{}) {
					t.Fatalf("nonexistent recorder was snapshotted/stopped: %+v", receipt)
				}
			}
			if mode == "abort-bounded-output" || mode == "abort-zero-output" {
				wantBytes := 64
				if mode == "abort-zero-output" {
					wantBytes = 0
				}
				if receipt.TraceBytes != wantBytes || receipt.TraceStatus != "capture-failed" || !receipt.Partial || receipt.ExportAuthorized || receipt.TraceFile != "native.trace.partial" || !strings.Contains(receipt.Error, "command pipe EOF before export") || !strings.Contains(receipt.Error, "snapshot native flight recorder failed") {
					t.Fatalf("abort snapshot failure not preserved: %+v", receipt)
				}
			}
			if mode == "post-capture-eof" {
				if !receipt.Partial || receipt.TraceStatus != "captured-partial" || receipt.ExportAuthorized || receipt.Snapshot != triggered.Receipt.Snapshot || receipt.Stop != triggered.Receipt.Stop || receipt.TraceBytes != triggered.Receipt.TraceBytes {
					t.Fatalf("captured trigger was snapshotted/stopped again: %+v", receipt)
				}
				parseTrace(t, filepath.Join(directory, receipt.TraceFile))
			}
			info, err := os.Stat(directory)
			if err != nil || info.Mode().Perm() != 0o700 {
				t.Fatalf("directory permissions: %v %v", info, err)
			}
			entries, _ := os.ReadDir(directory)
			if receipt.TraceFile != "" && mode != "write-error" && len(entries) != 2 {
				t.Fatalf("duplicate or missing trace artifacts: %v", entries)
			}
			for _, entry := range entries {
				info, err := entry.Info()
				if err != nil || info.Mode().Perm() != 0o600 {
					t.Fatalf("file permissions: %v %v", info, err)
				}
				if entry.Name() == receipt.TraceFile && info.Size() != int64(receipt.TraceBytes) {
					t.Fatalf("trace artifact size=%d differs from receipt=%d", info.Size(), receipt.TraceBytes)
				}
			}
		})
	}
}

func abortMarkerMode(mode string) bool {
	return mode == "eof" || mode == "cancel" || mode == "oversized-frame" || mode == "invalid-command-abort" || mode == "max-frames"
}

func parseAbortTrace(t *testing.T, path string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, "go", "tool", "trace", "-d=parsed", path).CombinedOutput()
	if err != nil {
		t.Fatalf("parse abort trace: %v\n%s", err, b)
	}
	text := string(b)
	before := `Category="native-recorder-test-before-abort"`
	abort := `Category="postgres-native-late-abort-snapshot"`
	if strings.Count(text, before) != 1 || strings.Count(text, abort) != 1 || strings.Index(text, before) >= strings.Index(text, abort) || strings.Contains(text, `Category="postgres-native-late-outlier"`) {
		t.Fatal("abort trace lost its pre-abort marker, duplicated a snapshot, or invented a trigger")
	}
}

func parseTrace(t *testing.T, path string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, "go", "tool", "trace", "-d=parsed", path).CombinedOutput()
	if err != nil {
		t.Fatalf("parse trace: %v\n%s", err, b)
	}
	for _, marker := range []string{"postgres-native-late-outlier", "postgres-native-late-snapshot", "slot=17108"} {
		if !strings.Contains(string(b), marker) {
			t.Fatalf("trace missing %q", marker)
		}
	}
	logs := regexp.MustCompile(`G=([0-9]+) Log Time=([0-9]+) .*Category="postgres-native-late-(outlier|snapshot)"`).FindAllStringSubmatch(string(b), -1)
	if len(logs) != 2 || logs[0][1] != logs[1][1] || logs[0][3] != "outlier" || logs[1][3] != "snapshot" {
		t.Fatalf("native marker goroutine/ordering: %v", logs)
	}
	first, _ := strconv.ParseInt(logs[0][2], 10, 64)
	last, _ := strconv.ParseInt(logs[1][2], 10, 64)
	if time.Duration(last-first) < 900*time.Millisecond {
		t.Fatalf("trace did not retain a post-trigger tail: %dns", last-first)
	}
	b, err = exec.CommandContext(ctx, "go", "tool", "trace", "-d=wire", path).CombinedOutput()
	if err != nil || !strings.Contains(string(b), "ClockSnapshot") {
		t.Fatalf("trace lacks native clock snapshot: %v", err)
	}
}

func TestRecorderChild(t *testing.T) {
	mode := *recorderChild
	if mode == "" {
		t.Skip("isolated recorder subprocess only; do not inherit -test.trace")
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	commands, err := OpenPipeFD(3, "commands")
	if err != nil {
		t.Fatal(err)
	}
	replies, err := OpenPipeFD(4, "replies")
	if err != nil {
		t.Fatal(err)
	}
	markerReady, err := OpenPipeFD(5, "test-marker-ready")
	if err != nil {
		t.Fatal(err)
	}
	defer markerReady.Close()
	markerDone := make(chan struct{})
	var markerErr error
	if abortMarkerMode(mode) {
		go func() {
			defer close(markerDone)
			defer markerReady.Close()
			ticker := time.NewTicker(time.Millisecond)
			defer ticker.Stop()
			for {
				if trace.IsEnabled() {
					trace.Log(ctx, "native-recorder-test-before-abort", "retained-before-abort")
					_, markerErr = markerReady.Write([]byte{1})
					return
				}
				select {
				case <-ticker.C:
				case <-ctx.Done():
					markerErr = ctx.Err()
					return
				}
			}
		}()
	} else {
		close(markerDone)
	}
	if mode == "start-failed" {
		other := trace.NewFlightRecorder(trace.FlightRecorderConfig{})
		if err := other.Start(); err != nil {
			t.Fatal(err)
		}
		defer other.Stop()
	}
	if mode == "cancel" {
		time.AfterFunc(time.Second, cancel)
	}
	if mode == "cancel-tail" {
		time.AfterFunc(300*time.Millisecond, cancel)
	}
	if mode == "bounded-output" || mode == "write-error" || mode == "abort-bounded-output" || mode == "abort-zero-output" {
		// exercise the real owner with narrow injected storage, not a fake
		// recorder. production Run has no configurable output cap or writer.
		defer commands.Close()
		defer replies.Close()
		decoder := NewDecoder(commands)
		var arm Command
		if err := decoder.Read(&arm); err != nil {
			t.Fatal(err)
		}
		d := &recorderOwner{epoch: arm.Start}
		d.receipt = Receipt{Phase: arm.Phase, Component: arm.Component, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, PID: os.Getpid(), TraceLimit: TraceLimit}
		d.arm()
		d.data = d.data[:64:64]
		if mode == "abort-zero-output" {
			d.data = d.data[:0:0]
		}
		if err := WriteFrame(replies, Reply{ID: 1, Kind: Arm}); err != nil {
			t.Fatal(err)
		}
		if mode == "abort-bounded-output" || mode == "abort-zero-output" {
			if err := decoder.Read(new(Command)); err != io.EOF {
				t.Fatalf("expected abort EOF: %v", err)
			}
			d.fail("command pipe EOF before export")
			d.abort(ctx)
			snapshot, stop := d.receipt.Snapshot, d.receipt.Stop
			d.abort(ctx)
			d.stop()
			if d.recorder != nil || d.receipt.Snapshot != snapshot || d.receipt.Stop != stop {
				t.Fatal("abort/Stop was not idempotent")
			}
			d.export(*recorderDirectory, false)
		} else {
			if mode == "bounded-output" {
				var trigger Command
				if err := decoder.Read(&trigger); err != nil {
					t.Fatal(err)
				}
				d.capture(ctx, trigger.Event)
				if err := WriteFrame(replies, Reply{ID: 2, Kind: Trigger, Error: d.err.Error()}); err != nil {
					t.Fatal(err)
				}
			} else {
				d.stop()
				d.receipt.TraceFile, d.receipt.TraceBytes = "native.trace", len(d.data)
				// force the artifact write to fail without losing the receipt.
				d.receipt.TraceFile = "missing/native.trace"
			}
			var export Command
			if err := decoder.Read(&export); err != nil {
				t.Fatal(err)
			}
			d.export(*recorderDirectory, true)
			if err := WriteFrame(replies, Reply{ID: export.ID, Kind: Export, Receipt: &d.receipt, Error: d.err.Error()}); err != nil {
				t.Fatal(err)
			}
		}
	} else {
		err := Run(ctx, commands, replies, *recorderDirectory)
		if (err != nil) != (mode != "capture" && mode != "no-event") {
			t.Fatalf("recorder return error: %v", err)
		}
	}
	<-markerDone
	if markerErr != nil {
		t.Fatal(markerErr)
	}
	if mode != "start-failed" {
		next := trace.NewFlightRecorder(trace.FlightRecorderConfig{})
		if err := next.Start(); err != nil {
			t.Fatalf("recorder not stopped: %v", err)
		}
		next.Stop()
	}
}
