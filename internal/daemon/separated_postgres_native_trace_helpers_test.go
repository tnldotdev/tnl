package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/trace"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability/runtimetrace"
)

var postgresNativeTraceChild = flag.Bool("tnl-postgres-native-trace-child", false, "isolated native trace IPC helper")
var postgresNativeTraceChildDone chan struct{}

func init() {
	// this test executable stands in for the tagged CLI only in subprocesses;
	// ordinary daemon tests neither consume private args nor start a recorder.
	for _, arg := range os.Args {
		if arg != "-tnl-postgres-native-trace-child=true" {
			continue
		}
		args, directory, enabled, err := runtimetrace.ConsumeArgs(os.Args)
		if err != nil || !enabled {
			panic("invalid isolated native recorder arguments")
		}
		os.Args = args
		commands, commandErr := runtimetrace.OpenPipeFD(3, "commands")
		replies, replyErr := runtimetrace.OpenPipeFD(4, "replies")
		if commandErr != nil || replyErr != nil {
			panic("isolated native recorder pipes unavailable")
		}
		postgresNativeTraceChildDone = make(chan struct{})
		go func() {
			defer close(postgresNativeTraceChildDone)
			_ = runtimetrace.Run(context.Background(), commands, replies, directory)
		}()
		return
	}
}

func TestPostgresNativeTraceChild(t *testing.T) {
	if !*postgresNativeTraceChild {
		t.Skip("isolated IPC subprocess only")
	}
	for _, arg := range os.Args {
		if strings.HasPrefix(arg, runtimetrace.CommandFDFlag) || strings.HasPrefix(arg, runtimetrace.ReplyFDFlag) || strings.HasPrefix(arg, runtimetrace.DirectoryFlag) {
			t.Fatal("private trace argument reached test flag parser")
		}
	}
	<-postgresNativeTraceChildDone
	next := trace.NewFlightRecorder(trace.FlightRecorderConfig{})
	if err := next.Start(); err != nil {
		t.Fatalf("native recorder was not joined: %v", err)
	}
	next.Stop()
}

func TestPostgresNativeTraceIPC(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"capture", "no-event", "cancel", "late-arm", "export-error"} {
		t.Run(mode, func(t *testing.T) {
			processCtx, stopProcess := context.WithTimeout(t.Context(), 10*time.Second)
			defer stopProcess()
			ctx, cancel := context.WithCancel(processCtx)
			defer cancel()
			command := exec.CommandContext(processCtx, executable, "-test.run=^TestPostgresNativeTraceChild$", "-test.count=1", "-tnl-postgres-native-trace-child=true")
			var output synchronizedBuffer
			command.Stdout, command.Stderr = &output, &output
			directory := filepath.Join(t.TempDir(), "native")
			if mode == "export-error" {
				if err := os.Mkdir(directory, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			d, err := newPostgresNativeTrace(ctx, command, "visitor-1", directory)
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			owner, err := startOwnedCommand(command, nil)
			if err != nil {
				t.Fatal(err)
			}
			d.AfterStart()
			d.AfterStart()
			phase := connectLoadPhase{Name: "connect-postgres-warm", Start: time.Now().Add(3 * time.Second), Duration: time.Second}
			if mode == "late-arm" {
				phase.Start = time.Now().Add(-time.Second)
			}
			err = d.Arm(ctx, phase)
			if (err != nil) != (mode == "late-arm") {
				t.Fatalf("arm: %v", err)
			}
			if mode == "capture" {
				e := postgresLateTrigger{Slot: 17108, Kind: "query", Started: time.Second, Completed: time.Second + 32*time.Millisecond, Observed: time.Second + 33*time.Millisecond}
				notifyCtx, stopNotify := context.WithTimeout(ctx, 2*time.Second)
				err := d.Trigger(notifyCtx, e)
				stopNotify()
				if err != nil || len(d.mailboxes[1]) != 0 {
					t.Fatalf("Trigger must return without waiting for its tail ACK: %v", err)
				}
			}
			if mode == "cancel" {
				cancel()
				d.Close()
			} else {
				err := d.Finish(ctx)
				if (err != nil) != (mode == "late-arm" || mode == "export-error") {
					t.Fatalf("Finish: %v", err)
				}
				if second := d.Finish(ctx); (second == nil) != (err == nil) {
					t.Fatalf("repeated Finish: %v %v", err, second)
				}
			}
			waitCtx, stopWait := context.WithTimeout(t.Context(), 5*time.Second)
			defer stopWait()
			if err := waitForDone(waitCtx, owner.done); err != nil || owner.result() != nil {
				t.Fatalf("child join: %v child=%v\n%s", err, owner.result(), output.String())
			}
			if mode == "cancel" {
				b, err := os.ReadFile(filepath.Join(directory, "receipt.json"))
				var aborted runtimetrace.Receipt
				if err != nil || json.Unmarshal(b, &aborted) != nil || aborted.Error == "" || aborted.ExportAuthorized {
					t.Fatalf("cancel did not preserve an abort receipt: %s %v", b, err)
				}
				return
			}
			r := d.Receipt()
			if r == nil || r.Phase != phase.Name || r.PID != command.Process.Pid {
				t.Fatalf("missing parent receipt: %+v", r)
			}
			if mode == "export-error" {
				if r.Error == "" {
					t.Fatal("export error lost from reply receipt")
				}
				return
			}
			b, err := os.ReadFile(filepath.Join(directory, "receipt.json"))
			if err != nil {
				t.Fatal(err)
			}
			var disk runtimetrace.Receipt
			if err := json.Unmarshal(b, &disk); err != nil || disk.PID != r.PID || disk.TraceBytes != r.TraceBytes {
				t.Fatalf("disk/reply mismatch: %+v %v", disk, err)
			}
		})
	}
}

func TestPostgresNativeTraceStartupCleanup(t *testing.T) {
	command := exec.Command(filepath.Join(t.TempDir(), "missing"))
	d, err := newPostgresNativeTrace(t.Context(), command, "visitor-1", filepath.Join(t.TempDir(), "native"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := startOwnedCommand(command, nil); err == nil {
		t.Fatal("missing executable started")
	}
	d.Close()
	d.Close()
	for _, f := range []*os.File{d.commands, d.replies, d.childCommands, d.childReplies} {
		if _, err := f.Stat(); err == nil {
			t.Fatal("startup failure leaked an IPC descriptor")
		}
	}
	select {
	case <-d.done:
	default:
		t.Fatal("startup failure did not join reply pump")
	}
	if err := (*postgresNativeTrace)(nil).Finish(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, c := range []*exec.Cmd{nil, {ExtraFiles: []*os.File{nil}}} {
		if d, err := newPostgresNativeTrace(t.Context(), c, "visitor-1", "/results/native"); err == nil || d != nil {
			t.Fatal("invalid command accepted")
		}
	}
}

func TestPostgresNativeTraceAckWait(t *testing.T) {
	d, err := newPostgresNativeTrace(t.Context(), exec.Command("unused"), "visitor-1", filepath.Join(t.TempDir(), "native"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := d.wait(ctx, 1, runtimetrace.Arm); !errors.Is(err, context.Canceled) {
		t.Fatalf("ACK wait ignored cancellation: %v", err)
	}
	for _, mailbox := range d.mailboxes {
		if cap(mailbox) != 1 {
			t.Fatal("unbounded reply mailbox")
		}
	}
	if err := runtimetrace.WriteFrame(d.childReplies, runtimetrace.Reply{ID: 2, Kind: runtimetrace.Arm}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := waitForDone(ctx, d.done); err != nil {
		t.Fatal(err)
	}
	if err := d.wait(ctx, 1, runtimetrace.Arm); err == nil {
		t.Fatal("wrong ACK ID satisfied the waiter")
	}
}
