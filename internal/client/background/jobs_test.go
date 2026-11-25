package background

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

var (
	helperMode   = flag.String("tnl-background-test-mode", "", "select background process fixture")
	helperRoot   = flag.String("tnl-background-test-root", "", "state root for background launcher fixture")
	helperSync   = flag.String("tnl-background-test-sync", "", "unix socket fixture rendezvous")
	helperOutput = flag.String("tnl-background-test-output", "stdout", "background output stream fixture")
)

type testWork struct {
	Mode string
	Sync string
}

type testProfile struct {
	Protocol, Host, Hostname string
	Port                     int
	ConnectorRequired        bool
}

func TestBackgroundProcessHelper(t *testing.T) {
	switch *helperMode {
	case "":
		return
	case "launcher":
		opts := helperOptions(t, *helperRoot, testWork{Mode: "write-" + *helperOutput, Sync: *helperSync})
		if err := Launch(t.Context(), opts, func(ctx context.Context, entry Entry) error {
			return json.NewEncoder(ReceiptWriter(ctx, os.Stdout)).Encode(entry)
		}); err != nil {
			t.Fatal(err)
		}
		return
	case "early-exit":
		os.Exit(17) // no bootstrap reader and no work to join
	case "stuck":
		// the owner must kill and reap a child that ignores graceful shutdown.
		signal.Ignore(syscall.SIGTERM)
		conn, err := net.Dial("unix", *helperSync)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fmt.Fprintln(conn, os.Getpid())
		_, _ = io.Copy(io.Discard, conn)
		os.Exit(19)
	}

	ctx, stop := signal.NotifyContext(t.Context(), syscall.SIGTERM)
	defer stop()
	err := RunChild(ctx, func(ctx context.Context, spec Bootstrap) error {
		var work testWork
		if err := json.Unmarshal(spec.Payload, &work); err != nil {
			return err
		}
		if work.Mode == "after-socket-failure" {
			return errors.New("fixture setup failed")
		}
		if work.Sync != "" {
			conn, err := net.Dial("unix", work.Sync)
			if err != nil {
				return err
			}
			defer conn.Close()
			if _, err := fmt.Fprintln(conn, os.Getpid()); err != nil {
				return err
			}
			defer func() {
				if work.Mode == "hold-stop" {
					_, _ = conn.Write([]byte{'j'})
					var release [1]byte
					_, _ = io.ReadFull(conn, release[:])
				}
			}()
			if work.Mode == "pending" {
				<-ctx.Done()
				return nil
			}
			if output, ok := strings.CutPrefix(work.Mode, "write-"); ok {
				if err := Ready(ctx, Readiness{Address: "https://published.example.test"}); err != nil {
					return err
				}
				var release [1]byte
				if _, err := io.ReadFull(conn, release[:]); err != nil {
					return err
				}
				stream := os.Stdout
				if output == "stderr" {
					stream = os.Stderr
				}
				if _, err := fmt.Fprintln(stream, "wrote after launcher exit"); err != nil {
					return err
				}
				if _, err := conn.Write([]byte{'w'}); err != nil {
					return err
				}
				<-ctx.Done()
				return nil
			}
		}
		ready := Readiness{Address: "https://published.example.test", TunnelID: "tun_0123456789ABCDEFGHIJKL"}
		if work.Mode == "connector-only" {
			ready = Readiness{Target: "localhost:3000", ServiceID: "svc_0123456789ABCDEFGHIJKL", ConnectCommand: []string{"tnl", "connect", "service"}}
		}
		if protocol, ok := strings.CutPrefix(work.Mode, "profile-"); ok {
			ready = Readiness{Address: "127.0.0.1:15432"}
			ready.Profile, _ = json.Marshal(testProfile{protocol, "127.0.0.1", "approved.example.test", 15432, true})
		}
		if err := Ready(ctx, ready); err != nil {
			return err
		}
		<-ctx.Done()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func helperOptions(t *testing.T, root string, work testWork) LaunchOptions {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	args := helperArgs("worker")
	payload, err := json.Marshal(work)
	if err != nil {
		t.Fatal(err)
	}
	if work.Mode == "early-exit" || work.Mode == "stuck" {
		args = append(helperArgs(work.Mode), "-tnl-background-test-sync="+work.Sync)
	}
	return LaunchOptions{StateDir: root, Binary: binary, Args: args, Kind: KindPublish, Payload: payload}
}

func helperArgs(mode string) []string {
	return []string{"-test.run=^TestBackgroundProcessHelper$", "-tnl-background-test-mode=" + mode}
}

func testScope(t *testing.T, root string) (string, string) {
	t.Helper()
	canonical, err := selectStateRoot(root, true)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := scopeDirectory(canonical, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return canonical, dir
}

func runFixture(t *testing.T, opts LaunchOptions) Entry {
	t.Helper()
	var result Entry
	err := Launch(t.Context(), opts, func(_ context.Context, entry Entry) error {
		result = entry
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = Stop(context.Background(), opts.StateDir, result.JobID) })
	return result
}

func TestBackgroundProfileOnLongStatePath(t *testing.T) {
	long := filepath.Join(t.TempDir(), strings.Repeat("long-ancestor-", 12))
	if err := os.Mkdir(long, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(long, alias); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(alias, "state")
	canonical, scope := testScope(t, root)
	if len(canonical) < 104 {
		t.Fatal("canonical state root needs to exceed a unix socket path")
	}
	for _, protocol := range []string{"http", "postgres", "mysql", "tcp", "kubernetes"} {
		t.Run(protocol, func(t *testing.T) {
			opts := helperOptions(t, root, testWork{Mode: "profile-" + protocol})
			opts.Kind = KindConnect
			entry := runFixture(t, opts)
			group, err := syscall.Getpgid(entry.PID)
			if err != nil || group != entry.PID {
				t.Fatalf("child did not start its own session: pgid=%d pid=%d err=%v", group, entry.PID, err)
			}
			var profile testProfile
			if err := json.Unmarshal(entry.Profile, &profile); err != nil {
				t.Fatal(err)
			}
			if entry.StateDir != canonical || entry.State != StateReady || entry.Address != "127.0.0.1:15432" ||
				profile != (testProfile{protocol, "127.0.0.1", "approved.example.test", 15432, true}) {
				t.Fatalf("wrong receipt: %+v / %+v", entry, profile)
			}
			live, err := Status(t.Context(), canonical, entry.JobID)
			if err != nil || live.State != StateReady || live.PID != entry.PID || live.Kind != KindConnect ||
				live.Target != entry.Target || live.Address != entry.Address || live.Profile != nil {
				t.Fatalf("wrong status: %+v / %v", live, err)
			}
			dir, socket := jobPaths(scope, entry.JobID)
			for path, want := range map[string]os.FileMode{scope: 0o700, dir: 0o700, socket: 0o600} {
				info, err := os.Lstat(path)
				if err != nil || info.Mode().Perm() != want {
					t.Fatalf("%s: expected %04o; %v / %v", path, want, info, err)
				}
			}
		})
	}
}

func TestBackgroundStopIsExactAndConfirmsJoinedWork(t *testing.T) {
	root, scope := testScope(t, filepath.Join(t.TempDir(), "state"))
	sync := testListener(t, scope)
	first := runFixture(t, helperOptions(t, root, testWork{Mode: "hold-stop", Sync: sync.Addr().String()}))
	conn, pid := acceptPID(t, sync)
	if pid != first.PID {
		t.Fatal("wrong fixture worker")
	}
	second := runFixture(t, helperOptions(t, root, testWork{}))
	if first.JobID == second.JobID || !opaqueid.Valid(first.JobID, opaqueid.JobPrefix) || !opaqueid.Valid(second.JobID, opaqueid.JobPrefix) {
		t.Fatal("jobs did not receive separate opaque IDs")
	}
	if _, listener, err := reserveSocket(scope, first.JobID); err == nil {
		listener.Close()
		t.Fatal("another child took an active control socket")
	}
	entries, err := List(t.Context(), root)
	if err != nil || len(entries) != 2 {
		t.Fatalf("list: %+v / %v", entries, err)
	}
	if _, err := Stop(t.Context(), filepath.Join(root, "other"), first.JobID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stop reached a different state scope: %v", err)
	}
	for _, id := range []string{"../../outside", "abcdef0123456789abcdef01"} {
		if _, err := Stop(t.Context(), root, id); err == nil {
			t.Fatal("accepted an invalid job ID")
		}
	}
	_, path := jobPaths(scope, first.JobID)
	misdirected, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer misdirected.Close()
	_ = misdirected.SetDeadline(time.Now().Add(time.Second))
	// the socket alone does not select a job (case-insensitive mounts can
	// send a request for a different ID to this listener).
	if err := writeFrame(misdirected, controlRequest{JobID: second.JobID, Operation: stopRequest}); err != nil {
		t.Fatal(err)
	}
	var wrong Entry
	if err := readFrame(frameReader(misdirected), &wrong); err != nil || wrong.JobID != first.JobID || wrong.State != StateReady {
		t.Fatalf("wrong-ID stop was accepted: %+v / %v", wrong, err)
	}
	stopping, err := Stop(t.Context(), root, first.JobID)
	if err != nil || stopping.State != StateStopping {
		t.Fatalf("stop claimed the blocked worker had joined: %+v / %v", stopping, err)
	}
	var joining [1]byte
	if _, err := io.ReadFull(conn, joining[:]); err != nil || joining[0] != 'j' {
		t.Fatalf("stop did not cancel the worker: %v", err)
	}
	status, err := Status(t.Context(), root, first.JobID)
	if err != nil || status.State != StateStopping {
		t.Fatalf("stopping job status: %+v / %v", status, err)
	}
	again, err := Stop(t.Context(), root, first.JobID)
	if err != nil || again.State != StateStopping {
		t.Fatalf("repeated stop claimed completion: %+v / %v", again, err)
	}
	status, err = Status(t.Context(), root, second.JobID)
	if err != nil || status.State != StateReady {
		t.Fatalf("stopping the first job affected the second: %+v / %v", status, err)
	}
	_, _ = conn.Write([]byte{'x'})
	stopped, err := Stop(t.Context(), root, second.JobID)
	if err != nil || stopped.State != StateStopped {
		t.Fatalf("joined stop: %+v / %v", stopped, err)
	}
}

func TestBackgroundConnectorOnlyPublicationDoesNotClaimPublicAddress(t *testing.T) {
	root, _ := testScope(t, filepath.Join(t.TempDir(), "state"))
	entry := runFixture(t, helperOptions(t, root, testWork{Mode: "connector-only"}))
	if entry.Address != "" || entry.Target == "" || entry.ServiceID == "" || len(entry.ConnectCommand) == 0 {
		t.Fatalf("wrong connector-only receipt: %+v", entry)
	}
	live, err := Status(t.Context(), root, entry.JobID)
	if err != nil || live.Address != "" || live.ServiceID != entry.ServiceID || live.State != StateReady || len(live.ConnectCommand) != 0 {
		t.Fatalf("wrong connector-only status: %+v / %v", live, err)
	}
}

func TestBackgroundSocketDoesNotImplyHandoff(t *testing.T) {
	root, _ := testScope(t, filepath.Join(t.TempDir(), "state"))
	opts := helperOptions(t, root, testWork{})
	var id string
	err := Launch(t.Context(), opts, func(_ context.Context, entry Entry) error {
		id = entry.JobID
		live, err := Status(t.Context(), root, id)
		if err != nil || live.State != StateStarting {
			return fmt.Errorf("job was discoverable as ready before receipt commit: %+v / %v", live, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = Stop(context.Background(), root, id) })
	live, err := Status(t.Context(), root, id)
	if err != nil || live.State != StateReady {
		t.Fatalf("committed job was not ready: %+v / %v", live, err)
	}
}

func TestBackgroundProcessSignalCancelsWorker(t *testing.T) {
	root, scope := testScope(t, filepath.Join(t.TempDir(), "state"))
	listener := testListener(t, scope)
	entry := runFixture(t, helperOptions(t, root, testWork{Mode: "hold-stop", Sync: listener.Addr().String()}))
	conn, pid := acceptPID(t, listener)
	proc, err := os.FindProcess(pid)
	if err != nil || pid != entry.PID {
		t.Fatalf("wrong worker: %d / %v", pid, err)
	}
	defer proc.Release()
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	var joining [1]byte
	if _, err := io.ReadFull(conn, joining[:]); err != nil || joining[0] != 'j' {
		t.Fatalf("signal did not cancel the worker: %v", err)
	}
	status, err := Status(t.Context(), root, entry.JobID)
	if err != nil || status.State != StateStopping {
		t.Fatalf("signal cancellation status: %+v / %v", status, err)
	}
	_, _ = conn.Write([]byte{'x'})
}

func TestBackgroundAwaitRejectsReadinessForAnotherProcess(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	parent, other := net.Pipe()
	defer parent.Close()
	_ = parent.SetDeadline(time.Now().Add(time.Second))
	id := "job_0123456789ABCDEFGHIJKL"
	spec := startup{Bootstrap: Bootstrap{JobID: id, Kind: KindPublish}}
	child := &childProcess{cmd: &exec.Cmd{Process: &os.Process{Pid: 1}}, done: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		defer other.Close()
		if err := readFrame(frameReader(other), &startup{}); err != nil {
			done <- err
			return
		}
		done <- writeFrame(other, startupReply{Entry: Entry{JobID: id, Kind: spec.Kind, State: StateReady, PID: 2}})
	}()
	written := false
	err := awaitReceipt(ctx, child, parent, spec, func(context.Context, Entry) error { written = true; return nil })
	if otherErr := <-done; otherErr != nil {
		t.Fatal(otherErr)
	}
	if reason, _ := failure.ReasonOf(err); reason != failure.BackgroundStartFailed || written {
		t.Fatalf("launcher accepted a different job's readiness: %v", err)
	}
}

func TestBackgroundStatusRefusesPublicSockets(t *testing.T) {
	root, scope := testScope(t, filepath.Join(t.TempDir(), "state"))
	id := "job_0123456789ABCDEFGHIJKL"
	reservation, listener, err := reserveSocket(scope, id)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	defer reservation.remove()
	if err := os.Chmod(reservation.path, 0o666); err != nil {
		t.Fatal(err)
	}
	_, err = Status(t.Context(), root, id)
	if reason, _ := failure.ReasonOf(err); reason != failure.ClientStateUnavailable {
		t.Fatalf("did not reject public control socket: %v", err)
	}
}

func TestBackgroundListIgnoresStaleSockets(t *testing.T) {
	root, scope := testScope(t, filepath.Join(t.TempDir(), "state"))
	id := "job_0123456789ABCDEFGHIJKL"
	reservation, listener, err := reserveSocket(scope, id)
	if err != nil {
		t.Fatal(err)
	}
	defer reservation.remove()
	_ = listener.Close()
	entries, err := List(t.Context(), root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("stale socket was reported as a job: %+v / %v", entries, err)
	}
	if _, err := Stop(t.Context(), root, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stale socket confirmed a stop: %v", err)
	}
}

func TestBackgroundStartupFailureDoesNotLeaveAJob(t *testing.T) {
	for _, mode := range []string{"early-exit", "after-socket-failure", "pending", "stuck", "receipt-failed", "receipt-canceled"} {
		t.Run(mode, func(t *testing.T) {
			root, scope := testScope(t, filepath.Join(t.TempDir(), "state"))
			work := testWork{Mode: mode}
			var listener *net.UnixListener
			limit := 5 * time.Second
			if mode == "pending" || mode == "stuck" {
				listener = testListener(t, scope)
				work.Sync = listener.Addr().String()
			}
			if mode == "pending" {
				limit = 1 * time.Second
			}
			opts := helperOptions(t, root, work)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			writeError := errors.New("receipt writer failed")
			var receiptPID int
			result := make(chan error, 1)
			go func() {
				result <- launch(ctx, opts, limit, func(_ context.Context, entry Entry) error {
					receiptPID = entry.PID
					if mode == "receipt-canceled" {
						cancel()
						return nil
					}
					return writeError
				})
			}()
			var pendingPID int
			if listener != nil {
				_, pendingPID = acceptPID(t, listener)
			}
			if mode == "stuck" {
				cancel()
			}
			err := <-result
			if pendingPID != 0 {
				assertReaped(t, pendingPID)
			}
			switch mode {
			case "receipt-canceled", "stuck":
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("expected cancellation, got %v", err)
				}
			case "receipt-failed":
				if !errors.Is(err, writeError) {
					t.Fatalf("expected receipt error, got %v", err)
				}
			default:
				if reason, _ := failure.ReasonOf(err); reason != failure.BackgroundStartFailed || receiptPID != 0 {
					t.Fatalf("unready process returned a receipt or wrong failure: %d / %v", receiptPID, err)
				}
			}
			if mode == "receipt-canceled" || mode == "receipt-failed" {
				assertReaped(t, receiptPID)
			}
			children, err := os.ReadDir(scope)
			if err != nil {
				t.Fatal(err)
			}
			for _, child := range children {
				if opaqueid.Valid(child.Name(), opaqueid.JobPrefix) {
					t.Fatalf("failed startup left a socket reservation: %v", child)
				}
			}
		})
	}
}

func TestBackgroundJobSurvivesLauncherExit(t *testing.T) {
	for _, stream := range []string{"stdout", "stderr"} {
		t.Run(stream, func(t *testing.T) { testBackgroundOutput(t, stream) })
	}
}

func testBackgroundOutput(t *testing.T, stream string) {
	t.Helper()
	root, scope := testScope(t, filepath.Join(t.TempDir(), "state"))
	listener := testListener(t, scope)
	binary := helperOptions(t, root, testWork{}).Binary
	args := append(helperArgs("launcher"), "-tnl-background-test-root="+root, "-tnl-background-test-sync="+listener.Addr().String(), "-tnl-background-test-output="+stream)
	output, err := exec.CommandContext(t.Context(), binary, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("launcher: %v / %s", err, output)
	}
	var entry Entry
	if err := json.NewDecoder(strings.NewReader(string(output))).Decode(&entry); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = Stop(context.Background(), root, entry.JobID) })
	conn, pid := acceptPID(t, listener)
	if pid != entry.PID {
		t.Fatal("wrong child wrote output")
	}
	if _, err := conn.Write([]byte{'x'}); err != nil {
		t.Fatal(err)
	}
	var wrote [1]byte
	if _, err := io.ReadFull(conn, wrote[:]); err != nil || wrote[0] != 'w' {
		t.Fatalf("child could not write after launcher exit: %v", err)
	}
	status, err := Status(t.Context(), root, entry.JobID)
	if err != nil || status.State != StateReady {
		t.Fatalf("child did not survive launcher exit: %+v / %v", status, err)
	}
}

func testListener(t *testing.T, scope string) *net.UnixListener {
	t.Helper()
	addr := &net.UnixAddr{Name: filepath.Join(scope, "test"), Net: "unix"}
	listener, err := net.ListenUnix("unix", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	_ = listener.SetDeadline(time.Now().Add(10 * time.Second))
	return listener
}

func acceptPID(t *testing.T, listener *net.UnixListener) (net.Conn, int) {
	t.Helper()
	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || pid <= 0 {
		t.Fatalf("invalid worker PID %q: %v", line, err)
	}
	return conn, pid
}

func assertReaped(t *testing.T, pid int) {
	t.Helper()
	if pid <= 0 {
		t.Fatal("no child PID supplied")
	}
	if _, err := syscall.Wait4(pid, nil, syscall.WNOHANG, nil); !errors.Is(err, syscall.ECHILD) {
		t.Fatalf("process %d still owned by launcher: %v", pid, err)
	}
}
