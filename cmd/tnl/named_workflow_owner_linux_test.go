package main

import (
	"errors"
	"flag"
	"fmt"
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

	"golang.org/x/sys/unix"
)

// the named workflow already runs alone in a child test process. adopt owners
// whose short-lived cli launcher exits, then reap them after registrations stop.
func joinNamedWorkflowOwners(t *testing.T) {
	t.Helper()
	if !*cliWorkflowChild {
		t.Fatal("automatic owner joining requires the isolated CLI workflow child")
	}
	changed := make(chan os.Signal, 1)
	signal.Notify(changed, syscall.SIGCHLD)
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		signal.Stop(changed)
		t.Fatal("adopt automatic publisher owners:", err)
	}
	t.Cleanup(func() {
		defer signal.Stop(changed)
		defer func() {
			if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 0, 0, 0, 0); err != nil {
				t.Error("release automatic publisher owner adoption:", err)
			}
		}()
		deadline := time.NewTimer(15 * time.Second)
		defer deadline.Stop()
		for {
			var status unix.WaitStatus
			pid, err := unix.Wait4(-1, &status, unix.WNOHANG, nil)
			if errors.Is(err, unix.ECHILD) {
				return
			}
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if err != nil {
				t.Error("join automatic publisher owner:", err)
				return
			}
			if pid > 0 {
				if status.Signaled() {
					t.Errorf("automatic publisher owner %d terminated by %s", pid, status.Signal())
				} else if !status.Exited() || status.ExitStatus() != 0 {
					t.Errorf("automatic publisher owner %d exited with status %d", pid, status.ExitStatus())
				}
				continue
			}
			select {
			case <-changed:
			case <-deadline.C:
				t.Error("automatic publisher owner did not exit after its registrations stopped")
				return
			}
		}
	})
}

var namedOwnerFixture = flag.String("tnl-named-owner-fixture", "", "private automatic owner lifetime fixture")
var namedOwnerAddress = flag.String("tnl-named-owner-address", "", "private automatic owner readiness socket")
var namedOwnerRecord = flag.String("tnl-named-owner-record", "", "private automatic owner PID record")
var namedOwnerExit = flag.Int("tnl-named-owner-exit", 0, "private automatic owner exit status")

func TestNamedWorkflowJoinsAutomaticOwner(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range []int{0, 7} {
		t.Run(fmt.Sprintf("owner exit %d", status), func(t *testing.T) {
			record := filepath.Join(t.TempDir(), "owner")
			command := exec.CommandContext(t.Context(), executable, "-test.run=^TestNamedWorkflowOwnerFixture$", "-test.v", "-test.timeout=30s", "-tnl-cli-workflow-child", "-tnl-named-owner-fixture=parent", "-tnl-named-owner-record="+record, fmt.Sprintf("-tnl-named-owner-exit=%d", status))
			output, err := command.CombinedOutput()
			if status == 0 && err != nil {
				t.Fatalf("join automatic owner: %v\n%s", err, output)
			}
			if status != 0 && (err == nil || !strings.Contains(string(output), "exited with status 7")) {
				t.Fatalf("automatic owner failure was lost: %v\n%s", err, output)
			}
			data, err := os.ReadFile(record)
			if err != nil {
				t.Fatal(err)
			}
			pid, err := strconv.Atoi(string(data))
			if err != nil {
				t.Fatal(err)
			}
			if err := unix.Kill(pid, 0); !errors.Is(err, unix.ESRCH) {
				t.Fatalf("automatic owner %d was not reaped: %v", pid, err)
			}
		})
	}
}

func TestNamedWorkflowOwnerFixture(t *testing.T) {
	if *namedOwnerFixture == "" {
		t.Skip("private subprocess fixture")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	arguments := []string{"-test.run=^TestNamedWorkflowOwnerFixture$", "-test.timeout=30s", "-tnl-named-owner-record=" + *namedOwnerRecord, fmt.Sprintf("-tnl-named-owner-exit=%d", *namedOwnerExit)}
	switch *namedOwnerFixture {
	case "parent":
		joinNamedWorkflowOwners(t)
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		launcher := exec.CommandContext(t.Context(), executable, append(arguments, "-tnl-named-owner-fixture=launcher", "-tnl-named-owner-address="+listener.Addr().String())...)
		if output, err := launcher.CombinedOutput(); err != nil {
			t.Fatalf("automatic owner launcher: %v\n%s", err, output)
		}
		if err := listener.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		connection, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		var pid int
		if _, err := fmt.Fscanln(connection, &pid); err != nil {
			t.Fatal(err)
		}
		if err := unix.Kill(pid, 0); err != nil {
			t.Fatal("owner did not outlive its launcher:", err)
		}
		// registered after the join: cleanup releases the owner, then reaps it.
		t.Cleanup(func() {
			defer connection.Close()
			if _, err := fmt.Fprintln(connection, "stop"); err != nil {
				t.Error(err)
			}
		})
	case "launcher":
		owner := exec.Command(executable, append(arguments, "-tnl-named-owner-fixture=owner", "-tnl-named-owner-address="+*namedOwnerAddress)...)
		// match runtime endpoint: the owner intentionally outlives this launcher.
		if err := owner.Start(); err != nil {
			t.Fatal(err)
		}
	case "owner":
		connection, err := net.Dial("tcp", *namedOwnerAddress)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		if err := os.WriteFile(*namedOwnerRecord, []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := fmt.Fprintln(connection, os.Getpid()); err != nil {
			t.Fatal(err)
		}
		var stop string
		if _, err := fmt.Fscanln(connection, &stop); err != nil || stop != "stop" {
			t.Fatalf("owner cleanup release: %q, %v", stop, err)
		}
		os.Exit(*namedOwnerExit)
	default:
		t.Fatal("unknown automatic owner fixture phase")
	}
}
