package detached

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/connector"
	"github.com/tnldotdev/tnl/internal/failure"
)

var detachedHelperRoot = flag.String("tnl-detached-child-root", "", "private state root for detached process test")
var detachedHelperMode = flag.String("tnl-detached-child-mode", "pending", "startup state for detached process test")

func TestDetachedChildProcess(t *testing.T) {
	if *detachedHelperRoot == "" {
		return
	}
	if *detachedHelperMode == "fail-early" {
		t.Fatal("project configuration failed before a control socket exists")
	}
	if output, ok := strings.CutPrefix(*detachedHelperMode, "spawn-"); ok {
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		child, err := startDetachedProcess(binary, []string{"-test.run=^TestDetachedChildProcess$", "-tnl-detached-child-root=" + *detachedHelperRoot, "-tnl-detached-child-mode=write-" + output})
		if err != nil {
			t.Fatal(err)
		}
		if err := awaitDetachedCommandReady(t.Context(), child, *detachedHelperRoot, "abcdef0123456789abcdef01", 5*time.Second, func(string) error { return nil }); err != nil {
			t.Fatal(err)
		}
		return
	}
	ctx, cleanup, err := ServeWithOptions(context.Background(), *detachedHelperRoot, "abcdef0123456789abcdef01", clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if *detachedHelperMode == "fail-after-socket" {
		Starting(ctx)
		t.Fatal("publisher grant enrollment failed before readiness")
	}
	if *detachedHelperMode == "ready" {
		Starting(ctx)
		Ready(ctx)
	}
	if output, ok := strings.CutPrefix(*detachedHelperMode, "write-"); ok {
		Starting(ctx)
		Ready(ctx)
		for {
			if _, err := os.Stat(filepath.Join(*detachedHelperRoot, "write")); err == nil {
				break
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(10 * time.Millisecond):
			}
		}
		stream := os.Stdout
		if output == "stderr" {
			stream = os.Stderr
		}
		if _, err := io.WriteString(stream, "detached lifecycle output\n"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(*detachedHelperRoot, "wrote"), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if protocol, ok := strings.CutPrefix(*detachedHelperMode, "connection-"); ok {
		Starting(ctx)
		profile := connector.Profile{Schema: 1, ServiceID: "svc_0123456789ABCDEFGHIJKL", Protocol: config.ProtocolName(protocol), Hostname: "approved.example.test", ServicePort: 25443, Host: "127.0.0.1", Port: 15432, Public: true, ConnectorRequired: true, Authentication: "connector"}
		SetConnection(ctx, profile)
		time.Sleep(100 * time.Millisecond)
		Ready(ctx)
	}
	<-ctx.Done()
}

func TestDetachedOutputSurvivesParentExit(t *testing.T) {
	for _, output := range []string{"stdout", "stderr"} {
		t.Run(output, func(t *testing.T) {
			root, err := os.MkdirTemp("/tmp", "tnl-detached-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(root) })
			root, err = filepath.EvalSymlinks(root)
			if err != nil {
				t.Fatal(err)
			}
			state := filepath.Join(root, "state")
			const id = "abcdef0123456789abcdef01"
			t.Cleanup(func() { _, _ = Request(state, id, "stop") })
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			parent := exec.CommandContext(t.Context(), binary, "-test.run=^TestDetachedChildProcess$", "-tnl-detached-child-root="+state, "-tnl-detached-child-mode=spawn-"+output)
			if data, err := parent.CombinedOutput(); err != nil {
				t.Fatalf("detached launcher: %v %s", err, data)
			}
			// only the launcher owned the output reader. write after that process
			// has exited, not merely after it returned the ready notification.
			if err := os.WriteFile(filepath.Join(state, "write"), nil, 0600); err != nil {
				t.Fatal(err)
			}
			waitFor(t, 5*time.Second, func() bool {
				_, err := os.Stat(filepath.Join(state, "wrote"))
				return err == nil
			})
			if state, _, err := Status(state, id); err != nil || state != "ready" {
				t.Fatal("detached child did not survive output after launcher exit", state, err)
			}
		})
	}
}

func TestDetachedConnectorReturnsPreparedAddressForEveryProtocol(t *testing.T) {
	for _, protocol := range []string{"http", "postgres", "mysql", "tcp", "kubernetes"} {
		t.Run(protocol, func(t *testing.T) {
			root, err := os.MkdirTemp("/tmp", "tnl-detached-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(root) })
			root, err = filepath.EvalSymlinks(root)
			if err != nil {
				t.Fatal(err)
			}
			state := filepath.Join(root, "state")
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd, err := startDetachedProcess(binary, []string{"-test.run=^TestDetachedChildProcess$", "-tnl-detached-child-root=" + state, "-tnl-detached-child-mode=connection-" + protocol})
			if err != nil {
				t.Fatal(err)
			}
			const id = "abcdef0123456789abcdef01"
			var output bytes.Buffer
			err = awaitDetachedCommandReady(t.Context(), cmd, state, id, 5*time.Second, func(string) error {
				data, err := ReadConnection(state, id)
				if err == nil {
					_, err = output.Write(data)
				}
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _, _ = Request(state, id, "stop") }()
			var profile connector.Profile
			if json.Unmarshal(output.Bytes(), &profile) != nil || string(profile.Protocol) != protocol || profile.Host != "127.0.0.1" || profile.Port != 15432 || profile.Hostname != "approved.example.test" || !profile.Public || !profile.ConnectorRequired {
				t.Fatal("detached command omitted prepared local instructions", output.String())
			}
			status, _, err := Status(state, id)
			if err != nil || status != "ready" {
				t.Fatal("detached command exited before readiness", status, err)
			}
			if _, err := Request(state, id, "stop"); err != nil {
				t.Fatal(err)
			}
			waitFor(t, 3*time.Second, func() bool { _, err := os.Lstat(filepath.Join(state, "d", id)); return os.IsNotExist(err) })
		})
	}
}

func TestDetachedHandshakeWaitsForReadyAndReapsStartupFailures(t *testing.T) {
	for _, mode := range []string{"fail-early", "fail-after-socket", "ready", "pending"} {
		t.Run(mode, func(t *testing.T) {
			root, err := os.MkdirTemp("/tmp", "tnl-detached-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(root) })
			root, err = filepath.EvalSymlinks(root)
			if err != nil {
				t.Fatal(err)
			}
			stateRoot := filepath.Join(root, "state")
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd, err := startDetachedProcess(binary, []string{"-test.run=^TestDetachedChildProcess$", "-tnl-detached-child-root=" + stateRoot, "-tnl-detached-child-mode=" + mode})
			if err != nil {
				t.Fatal(err)
			}
			id := "abcdef0123456789abcdef01"
			var output bytes.Buffer
			timeout := 5 * time.Second
			if mode == "pending" {
				timeout = 100 * time.Millisecond
			}
			err = awaitDetachedCommandReady(t.Context(), cmd, stateRoot, id, timeout, func(string) error {
				_, err := fmt.Fprintln(&output, "ready")
				return err
			})
			if mode == "ready" {
				if err != nil || output.String() != "ready\n" {
					t.Fatalf("ready publication did not pass handshake: %s %v", output.String(), err)
				}
				if _, err := Request(stateRoot, id, "stop"); err != nil {
					t.Fatal(err)
				}
				deadline := time.Now().Add(2 * time.Second)
				for {
					if _, err := os.Lstat(filepath.Join(stateRoot, "d", id)); os.IsNotExist(err) {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("ready child did not remove its control socket after stop")
					}
					time.Sleep(10 * time.Millisecond)
				}
				return
			}
			if classified, ok := failure.Of(err); !ok || classified.Reason() != failure.DetachedStartFailed || output.Len() != 0 {
				t.Fatalf("%s was reported as a successful publication: %s %v", mode, output.String(), err)
			}
			if mode == "pending" {
				if _, statErr := os.Lstat(filepath.Join(stateRoot, "d", id)); !os.IsNotExist(statErr) {
					t.Fatalf("timed-out child left a control socket: %v", statErr)
				}
			}
		})
	}
}

func TestDetachedProcessHasIndependentSessionAndStopsBySocket(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "tnl-detached-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	stateRoot := filepath.Join(root, "state")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd, err := startDetachedProcess(binary, []string{"-test.run=^TestDetachedChildProcess$", "-tnl-detached-child-root=" + stateRoot})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	joined := false
	defer func() {
		if !joined {
			_ = cmd.Process.Kill()
			<-done
		}
	}()
	group, err := syscall.Getpgid(cmd.Process.Pid)
	if err != nil || group != cmd.Process.Pid {
		t.Fatalf("child did not start a new session: pgid=%d pid=%d err=%v", group, cmd.Process.Pid, err)
	}
	id := "abcdef0123456789abcdef01"
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := Request(stateRoot, id, "status"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("detached child did not open its control socket")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := Request(stateRoot, id, "stop"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		joined = true
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("detached child did not stop")
	}
	if _, err := os.Lstat(filepath.Join(stateRoot, "d", id)); !os.IsNotExist(err) {
		t.Fatalf("detached socket survived process exit: %v", err)
	}
}

func TestDetachedSocketOwnsStopAndDisappearsOnExit(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "tnl-detached-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	id := "0123456789abcdef01234567"
	ctx, cleanup, err := ServeWithOptions(t.Context(), filepath.Join(root, "state"), id, clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if _, _, err := ServeWithOptions(t.Context(), filepath.Join(root, "state"), id, clientstate.OpenOptions{Protection: clientstate.ProtectionFile}); err == nil {
		t.Fatal("a second child took the live control socket")
	}
	if _, err := Request(filepath.Join(root, "state"), id, "status"); err != nil {
		t.Fatalf("original detached child lost its listener: %v", err)
	}
	state, _, err := Status(filepath.Join(root, "state"), id)
	if err != nil || state != "booting" {
		t.Fatalf("control socket implied a publication was ready: %s %v", state, err)
	}
	entries, err := List(filepath.Join(root, "state"))
	if err != nil || len(entries) != 1 || entries[0].ID != id || entries[0].State != "booting" {
		t.Fatalf("detached list = %+v, %v", entries, err)
	}
	if err := Stop(filepath.Join(root, "state"), id); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("stop did not cancel the child")
	}
	if err := Stop(filepath.Join(root, "state"), id); err == nil {
		t.Fatal("duplicate stop was reported as a new successful stop")
	}
	cleanup()
	if _, err := os.Lstat(filepath.Join(root, "state", "d", id)); !os.IsNotExist(err) {
		t.Fatalf("socket still exists: %v", err)
	}
	if _, err := Request(filepath.Join(root, "state"), "../../outside", "stop"); err == nil {
		t.Fatal("invalid detached ID accepted")
	}
}

func TestDetachedContextStopsWithParentSignal(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "tnl-detached-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	parent, cancel := context.WithCancel(t.Context())
	child, cleanup, err := ServeWithOptions(parent, filepath.Join(root, "state"), "abcdef0123456789abcdef01", clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	cancel()
	select {
	case <-child.Done():
	case <-time.After(time.Second):
		t.Fatal("signal did not cancel detached worker")
	}
}
