package main

import (
	"bufio"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

func TestChildResultPreservesExitStatus(t *testing.T) {
	process, err := startDevProcess([]string{"sh", "-c", "exit 23"}, os.Environ(), nil, io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	cleanupDevProcess(t, process)
	waitForDevProcessDone(t, process)
	assertDevProcessExitStatus(t, process, 23)
}

func TestWaitForDevTargetStopsWhenCommandExits(t *testing.T) {
	ctx := devBootstrapTestContext(t)
	bootstrap := startDevBootstrapTest(t, ctx, "", t.TempDir())
	process, err := startDevProcess([]string{"sh", "-c", "exit 0"}, os.Environ(), nil, io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	cleanupDevProcess(t, process)
	if _, err := waitForDevTarget(ctx, bootstrap, process); err == nil || err.Error() != "development server command exited before target registration" {
		t.Fatalf("wait error = %v", err)
	}
}

func TestDevProcessNaturalLeaderExitKillsDescendants(t *testing.T) {
	process, output, reader := startDevProcessTestCommand(t, "natural")
	waitForDevProcessDone(t, process)
	assertDevProcessExitStatus(t, process, 23)
	assertDevProcessOutputEOF(t, output, reader)
}

func TestDevProcessResponsiveStopKillsDescendantsAndPreservesExitStatus(t *testing.T) {
	process, output, reader := startDevProcessTestCommand(t, "responsive")
	stopped := make(chan error, 1)
	go func() { stopped <- process.Stop(5 * time.Second) }()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Stop waited for its timeout after the leader exited")
	}
	assertDevProcessExitStatus(t, process, 23)
	assertDevProcessOutputEOF(t, output, reader)
}

func TestDevProcessStopEscalatesWhenLeaderIgnoresSIGTERM(t *testing.T) {
	process, output, reader := startDevProcessTestCommand(t, "ignoring")
	const timeout = 100 * time.Millisecond
	started := time.Now()
	if err := process.Stop(timeout); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed < timeout {
		t.Fatalf("Stop escalated after %s, before its %s timeout", elapsed, timeout)
	}
	var exitErr *exec.ExitError
	if err := process.Err(); !errors.As(err, &exitErr) {
		t.Fatalf("leader wait error = %v", err)
	}
	status, ok := exitErr.ProcessState.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf("leader wait status = %v", exitErr.ProcessState.Sys())
	}
	assertDevProcessOutputEOF(t, output, reader)
}

func TestDevProcessConcurrentStop(t *testing.T) {
	process, output, reader := startDevProcessTestCommand(t, "responsive")
	const callers = 8
	started := make(chan struct{})
	stopped := make(chan error, callers)
	for range callers {
		go func() { <-started; stopped <- process.Stop(5 * time.Second) }()
	}
	close(started)
	for range callers {
		select {
		case err := <-stopped:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("concurrent Stop did not return after the leader exited")
		}
	}
	assertDevProcessExitStatus(t, process, 23)
	assertDevProcessOutputEOF(t, output, reader)
}

func TestDevProcessRepeatedStop(t *testing.T) {
	process, output, reader := startDevProcessTestCommand(t, "responsive")
	if err := process.Stop(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := process.Stop(0); err != nil {
			t.Fatalf("repeated Stop: %v", err)
		}
	}
	assertDevProcessExitStatus(t, process, 23)
	assertDevProcessOutputEOF(t, output, reader)
}

func cleanupDevProcess(t *testing.T, process *devProcess) {
	t.Helper()
	t.Cleanup(func() {
		select {
		case <-process.Done():
			return // run has already called Wait and reaped the child.
		default:
		}
		if err := process.Stop(time.Second); err != nil {
			t.Errorf("stop development process during cleanup: %v", err)
		}
		waitForDevProcessDone(t, process)
	})
}

func startDevProcessTestCommand(t *testing.T, mode string) (*devProcess, *os.File, *bufio.Reader) {
	t.Helper()
	output, outputWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = output.Close() })
	t.Cleanup(func() { _ = outputWriter.Close() })
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	process, err := startDevProcess(
		[]string{executable, "-test.run=^TestDevProcessHelper$", "--", mode},
		append(os.Environ(), "GO_WANT_DEV_PROCESS_HELPER=1", "GORACE=atexit_sleep_ms=0"), nil, outputWriter, os.Stderr,
	)
	if err != nil {
		t.Fatal(err)
	}
	cleanupDevProcess(t, process)
	if err := outputWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := output.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(output)
	if ready, err := reader.ReadString('\n'); err != nil || ready != "ready\n" {
		t.Fatalf("descendant readiness = %q, %v", ready, err)
	}
	return process, output, reader
}

func waitForDevProcessDone(t *testing.T, process *devProcess) {
	t.Helper()
	select {
	case <-process.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("development process leader did not exit")
	}
}

func assertDevProcessExitStatus(t *testing.T, process *devProcess, want int) {
	t.Helper()
	var exitErr *childExitError
	if err := childResult(process.Err()); !errors.As(err, &exitErr) || exitErr.code != want {
		t.Fatalf("leader exit result = %v, want status %d", err, want)
	}
}

func assertDevProcessOutputEOF(t *testing.T, output *os.File, reader *bufio.Reader) {
	t.Helper()
	if err := output.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	remaining, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("wait for descendant output EOF: %v", err)
	}
	if len(remaining) != 0 {
		t.Fatalf("unexpected descendant output: %q", remaining)
	}
}

func TestDevProcessHelper(t *testing.T) {
	if os.Getenv("GO_WANT_DEV_PROCESS_HELPER") != "1" {
		return
	}
	mode := os.Args[len(os.Args)-1]
	if mode == "descendant" {
		signal.Ignore(syscall.SIGTERM)
		if _, err := io.WriteString(os.Stdout, "ready\n"); err != nil {
			t.Fatal(err)
		}
		ready := os.NewFile(3, "leader-ready")
		if ready == nil {
			t.Fatal("missing leader readiness pipe")
		}
		if _, err := ready.Write([]byte{1}); err != nil {
			t.Fatal(err)
		}
		if err := ready.Close(); err != nil {
			t.Fatal(err)
		}
		for {
			time.Sleep(time.Hour)
		}
	}
	var terminated chan os.Signal
	switch mode {
	case "natural":
	case "responsive":
		terminated = make(chan os.Signal, 1)
		signal.Notify(terminated, syscall.SIGTERM)
	case "ignoring":
		signal.Ignore(syscall.SIGTERM)
	default:
		t.Fatal("unknown development process helper mode")
	}
	ready, readyWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ready.Close(); _ = readyWriter.Close() })
	child := exec.Command(os.Args[0], "-test.run=^TestDevProcessHelper$", "--", "descendant")
	child.Stdout, child.Stderr = os.Stdout, os.Stderr
	child.ExtraFiles = []*os.File{readyWriter}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	// On assertion failure reap the helper. Successful os.Exit deliberately leaves
	// descendants for the process-group cleanup under test.
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	if err := readyWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ready.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(ready, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	if err := ready.Close(); err != nil {
		t.Fatal(err)
	}
	if mode == "natural" {
		os.Exit(23)
	}
	if mode == "responsive" {
		<-terminated
		os.Exit(23)
	}
	for {
		time.Sleep(time.Hour)
	}
}
