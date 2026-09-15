//go:build darwin

package main

import (
	"io"
	"os/exec"
	"testing"
	"time"
)

func TestWatchDevProcessExitAfterFastExit(t *testing.T) {
	command := exec.Command("sh", "-c", "exit 23")
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(output); err != nil {
		t.Fatal(err)
	}
	exited, err := watchDevProcessExit(command.Process.Pid)
	if err != nil {
		t.Fatalf("watch exited child: %v", err)
	}
	select {
	case err := <-exited:
		if err != nil {
			t.Fatalf("watch exited child: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("watch did not observe the exited child")
	}
	if err := command.Wait(); err == nil {
		t.Fatal("exited child status was lost")
	}
}
