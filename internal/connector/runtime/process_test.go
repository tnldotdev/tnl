package runtime

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

var lockChild = flag.String("tnl-owner-lock-child", "", "private directory for the native lifetime-lock subprocess fixture")

func TestConnectionOwnerKernelDeathRecovery(t *testing.T) {
	if *lockChild != "" {
		lock, err := ownerLock(*lockChild)
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Close()
		_, _ = fmt.Fprintln(os.Stdout, "ready")
		time.Sleep(time.Hour)
		return
	}
	directory, err := NewDirectory(fixtureScope(t).Directory)
	if err != nil {
		t.Fatal(err)
	}
	child := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestConnectionOwnerKernelDeathRecovery$", "-tnl-owner-lock-child="+directory)
	pipe, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	ready := make(chan string, 1)
	go func() { line, _ := bufio.NewReader(pipe).ReadString('\n'); ready <- line }()
	select {
	case line := <-ready:
		if line != "ready\n" {
			t.Fatal("child owner did not acquire its lock")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("owner startup timed out")
	}
	handle := filepath.Join(directory, "handle.json")
	if err := OwnerStopped(handle); !errors.Is(err, ErrUnavailable) {
		t.Fatal("live native owner was replaceable", err)
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()
	if err := OwnerStopped(handle); err != nil {
		t.Fatal("kernel did not release the dead native owner's lock", err)
	}
}
