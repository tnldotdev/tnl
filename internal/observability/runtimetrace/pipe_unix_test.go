//go:build unix

package runtimetrace

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

var pipeTestChild = flag.Bool("tnl-native-pipe-test-child", false, "isolated inherited pipe test")

func TestOpenPipeFDInheritance(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	commands, commandWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer commands.Close()
	defer commandWriter.Close()
	replyReader, replies, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer replyReader.Close()
	defer replies.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-test.run=^TestOpenPipeFDInheritanceChild$", "-tnl-native-pipe-test-child=true")
	command.ExtraFiles = []*os.File{commands, replies}
	var output strings.Builder
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	_ = commands.Close()
	_ = replies.Close()
	if _, err := commandWriter.Write([]byte("parent")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, len("child"))
	if _, err := io.ReadFull(replyReader, b); err != nil || string(b) != "child" {
		t.Fatalf("adopted pipe exchange: %q %v", b, err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("inherited pipe child: %v\n%s", err, output.String())
	}
}

func TestOpenPipeFDInheritanceChild(t *testing.T) {
	if !*pipeTestChild {
		t.Skip("isolated inherited pipe subprocess only")
	}
	for _, fd := range []uintptr{3, 4} {
		flags, err := unix.FcntlInt(fd, unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC != 0 {
			t.Fatalf("ExtraFiles did not arrive ready for adoption: fd=%d flags=%d error=%v", fd, flags, err)
		}
	}
	// prove the exec probe detects the raw ExtraFiles before adoption. Go's
	// child launcher must not be mistaken for the close-on-exec boundary.
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	probe := func() error {
		return exec.CommandContext(ctx, "/bin/sh", "-ec", "if [ -e /dev/fd/3 ] || [ -e /dev/fd/4 ]; then exit 1; fi").Run()
	}
	var inherited *exec.ExitError
	if err := probe(); !errors.As(err, &inherited) || inherited.ExitCode() != 1 {
		t.Fatalf("negative control did not detect inherited raw descriptors: %v", err)
	}
	commands, err := OpenPipeFD(3, "commands")
	if err != nil {
		t.Fatal(err)
	}
	defer commands.Close()
	replies, err := OpenPipeFD(4, "replies")
	if err != nil {
		t.Fatal(err)
	}
	defer replies.Close()
	for _, fd := range []uintptr{3, 4} {
		flags, err := unix.FcntlInt(fd, unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC == 0 {
			t.Fatalf("adopted pipe can leak across exec: fd=%d flags=%d error=%v", fd, flags, err)
		}
	}
	// this actual descendant receives no ExtraFiles. use a shell rather than
	// another Go runtime, which could reuse the closed descriptor numbers.
	if err := probe(); err != nil {
		t.Fatalf("descendant inherited private recorder descriptors: %v", err)
	}
	b := make([]byte, len("parent"))
	if _, err := io.ReadFull(commands, b); err != nil || string(b) != "parent" {
		t.Fatalf("parent command pipe: %q %v", b, err)
	}
	if _, err := replies.Write([]byte("child")); err != nil {
		t.Fatal(err)
	}
}
