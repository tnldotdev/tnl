//go:build tnl_benchtrace && linux

package main

import (
	"context"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability/runtimetrace"
)

var benchtraceSmokeChild = flag.Bool("tnl-benchtrace-smoke-child", false, "isolated tagged init smoke")

func TestBenchtraceInit(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cr, cw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer cr.Close()
	defer cw.Close()
	rr, rw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer rr.Close()
	defer rw.Close()
	doneRead, doneWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer doneRead.Close()
	defer doneWrite.Close()
	command := exec.CommandContext(ctx, executable, "-test.run=^TestBenchtraceInitChild$", "-test.count=1", "-tnl-benchtrace-smoke-child=true", runtimetrace.CommandFDFlag+"=3", runtimetrace.ReplyFDFlag+"=4", runtimetrace.DirectoryFlag+"="+filepath.Join(t.TempDir(), "native"))
	command.ExtraFiles = []*os.File{cr, rw, doneRead}
	var output strings.Builder
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	_ = cr.Close()
	_ = rw.Close()
	_ = doneRead.Close()
	decoder := runtimetrace.NewDecoder(rr)
	for _, c := range []runtimetrace.Command{{ID: 1, Kind: runtimetrace.Arm, Phase: "phase", Component: "visitor-1", Start: time.Now().Add(3 * time.Second), Duration: time.Second}, {ID: 2, Kind: runtimetrace.Export}} {
		if err := runtimetrace.WriteFrame(cw, c); err != nil {
			t.Fatal(err)
		}
		var reply runtimetrace.Reply
		if err := decoder.Read(&reply); err != nil || reply.Error != "" || reply.ID != c.ID {
			t.Fatalf("tagged init ACK: %+v %v", reply, err)
		}
	}
	_, _ = doneWrite.Write([]byte{1})
	if err := command.Wait(); err != nil {
		t.Fatalf("tagged init: %v\n%s", err, output.String())
	}
}

func TestBenchtraceInitChild(t *testing.T) {
	if !*benchtraceSmokeChild {
		t.Skip("isolated tagged init subprocess only")
	}
	for _, arg := range os.Args {
		if strings.HasPrefix(arg, "-tnl-native-trace-") {
			t.Fatal("private recorder flag was not stripped before CLI/test parsing")
		}
	}
	f, err := runtimetrace.OpenPipeFD(5, "smoke-complete")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := io.ReadFull(f, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
}
