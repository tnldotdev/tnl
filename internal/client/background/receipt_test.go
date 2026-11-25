package background

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"golang.org/x/sys/unix"
)

var receiptPipeFixture = flag.String("tnl-background-receipt-pipe", "", "receipt pipe fixture: closed or full")

func TestBackgroundReceiptPipeLauncher(t *testing.T) {
	if *receiptPipeFixture == "" {
		return
	}
	output, diagnostics := os.Stdout, os.Stderr
	if *helperOutput == "stderr" {
		output, diagnostics = diagnostics, output
	}
	opts := helperOptions(t, *helperRoot, testWork{})
	var pid int
	err := launch(t.Context(), opts, 2*time.Second, func(ctx context.Context, entry Entry) error {
		pid = entry.PID
		return json.NewEncoder(ReceiptWriter(ctx, output)).Encode(entry)
	})
	var want error = syscall.EPIPE
	if *receiptPipeFixture == "full" {
		want = context.DeadlineExceeded
	}
	var receiptErr *ReceiptWriteError
	if !errors.As(err, &receiptErr) || !errors.Is(err, want) || pid == 0 {
		fmt.Fprintln(diagnostics, "did not fail writing the ready child's receipt:", pid, err)
		os.Exit(1)
	}
	if _, err := syscall.Wait4(pid, nil, syscall.WNOHANG, nil); !errors.Is(err, syscall.ECHILD) {
		fmt.Fprintln(diagnostics, "launcher did not reap the child:", pid, err)
		os.Exit(1)
	}
	os.Exit(0) // the test runner's own output would write to the failed pipe
}

func TestBackgroundClosedOrFullReceiptPipeReapsChild(t *testing.T) {
	for _, mode := range []string{"closed", "full"} {
		for _, stream := range []string{"stdout", "stderr"} {
			t.Run(mode+"/"+stream, func(t *testing.T) {
				t.Parallel()
				root, scope := testScope(t, filepath.Join(t.TempDir(), "state"))
				reader, writer, err := os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				defer reader.Close()
				defer writer.Close()
				fd := writer.Fd()
				flags, err := unix.FcntlInt(fd, unix.F_GETFL, 0)
				if err != nil {
					t.Fatal(err)
				}
				if mode == "closed" {
					if err := reader.Close(); err != nil {
						t.Fatal(err)
					}
				} else {
					fillReceiptPipe(t, fd, flags)
				}
				// Darwin records that the pipe was used. snapshot the flags
				// after filling it, before the launcher sees the descriptor.
				flags, err = unix.FcntlInt(fd, unix.F_GETFL, 0)
				if err != nil {
					t.Fatal(err)
				}
				binary := helperOptions(t, root, testWork{}).Binary
				ctx, cancel := context.WithTimeout(t.Context(), 6*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, binary, "-test.run=^TestBackgroundReceiptPipeLauncher$",
					"-tnl-background-receipt-pipe="+mode, "-tnl-background-test-root="+root, "-tnl-background-test-output="+stream)
				var diagnostics bytes.Buffer
				cmd.Stdout, cmd.Stderr = writer, &diagnostics
				if stream == "stderr" {
					cmd.Stdout, cmd.Stderr = &diagnostics, writer
				}
				if err := cmd.Run(); err != nil {
					t.Fatalf("launcher did not handle the pipe failure: %v\n%s", err, &diagnostics)
				}
				if current, err := unix.FcntlInt(fd, unix.F_GETFL, 0); err != nil || current != flags {
					t.Fatalf("launcher changed shared descriptor flags: %x (was %x), %v", current, flags, err)
				}
				entries, err := os.ReadDir(scope)
				if err != nil {
					t.Fatal(err)
				}
				for _, entry := range entries {
					if opaqueid.Valid(entry.Name(), opaqueid.JobPrefix) {
						t.Fatalf("failed receipt left a job reservation: %s", entry.Name())
					}
				}
			})
		}
	}
}

func fillReceiptPipe(t *testing.T, fd uintptr, flags int) {
	t.Helper()
	if _, err := unix.FcntlInt(fd, unix.F_SETFL, flags|unix.O_NONBLOCK); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := unix.FcntlInt(fd, unix.F_SETFL, flags); err != nil {
			t.Fatal(err)
		}
	}()
	var chunk [4096]byte
	// finish with single-byte writes so even a short receipt cannot fit.
	for _, p := range [][]byte{chunk[:], chunk[:1]} {
		for {
			_, err := unix.Write(int(fd), p)
			if errors.Is(err, unix.EAGAIN) {
				break
			}
			if err != nil && !errors.Is(err, unix.EINTR) {
				t.Fatal(err)
			}
		}
	}
}
