//go:build linux || darwin

package managedssh

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pkg/sftp"
)

func TestChildProcess(t *testing.T) {
	mode := os.Args[len(os.Args)-1]
	if mode != "--managed-ssh-test-child" && mode != "--managed-ssh-production-child" {
		return
	}
	if runChild(context.Background(), mode == "--managed-ssh-test-child") != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func testRunner(t *testing.T) (*Runner, string) {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if u.Uid == "0" {
		t.Skip("same-uid subprocess tests require a non-root developer account")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return &Runner{Executable: exe, Args: []string{"-test.run=^TestChildProcess$", "--", "--managed-ssh-test-child"}, allowSameUID: true}, u.Username
}

func TestChildCommandIdentityEnvironmentAndExit(t *testing.T) {
	r, name := testRunner(t)
	t.Setenv("TNL_CHILD_MUST_NOT_INHERIT", "secret")
	var out, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	code, err := r.Run(ctx, Request{Username: name, Kind: "command", Command: `id -u; printf '%s\n' "$HOME" "$USER" "$LOGNAME" "${TNL_CHILD_MUST_NOT_INHERIT-unset}"; pwd; exit 37`}, Streams{Stdout: &out, Stderr: &stderr})
	if err != nil || code != 37 {
		t.Fatalf("code=%d err=%v stderr=%s", code, err, &stderr)
	}
	a, err := lookupAccount(name)
	if err != nil {
		t.Fatal(err)
	}
	want := strconv.Itoa(a.uid) + "\n" + a.home + "\n" + name + "\n" + name + "\nunset\n" + a.home + "\n"
	if out.String() != want {
		t.Fatalf("output %q, want %q", out.String(), want)
	}
}

func TestChildPTYSizeAndResize(t *testing.T) {
	r, name := testRunner(t)
	resize := make(chan Window, 1)
	resize <- Window{Width: 101, Height: 39}
	var out bytes.Buffer
	var stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	code, err := r.Run(ctx, Request{Username: name, Kind: "command", Command: "stty size; sleep 0.2; stty size", Term: "xterm", Window: Window{Width: 80, Height: 24}}, Streams{Stdout: &out, Stderr: &stderr, Resize: resize})
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v stderr=%s", code, err, &stderr)
	}
	if !strings.Contains(out.String(), "39 101") {
		t.Fatalf("resize not applied: %q", out.String())
	}
}

func TestChildInputEOF(t *testing.T) {
	r, name := testRunner(t)
	var out bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	code, err := r.Run(ctx, Request{Username: name, Kind: "command", Command: "cat"}, Streams{Stdin: strings.NewReader("input"), Stdout: &out, Stderr: io.Discard})
	if err != nil || code != 0 || out.String() != "input" {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}

func TestChildPTYInputEOF(t *testing.T) {
	r, name := testRunner(t)
	var out bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	code, err := r.Run(ctx, Request{Username: name, Kind: "command", Command: "cat", Term: "xterm"}, Streams{Stdin: strings.NewReader("input"), Stdout: &out, Stderr: io.Discard})
	if err != nil || code != 0 || !strings.Contains(out.String(), "input") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}

func TestChildCancelJoinsProcess(t *testing.T) {
	r, name := testRunner(t)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	var out bytes.Buffer
	_, err := r.Run(ctx, Request{Username: name, Kind: "command", Command: "echo $$; exec sleep 30"}, Streams{Stdout: &out, Stderr: io.Discard})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(out.String()))
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("session process remains: %v", err)
	}
}

func TestChildSFTP(t *testing.T) {
	r, name := testRunner(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	defer inR.Close()
	defer inW.Close()
	defer outR.Close()
	defer outW.Close()
	done := make(chan error, 1)
	go func() {
		_, err := r.Run(ctx, Request{Username: name, Kind: "sftp"}, Streams{Stdin: inR, Stdout: outW, Stderr: io.Discard})
		outW.Close()
		done <- err
	}()
	client, err := sftp.NewClientPipe(outR, inW)
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/sftp-file"
	f, err := client.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write([]byte("sftp data")); err != nil {
		t.Fatal(err)
	}
	f.Close()
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "sftp data" {
		t.Fatalf("file=%q err=%v", got, err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestChildDialHalfClose(t *testing.T) {
	r, name := testRunner(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		data, err := io.ReadAll(conn)
		if err == nil {
			_, err = conn.Write(append([]byte("reply:"), data...))
		}
		done <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := r.Dial(ctx, name, listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(conn)
	if err != nil || string(data) != "reply:request" {
		t.Fatalf("data=%q err=%v", data, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestChildDialFailureBeforeReturn(t *testing.T) {
	r, name := testRunner(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := l.Addr().String()
	l.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if c, err := r.Dial(ctx, name, address); err == nil {
		c.Close()
		t.Fatal("accepted failed connection")
	}
}

func TestChildDialCancellationJoins(t *testing.T) {
	r, name := testRunner(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, err := r.Dial(ctx, name, l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	remote := <-accepted
	defer remote.Close()
	cancel()
	select {
	case <-c.(*childConn).done:
	case <-time.After(5 * time.Second):
		t.Fatal("forward child was not joined")
	}
	if c.(*childConn).p.cmd.ProcessState == nil {
		t.Fatal("child has not been waited for")
	}
}

func TestChildRootRequirement(t *testing.T) {
	_, name := testRunner(t)
	if _, err := (&Runner{}).Run(context.Background(), Request{Username: name, Kind: "shell"}, Streams{}); !errors.Is(err, errRootRequired) {
		t.Fatalf("expected root requirement, got %v", err)
	}
}

func TestChildProductionEntryRejectsSameUID(t *testing.T) {
	r, name := testRunner(t)
	r.Args[len(r.Args)-1] = "--managed-ssh-production-child"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := r.Run(ctx, Request{Username: name, Kind: "command", Command: "exit 0"}, Streams{}); !errors.Is(err, errChildSetup) {
		t.Fatalf("production child accepted an unprivileged service: %v", err)
	}
}

func TestChildRejectsMalformedInheritedSetup(t *testing.T) {
	r, name := testRunner(t)
	valid, err := json.Marshal(childSetup{Request: Request{Username: name, Kind: "command", Command: "printf must-not-run"}})
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := json.Marshal(map[string]any{"Request": Request{Username: name, Kind: "command", Command: "printf must-not-run"}, "AllowSameUID": true})
	if err != nil {
		t.Fatal(err)
	}
	for label, data := range map[string][]byte{
		"unknown field": unknown,
		"extra value":   append(append([]byte{}, valid...), []byte(" {}")...),
		"oversized":     []byte(strings.Repeat("x", maxSetup+1)),
		"invalid json":  []byte("{secret-invalid-data"),
	} {
		t.Run(label, func(t *testing.T) {
			path := t.TempDir() + "/setup"
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			config, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer config.Close()
			statusR, statusW, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer statusR.Close()
			defer statusW.Close()
			resize, err := os.Open(os.DevNull)
			if err != nil {
				t.Fatal(err)
			}
			defer resize.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, r.Executable, r.Args...)
			cmd.Env = []string{"PATH=/usr/bin:/bin"}
			cmd.ExtraFiles = []*os.File{config, statusW, resize}
			var out bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = &out
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			statusW.Close()
			var result childStatus
			decodeErr := json.NewDecoder(statusR).Decode(&result)
			waitErr := cmd.Wait()
			if decodeErr != nil || !result.Failed || waitErr == nil || out.Len() != 0 {
				t.Fatalf("decode=%v status=%+v wait=%v output=%q", decodeErr, result, waitErr, out.String())
			}
		})
	}
}

func TestChildRejectsInvalidSetup(t *testing.T) {
	_, name := testRunner(t)
	for _, s := range []childSetup{
		{Request: Request{Username: name, Kind: "command", Command: "\x00"}},
		{Request: Request{Username: name, Kind: "sftp", Term: "xterm"}},
		{Request: Request{Username: name, Kind: "shell", Window: Window{Width: 65536}}},
		{Request: Request{Username: name, Kind: "dial"}, Address: "127.0.0.1:0"},
	} {
		if validateSetup(s) == nil {
			t.Errorf("accepted invalid setup: %+v", s)
		}
	}
}

func TestChildEarlyExitDoesNotBlockSetup(t *testing.T) {
	r, name := testRunner(t)
	r.Executable = "/usr/bin/false"
	r.Args = []string{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := r.Run(ctx, Request{Username: name, Kind: "command", Command: strings.Repeat("x", 64<<10)}, Streams{}); !errors.Is(err, errChildSetup) {
		t.Fatalf("unexpected early-exit error: %v", err)
	}
}
