package sshclient

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func transferSession(t *testing.T) Session {
	t.Helper()
	for _, binary := range []string{"ssh", "scp", "sftp"} {
		if _, err := exec.LookPath(binary); err != nil {
			t.Skip("system OpenSSH transfer clients are unavailable")
		}
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	session := testSession(t)
	session.Executable = filepath.Join(t.TempDir(), "tnl's %h helper")
	session.HostKey = string(ssh.MarshalAuthorizedKey(fixtureSigner(t).PublicKey()))
	script := "#!/bin/sh\nexec " + shellQuote(binary) + " '-test.run=^TestOpenSSHHelper$' -tnl-ssh-client-helper\n"
	if err := os.WriteFile(session.Executable, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return session
}

func TestSystemCopyUploadsAndDownloadsUsingSFTP(t *testing.T) {
	session := transferSession(t)
	dir := t.TempDir()
	source, remote, destination := filepath.Join(dir, "local:source 'file"), filepath.Join(dir, "remote 'file"), filepath.Join(dir, "download")
	data := []byte("managed file transfer\n")
	if err := os.WriteFile(source, data, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	var stdout, stderr bytes.Buffer
	if err := RunCopy(ctx, session, CopyOptions{LocalPath: source, RemotePath: remote, Upload: true}, strings.NewReader(""), &stdout, &stderr); err != nil {
		t.Fatalf("upload: %v; stderr=%s", err, &stderr)
	}
	if err := RunCopy(ctx, session, CopyOptions{LocalPath: destination, RemotePath: remote}, strings.NewReader(""), &stdout, &stderr); err != nil {
		t.Fatalf("download: %v; stderr=%s", err, &stderr)
	}
	got, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("copied file changed: %q, %v", got, err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("copy wrote non-file output to stdout: %q", &stdout)
	}
	wrongPin := testSession(t).HostKey
	session.HostKey = wrongPin
	err = RunCopy(ctx, session, CopyOptions{LocalPath: source, RemotePath: filepath.Join(dir, "must-not-exist"), Upload: true}, strings.NewReader(""), io.Discard, io.Discard)
	var exit *ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("wrong pin did not fail transfer: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "must-not-exist")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("wrong-pin transfer reached SFTP")
	}
}

func TestSystemSFTPUsesManagedHostPin(t *testing.T) {
	session := transferSession(t)
	dir := t.TempDir()
	source, destination := filepath.Join(dir, "source"), filepath.Join(dir, "remote")
	if err := os.WriteFile(source, []byte("interactive transfer"), 0o600); err != nil {
		t.Fatal(err)
	}
	commands := "put \"" + source + "\" \"" + destination + "\"\nbye\n"
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	var stdout, stderr bytes.Buffer
	if err := RunSFTP(ctx, session, strings.NewReader(commands), &stdout, &stderr); err != nil {
		t.Fatalf("interactive sftp: %v; stderr=%s stdout=%s", err, &stderr, &stdout)
	}
	got, err := os.ReadFile(destination)
	if err != nil || string(got) != "interactive transfer" {
		t.Fatalf("interactive transfer changed: %q %v", got, err)
	}
}

func TestTransferRejectsUnsafeSettingsBeforeInvocation(t *testing.T) {
	session := testSession(t)
	for _, path := range []string{"", "file\nother", "file\x00secret", strings.Repeat("x", 4097)} {
		if err := RunCopy(t.Context(), session, CopyOptions{LocalPath: "local", RemotePath: path}, nil, nil, nil); !errors.Is(err, ErrInvalidTransfer) {
			t.Fatalf("invalid transfer path accepted: %v", err)
		}
	}
	session.LocalForwards = []string{"8080:localhost:80"}
	if err := RunSFTP(t.Context(), session, nil, nil, nil); !errors.Is(err, ErrInvalidTransfer) {
		t.Fatalf("SFTP accepted forwarding options: %v", err)
	}
}

func TestSFTPCancellationStopsProxyHelper(t *testing.T) {
	session := transferSession(t)
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ready := filepath.Join(t.TempDir(), "ready")
	script := "#!/bin/sh\nexec " + shellQuote(binary) + " '-test.run=^TestOpenSSHHelper$' -tnl-ssh-client-helper -tnl-ssh-client-ready-file " + shellQuote(ready) + "\n"
	if err := os.WriteFile(session.Executable, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	input, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	defer writer.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- RunSFTP(ctx, session, input, io.Discard, io.Discard) }()
	pid := 0
	for ctx.Err() == nil {
		data, _ := os.ReadFile(ready)
		if pid, _ = strconv.Atoi(string(data)); pid > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if pid <= 0 {
		t.Fatal("SFTP proxy did not become ready")
	}
	proxyRunning := true
	t.Cleanup(func() {
		if proxyRunning {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	})
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("SFTP cancellation blocked")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
			proxyRunning = false
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("SFTP left its proxy helper running")
}
