//go:build linux || darwin

package managedssh

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSSHChildTerminalModes(t *testing.T) {
	runner, username := testRunner(t)
	config := protocolConfig(t)
	config.Users = []string{username}
	client, done := protocolServer(t, config, runner)
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err := session.RequestPty("xterm", 24, 80, ssh.TerminalModes{ssh.ECHO: 0, ssh.ICANON: 0, ssh.VINTR: 2, ssh.VEOF: 7, ssh.ONLCR: 0, ssh.TTY_OP_ISPEED: 9600, ssh.TTY_OP_OSPEED: 9600}); err != nil {
		t.Fatal(err)
	}
	output, err := session.Output("stty -a")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"-echo", "-icanon", "intr = ^B", "eof = ^G", "9600"} {
		if !strings.Contains(string(output), want) {
			t.Fatalf("terminal modes missing %q: %s", want, output)
		}
	}
	_ = client.Close()
	awaitProtocol(t, done)
}

func TestSSHChildSignalAndExitSignal(t *testing.T) {
	for _, pty := range []bool{false, true} {
		t.Run(map[bool]string{false: "command", true: "pty"}[pty], func(t *testing.T) {
			runner, username := testRunner(t)
			config := protocolConfig(t)
			config.Users = []string{username}
			client, done := protocolServer(t, config, runner)
			session, err := client.NewSession()
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			stdout, err := session.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			input, err := session.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			if pty {
				if err := session.RequestPty("xterm", 24, 80, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
					t.Fatal(err)
				}
			}
			if err := session.Start("exec /bin/sh -c 'printf ready; exec sleep 30'"); err != nil {
				t.Fatal(err)
			}
			ready := make(chan error, 1)
			go func() { var data [5]byte; _, err := io.ReadFull(stdout, data[:]); ready <- err }()
			if err := awaitProtocol(t, ready); err != nil {
				t.Fatal(err)
			}
			if err := session.Signal(ssh.SIGTERM); err != nil {
				t.Fatal(err)
			}
			wait := make(chan error, 1)
			go func() { wait <- session.Wait() }()
			err = awaitProtocol(t, wait)
			var exit *ssh.ExitError
			if !errors.As(err, &exit) || exit.Signal() != "TERM" {
				t.Fatalf("signal exit = %v", err)
			}
			_ = client.Close()
			awaitProtocol(t, done)
		})
	}
}

func TestChildSignalTrap(t *testing.T) {
	runner, username := testRunner(t)
	signals := make(chan string, 1)
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := make(chan int, 1)
	input, inputWriter := io.Pipe()
	defer input.Close()
	defer inputWriter.Close()
	go func() {
		code, err := runner.Run(ctx, Request{Username: username, Kind: "command", Command: "trap 'printf trapped; exit 23' USR1; printf ready; read line"}, Streams{Stdin: input, CloseInput: func() { _ = inputWriter.Close() }, Stdout: writer, Stderr: io.Discard, Signals: signals})
		if err != nil {
			code = -1
		}
		writer.Close()
		result <- code
	}()
	var ready [5]byte
	if _, err := io.ReadFull(reader, ready[:]); err != nil {
		t.Fatal(err)
	}
	signals <- "USR1"
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if code := awaitProtocol(t, result); code != 23 || string(output) != "trapped" {
		t.Fatalf("trap exit=%d output=%q", code, output)
	}
}
