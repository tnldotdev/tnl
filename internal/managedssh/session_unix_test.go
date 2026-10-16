//go:build linux || darwin

package managedssh

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"testing"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func TestSSHUserChildCommandAndSFTP(t *testing.T) {
	runner, username := testRunner(t)
	config := protocolConfig(t)
	config.Users = []string{username}
	client, done := protocolServer(t, config, runner)
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	session.Stdout, session.Stderr = &out, &stderr
	err = session.Run("printf stdout; printf stderr >&2; exit 19")
	var exit *ssh.ExitError
	if !errors.As(err, &exit) || exit.ExitStatus() != 19 || out.String() != "stdout" || stderr.String() != "stderr" {
		t.Fatalf("command: %q, %q, %v", &out, &stderr, err)
	}
	_ = session.Close()
	files, err := sftp.NewClient(client)
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/ssh-sftp-file"
	file, err := files.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("over SSH to the user child")); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "over SSH to the user child" {
		t.Fatalf("file = %q, %v", data, err)
	}
	_ = files.Close()
	_ = client.Close()
	awaitProtocol(t, done)
}

func TestSSHUserChildForwardTargetHalfClose(t *testing.T) {
	runner, username := testRunner(t)
	config := protocolConfig(t)
	config.Users = []string{username}
	client, done := protocolServer(t, config, runner)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	input := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			input <- "accept failed"
			return
		}
		defer conn.Close()
		_, _ = io.WriteString(conn, "target output")
		_ = conn.(*net.TCPConn).CloseWrite()
		data, _ := io.ReadAll(conn)
		input <- string(data)
	}()
	host, port, _ := net.SplitHostPort(listener.Addr().String())
	number, _ := strconv.Atoi(port)
	channel, requests, err := client.OpenChannel("direct-tcpip", ssh.Marshal(struct {
		Host       string
		Port       uint32
		Origin     string
		OriginPort uint32
	}{host, uint32(number), "127.0.0.1", 1234}))
	if err != nil {
		t.Fatal(err)
	}
	defer channel.Close()
	go ssh.DiscardRequests(requests)
	output := make(chan string, 1)
	go func() { data, _ := io.ReadAll(channel); output <- string(data) }()
	if value := awaitProtocol(t, output); value != "target output" {
		t.Fatalf("forward output = %q", value)
	}
	if _, err := io.WriteString(channel, "input after output EOF"); err != nil {
		t.Fatal(err)
	}
	_ = channel.CloseWrite()
	if value := awaitProtocol(t, input); value != "input after output EOF" {
		t.Fatalf("forward input = %q", value)
	}
	_ = channel.Close()
	_ = client.Close()
	awaitProtocol(t, done)
}
