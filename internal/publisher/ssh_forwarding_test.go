package publisher

import (
	"crypto/ed25519"
	"crypto/rand"
	"flag"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"golang.org/x/crypto/ssh"
)

var (
	testSSHAddress = flag.String("tnl-test-ssh-address", "", "disposable sshd host and port")
	testSSHHostKey = flag.String("tnl-test-ssh-host-key", "", "disposable sshd public host key")
)

func TestSSHForwardingRequiresInstalledCertificate(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	route, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "shell.example", ServiceProtocol: controlv1.Ssh, PublicPort: 2222,
		Target: listener.Addr().String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })
	visitor := openDatabaseVisitor(t, route, 2222)
	if _, err := visitor.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("SSH visitor before certificate installation = %v, want EOF", err)
	}
	tcpListener := listener.(*net.TCPListener)
	if err := tcpListener.SetDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if connection, err := listener.Accept(); err == nil {
		_ = connection.Close()
		t.Fatal("SSH target was contacted before certificate installation")
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("SSH target accept = %v, want timeout", err)
	}
	if err := tcpListener.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := route.InstallCertificate(publicURLTestCertificate(t, "shell.example")); err != nil {
		t.Fatal(err)
	}
	backendResult := make(chan string, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			backendResult <- err.Error()
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.WriteString(connection, "SSH-2.0-sshd\r\n"); err != nil {
			backendResult <- err.Error()
			return
		}
		var request [16]byte
		_, err = io.ReadFull(connection, request[:])
		if err != nil {
			backendResult <- err.Error()
			return
		}
		backendResult <- string(request[:])
	}()
	visitor = openDatabaseVisitor(t, route, 2222)
	var banner [14]byte
	if _, err := io.ReadFull(visitor, banner[:]); err != nil || string(banner[:]) != "SSH-2.0-sshd\r\n" {
		t.Fatalf("SSH host banner = %q, %v", banner, err)
	}
	if _, err := io.WriteString(visitor, "SSH-2.0-client\r\n"); err != nil {
		t.Fatal(err)
	}
	if received := awaitPublisherTest(t, backendResult); received != "SSH-2.0-client\r\n" {
		t.Fatalf("SSH target received %q", received)
	}
}

func TestSSHForwardingFollowsReplacedDockerTarget(t *testing.T) {
	first, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	var selected atomic.Value
	selected.Store(first.Addr().String())
	route, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "shell.example", ServiceProtocol: controlv1.Ssh, PublicPort: 2222,
		Target: first.Addr().String(), ResolveTarget: func() string { return selected.Load().(string) },
		Certificate: publicURLTestCertificate(t, "shell.example"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer route.Close()
	for _, entry := range []struct {
		listener net.Listener
		banner   string
	}{
		{first, "SSH-2.0-first\r\n"},
		{second, "SSH-2.0-second\r\n"},
	} {
		selected.Store(entry.listener.Addr().String())
		done := make(chan error, 1)
		go func() {
			backend, err := entry.listener.Accept()
			if err != nil {
				done <- err
				return
			}
			defer backend.Close()
			_, err = io.WriteString(backend, entry.banner)
			done <- err
		}()
		visitor := openDatabaseVisitor(t, route, 2222)
		banner := make([]byte, len(entry.banner))
		if _, err := io.ReadFull(visitor, banner); err != nil || string(banner) != entry.banner {
			t.Fatalf("rebound SSH banner = %q, %v; want %q", banner, err, entry.banner)
		}
		visitor.Close()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	selected.Store("")
	visitor := openDatabaseVisitor(t, route, 2222)
	if _, err := visitor.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("missing Docker service should not use the stale TCP target: %v", err)
	}
}

func TestIntegrationSSHClient(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	if *testSSHAddress == "" || *testSSHHostKey == "" {
		t.Skip("requires the SSH integration target and host key")
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(*testSSHHostKey))
	if err != nil {
		t.Fatal(err)
	}
	route, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "shell.example", ServiceProtocol: controlv1.Ssh, PublicPort: 2222,
		Target: *testSSHAddress, Certificate: publicURLTestCertificate(t, "shell.example"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })
	connection := openDatabaseVisitor(t, route, 2222)
	config := &ssh.ClientConfig{User: "tnl_test", Auth: []ssh.AuthMethod{ssh.Password("testpass")},
		HostKeyAlgorithms: []string{ssh.KeyAlgoED25519}, HostKeyCallback: ssh.FixedHostKey(key)}
	otherKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongKey, err := ssh.NewPublicKey(otherKey)
	if err != nil {
		t.Fatal(err)
	}
	untrusted := *config
	untrusted.HostKeyCallback = ssh.FixedHostKey(wrongKey)
	wrongConnection := openDatabaseVisitor(t, route, 2222)
	if _, _, _, err := ssh.NewClientConn(wrongConnection, "shell.example:2222", &untrusted); err == nil {
		t.Fatal("SSH client accepted an unexpected sshd host key")
	}
	_ = wrongConnection.Close()
	clientConnection, channels, requests, err := ssh.NewClientConn(connection, "shell.example:2222", config)
	if err != nil {
		t.Fatal(err)
	}
	client := ssh.NewClient(clientConnection, channels, requests)
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	output, err := session.CombinedOutput("printf ssh-ok")
	if err != nil || string(output) != "ssh-ok" {
		t.Fatalf("SSH command = %q, %v", output, err)
	}
}
