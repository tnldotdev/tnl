package publisher

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"flag"
	"io"
	"net"
	"sync"
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

func TestTCPVisitorFollowsReplacedBindingWithoutReplacingPublicURLServer(t *testing.T) {
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
	var mu sync.Mutex
	address := first.Addr().String()
	route, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "shell.example", ServiceProtocol: controlv1.Ssh, PublicPort: 2222,
		Target: address, Certificate: publicURLTestCertificate(t, "shell.example"),
		ResolveTarget: func(context.Context) (string, error) {
			mu.Lock()
			defer mu.Unlock()
			if address == "" {
				return "", errors.New("binding unavailable")
			}
			return address, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer route.Close()
	visit := func(listener net.Listener) {
		t.Helper()
		visitor := openDatabaseVisitor(t, route, 2222)
		defer visitor.Close()
		if tcp, ok := listener.(*net.TCPListener); ok {
			_ = tcp.SetDeadline(time.Now().Add(time.Second))
		}
		conn, err := listener.Accept()
		if err != nil {
			t.Fatalf("current binding was not reached: %v", err)
		}
		conn.Close()
	}
	visit(first)
	mu.Lock()
	address = ""
	mu.Unlock()
	visitor := openDatabaseVisitor(t, route, 2222)
	if _, err := visitor.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("missing binding: %v", err)
	}
	visitor.Close()
	mu.Lock()
	address = second.Addr().String()
	mu.Unlock()
	visit(second)
}

func TestTCPVisitorChecksCurrentNamedLeaseBeforeDialingTarget(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var current atomic.Bool
	current.Store(true)
	route, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "shell.example", ServiceProtocol: controlv1.Ssh, PublicPort: 2222,
		Target: listener.Addr().String(), Certificate: publicURLTestCertificate(t, "shell.example"),
		AdmitConnection: func() error {
			if !current.Load() {
				return errors.New("stale lease")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer route.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- struct{}{}
			_ = conn.Close()
		}
	}()
	first := openDatabaseVisitor(t, route, 2222)
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("current lease did not reach target")
	}
	_ = first.Close()
	current.Store(false)
	stale := openDatabaseVisitor(t, route, 2222)
	if _, err := stale.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("stale visitor = %v, want EOF", err)
	}
	if tcp, ok := listener.(*net.TCPListener); ok {
		_ = tcp.SetDeadline(time.Now().Add(200 * time.Millisecond))
	}
	if conn, err := listener.Accept(); err == nil {
		_ = conn.Close()
		t.Fatal("stale visitor reached the TCP target")
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("target accept after stale lease = %v", err)
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
