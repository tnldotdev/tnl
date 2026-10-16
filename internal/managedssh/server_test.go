package managedssh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type protocolRunner struct {
	run  func(context.Context, Request, Streams) (int, error)
	dial func(context.Context, string, string) (net.Conn, error)
}

func (r protocolRunner) Run(ctx context.Context, req Request, streams Streams) (int, error) {
	return r.run(ctx, req, streams)
}

func (r protocolRunner) Dial(ctx context.Context, user, address string) (net.Conn, error) {
	return r.dial(ctx, user, address)
}

func protocolConfig(t *testing.T) Config {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return Config{HostKey: signer, Users: []string{"worker"}, Authorize: func(_ context.Context, identity Identity, user string) (Decision, error) {
		return Decision{IdentityID: identity.IdentityID, PublicURLID: identity.PublicURLID, SSHUser: user, ValidUntil: time.Now().Add(time.Minute)}, nil
	}}
}

func protocolServer(t *testing.T, config Config, runner childRunner) (*ssh.Client, <-chan error) {
	t.Helper()
	server, err := newServer(config, 0, func([]string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	server.runner = runner
	address, done := protocolListen(t, server)
	client, err := ssh.Dial("tcp", address, &ssh.ClientConfig{User: config.Users[0], HostKeyCallback: ssh.FixedHostKey(config.HostKey.PublicKey()), Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client, done
}

func protocolListen(t *testing.T, server *Server) (string, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			err = server.ServeConn(ctx, connection, Identity{IdentityID: "identity-a", PublicURLID: "url-a"})
		}
		done <- err
	}()
	t.Cleanup(func() { cancel(); _ = listener.Close() })
	return listener.Addr().String(), done
}

func awaitProtocol[T any](t *testing.T, result <-chan T) T {
	t.Helper()
	select {
	case value := <-result:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("SSH operation did not join")
		var zero T
		return zero
	}
}

func TestSSHExactIdentityAndHostAllowlist(t *testing.T) {
	for _, test := range []string{"host-user", "identity", "url", "grant-user", "expired", "grant-error"} {
		t.Run(test, func(t *testing.T) {
			config := protocolConfig(t)
			var calls atomic.Int32
			config.Authorize = func(_ context.Context, identity Identity, username string) (Decision, error) {
				calls.Add(1)
				if identity.IdentityID != "identity-a" || identity.PublicURLID != "url-a" {
					t.Error("lost trusted identity")
				}
				d := Decision{IdentityID: identity.IdentityID, PublicURLID: identity.PublicURLID, SSHUser: username, ValidUntil: time.Now().Add(time.Minute)}
				switch test {
				case "identity":
					d.IdentityID = "identity-b"
				case "url":
					d.PublicURLID = "url-b"
				case "grant-user":
					d.SSHUser = "different"
				case "expired":
					d.ValidUntil = time.Now().Add(-time.Second)
				case "grant-error":
					return Decision{}, errors.New("secret provider detail")
				}
				return d, nil
			}
			server, err := newServer(config, 0, func([]string) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			address, done := protocolListen(t, server)
			user := "worker"
			if test == "host-user" {
				user = "other"
			}
			client, err := ssh.Dial("tcp", address, &ssh.ClientConfig{User: user, HostKeyCallback: ssh.FixedHostKey(config.HostKey.PublicKey()), Timeout: time.Second})
			if err == nil {
				client.Close()
				t.Fatal("accepted denied SSH user")
			}
			if strings.Contains(err.Error(), "secret provider detail") {
				t.Fatal("exposed authorization cause")
			}
			awaitProtocol(t, done)
			if test == "host-user" && calls.Load() != 0 {
				t.Fatal("control grant bypassed host allowlist")
			}
		})
	}
}

func TestSSHCommandStreamsExitAndDeniedRequests(t *testing.T) {
	config := protocolConfig(t)
	client, done := protocolServer(t, config, protocolRunner{run: func(_ context.Context, req Request, streams Streams) (int, error) {
		if req.Kind != "command" || req.Command != "echo command" || req.Username != "worker" {
			t.Errorf("request = %#v", req)
		}
		_, _ = io.Copy(streams.Stdout, streams.Stdin)
		_, _ = io.WriteString(streams.Stderr, "separate stderr")
		return 17, nil
	}})
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	for _, typ := range []string{"auth-agent-req@openssh.com", "x11-req", "env", "signal"} {
		ok, err := session.SendRequest(typ, true, nil)
		if err != nil || ok {
			t.Fatalf("%s = %v, %v", typ, ok, err)
		}
	}
	for _, typ := range []string{"tcpip-forward", "streamlocal-forward@openssh.com"} {
		ok, _, err := client.SendRequest(typ, true, nil)
		if err != nil || ok {
			t.Fatalf("%s = %v, %v", typ, ok, err)
		}
	}
	channel, _, err := client.OpenChannel("direct-streamlocal@openssh.com", nil)
	if err == nil {
		channel.Close()
		t.Fatal("accepted Unix forwarding")
	}
	var out, stderr bytes.Buffer
	session.Stdin = strings.NewReader("input through EOF")
	session.Stdout, session.Stderr = &out, &stderr
	err = session.Run("echo command")
	var exit *ssh.ExitError
	if !errors.As(err, &exit) || exit.ExitStatus() != 17 || out.String() != "input through EOF" || stderr.String() != "separate stderr" {
		t.Fatalf("command = stdout %q stderr %q error %v", out.String(), stderr.String(), err)
	}
	_ = client.Close()
	awaitProtocol(t, done)
}

func TestSSHPTYResizeAndDisconnectJoinsChild(t *testing.T) {
	resized := make(chan Window, 1)
	joined := make(chan struct{})
	client, done := protocolServer(t, protocolConfig(t), protocolRunner{run: func(ctx context.Context, req Request, streams Streams) (int, error) {
		defer close(joined)
		if req.Kind != "shell" || req.Term != "xterm-256color" || req.Window.Width != 80 {
			t.Errorf("pty request = %#v", req)
		}
		select {
		case size := <-streams.Resize:
			resized <- size
		case <-ctx.Done():
			return 0, ctx.Err()
		}
		<-ctx.Done()
		return 0, ctx.Err()
	}})
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := session.RequestPty("xterm-256color", 24, 80, nil); err != nil {
		t.Fatal(err)
	}
	if err := session.Shell(); err != nil {
		t.Fatal(err)
	}
	if err := session.WindowChange(45, 120); err != nil {
		t.Fatal(err)
	}
	if size := awaitProtocol(t, resized); size.Width != 120 || size.Height != 45 {
		t.Fatalf("resize = %#v", size)
	}
	_ = session.Close()
	awaitProtocol(t, joined)
	_ = client.Close()
	awaitProtocol(t, done)
}

func TestSSHForwardPreservesHalfClose(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	targetResult := make(chan string, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			targetResult <- "accept failed"
			return
		}
		defer connection.Close()
		_, _ = io.WriteString(connection, "target half-close")
		_ = connection.(*net.TCPConn).CloseWrite()
		input, _ := io.ReadAll(connection)
		targetResult <- string(input)
	}()
	var dialed atomic.Bool
	client, done := protocolServer(t, protocolConfig(t), protocolRunner{dial: func(ctx context.Context, user, address string) (net.Conn, error) {
		if user != "worker" || address != listener.Addr().String() {
			t.Errorf("dial = %s %s", user, address)
		}
		dialed.Store(true)
		return (&net.Dialer{}).DialContext(ctx, "tcp", address)
	}})
	host, port, _ := net.SplitHostPort(listener.Addr().String())
	var number uint32
	for _, digit := range port {
		number = number*10 + uint32(digit-'0')
	}
	channel, requests, err := client.OpenChannel("direct-tcpip", ssh.Marshal(struct {
		Host       string
		Port       uint32
		Origin     string
		OriginPort uint32
	}{host, number, "127.0.0.1", 1234}))
	if err != nil {
		t.Fatal(err)
	}
	go ssh.DiscardRequests(requests)
	output, err := io.ReadAll(channel)
	if err != nil || string(output) != "target half-close" || !dialed.Load() {
		t.Fatalf("forward read = %q, %v", output, err)
	}
	if _, err := io.WriteString(channel, "after target EOF"); err != nil {
		t.Fatal(err)
	}
	_ = channel.CloseWrite()
	if input := awaitProtocol(t, targetResult); input != "after target EOF" {
		t.Fatalf("forward input = %q", input)
	}
	_ = channel.Close()
	_ = client.Close()
	awaitProtocol(t, done)
}

func TestSSHRevocationClosesAndJoins(t *testing.T) {
	config := protocolConfig(t)
	config.RecheckInterval = 10 * time.Millisecond
	var revoked atomic.Bool
	config.Authorize = func(_ context.Context, identity Identity, username string) (Decision, error) {
		if revoked.Load() {
			return Decision{}, ErrUnauthorized
		}
		return Decision{IdentityID: identity.IdentityID, PublicURLID: identity.PublicURLID, SSHUser: username, ValidUntil: time.Now().Add(time.Minute)}, nil
	}
	started, joined := make(chan struct{}), make(chan struct{})
	client, done := protocolServer(t, config, protocolRunner{run: func(ctx context.Context, _ Request, _ Streams) (int, error) {
		close(started)
		<-ctx.Done()
		close(joined)
		return 0, ctx.Err()
	}})
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Shell(); err != nil {
		t.Fatal(err)
	}
	awaitProtocol(t, started)
	revoked.Store(true)
	awaitProtocol(t, done)
	awaitProtocol(t, joined)
}
