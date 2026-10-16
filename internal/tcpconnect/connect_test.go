package tcpconnect

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"
)

func TestListenOnlyBindsLoopback(t *testing.T) {
	for _, address := range []string{"0.0.0.0:1234", "[::]:1234", "localhost:1234", "127.0.0.1:65536", "127.0.0.1:-1", "127.0.0.1:01", "192.0.2.1:1234"} {
		if listener, err := Listen(address); err == nil {
			listener.Close()
			t.Fatalf("accepted nonloopback or invalid address %q", address)
		}
	}
	listener, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener.Close()
}

func TestConnectRequiresLoopbackTCPPeer(t *testing.T) {
	options, _ := fixture(t)
	left, right := net.Pipe()
	defer right.Close()
	if err := Connect(t.Context(), options, left); !errors.Is(err, ErrInvalidConnection) {
		t.Fatalf("non-TCP local peer accepted: %v", err)
	}
}

func fixture(t *testing.T) (Options, net.Listener) {
	return fixtureWithServerName(t, "localhost")
}

func fixtureWithServerName(t *testing.T, serverName string) (Options, net.Listener) {
	t.Helper()
	rootPublic, rootPrivate, _ := ed25519.GenerateKey(rand.Reader)
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture root"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, rootPublic, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	makeCert := func(serial int64, client bool) tls.Certificate {
		public, private, _ := ed25519.GenerateKey(rand.Reader)
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		if client {
			leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			leaf.URIs = []*url.URL{{Scheme: "tnl", Host: "visitor", Path: "/url_0123456789abcdefghijkl/ident_0123456789abcdefghijkl"}}
		} else {
			leaf.DNSNames = []string{serverName}
			leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		}
		der, err := x509.CreateCertificate(rand.Reader, leaf, root, public, rootPrivate)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der, rootDER}, PrivateKey: private, Leaf: parsed}
	}
	server := makeCert(2, false)
	client := makeCert(3, true)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{server}, ClientAuth: tls.RequireAnyClientCert, NextProtos: []string{"tnl-tcp-test"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return Options{PublicURLID: "url_0123456789abcdefghijkl", Hostname: "localhost", Port: listener.Addr().(*net.TCPAddr).Port, Certificate: client, RootCAs: roots, ALPN: "tnl-tcp-test"}, listener
}

func localPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	return server, client
}

func TestConnectVerifiesScopeTLSAndHalfClose(t *testing.T) {
	options, server := fixture(t)
	for _, change := range []func(*Options){
		func(o *Options) { o.PublicURLID = "url_abcdefghijkl0123456789" },
		func(o *Options) { o.Hostname = "-invalid" },
		func(o *Options) { o.Port = 65536 },
	} {
		invalid := options
		change(&invalid)
		left, right := localPair(t)
		if err := Connect(t.Context(), invalid, left); !errors.Is(err, ErrInvalidConnection) {
			t.Fatalf("invalid connection accepted: %v", err)
		}
		right.Close()
	}
	local, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	done := make(chan error, 1)
	go func() {
		peer, err := server.Accept()
		if err != nil {
			done <- err
			return
		}
		defer peer.Close()
		conn := peer.(*tls.Conn)
		if err := conn.Handshake(); err != nil {
			done <- err
			return
		}
		if conn.ConnectionState().NegotiatedProtocol != options.ALPN || len(conn.ConnectionState().PeerCertificates) == 0 {
			done <- ErrInvalidConnection
			return
		}
		data, err := io.ReadAll(io.LimitReader(conn, 4096))
		if err != nil || string(data) != "request" {
			done <- ErrInvalidConnection
			return
		}
		_, err = conn.Write([]byte("reply:" + string(data)))
		if err == nil {
			err = conn.CloseWrite()
		}
		done <- err
	}()
	forward := make(chan error, 1)
	go func() {
		peer, err := local.Accept()
		if err != nil {
			forward <- err
			return
		}
		forward <- Connect(t.Context(), options, peer)
	}()
	client, err := net.Dial("tcp", local.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := io.WriteString(client, "request"); err != nil {
		t.Fatal(err)
	}
	if err := client.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(client)
	if err != nil || !bytes.Equal(response, []byte("reply:request")) {
		t.Fatalf("reply: %q %v", response, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := <-forward; err != nil {
		t.Fatal(err)
	}
}

func TestConnectRejectsWrongWebPKINameAndALPN(t *testing.T) {
	for _, wrongName := range []bool{false, true} {
		name := "localhost"
		if wrongName {
			name = "other.example.test"
		}
		options, server := fixtureWithServerName(t, name)
		if !wrongName {
			options.ALPN = "wrong"
		}
		left, right := localPair(t)
		done := make(chan error, 1)
		go func() {
			conn, err := server.Accept()
			if err != nil {
				done <- err
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			done <- conn.(*tls.Conn).Handshake()
		}()
		if err := Connect(t.Context(), options, left); err == nil {
			t.Fatalf("wrong WebPKI name or ALPN accepted (wrong name: %t)", wrongName)
		}
		right.Close()
		<-done
	}
}

func TestConnectCancellationClosesBothStreams(t *testing.T) {
	options, server := fixture(t)
	connected := make(chan struct{})
	remoteDone := make(chan struct{})
	go func() {
		defer close(remoteDone)
		conn, err := server.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		if conn.(*tls.Conn).Handshake() != nil {
			return
		}
		close(connected)
		_, _ = io.Copy(io.Discard, conn)
	}()
	left, right := localPair(t)
	defer right.Close()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- Connect(ctx, options, left) }()
	select {
	case <-connected:
	case <-time.After(3 * time.Second):
		t.Fatal("TLS handshake did not complete")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("connector did not join the copy workers")
	}
	select {
	case <-remoteDone:
	case <-time.After(3 * time.Second):
		t.Fatal("remote stream remained open")
	}
}
