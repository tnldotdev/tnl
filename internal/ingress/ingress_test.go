package ingress

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/proxyproto"
	"github.com/tnldotdev/tnl/internal/worker"
)

func TestIngressRoutesTLSWithProxyMetadata(t *testing.T) {
	certificate := testCertificate(t, "route.example")
	backend := &tlsBackend{certificate: certificate, result: make(chan backendResult, 1)}
	usage := &testUsageConnection{closed: make(chan struct{})}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(listener, Config{
		Lookup: func(hostname string) (Route, bool) {
			return Route{ID: "route_test", Generation: 1, Backend: backend}, hostname == "route.example"
		},
		OpenUsage: func(routeID string, generation uint64, at time.Time) UsageConnection {
			usage.routeID = routeID
			usage.generation = generation
			usage.openedAt = at
			return usage
		},
		MaxConnections:      8,
		MaxRouteConnections: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- server.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Drain(ctx)
		<-served
	})

	client, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
		ServerName:         "route.example",
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // The test certificate is self-signed.
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != "pong" {
		t.Fatalf("response = %q", response)
	}
	_ = client.Close()

	result := <-backend.result
	if result.err != nil {
		t.Fatal(result.err)
	}
	if result.request != "ping" || !result.header.Source.Addr().IsLoopback() || !result.header.Destination.Addr().IsLoopback() {
		t.Fatalf("backend result = %#v", result)
	}
	select {
	case <-usage.closed:
	case <-time.After(time.Second):
		t.Fatal("usage connection did not close")
	}
	usage.mu.Lock()
	defer usage.mu.Unlock()
	if usage.routeID != "route_test" || usage.generation != 1 || usage.openedAt.IsZero() || usage.closedAt.IsZero() {
		t.Fatalf("usage identity = %#v", usage)
	}
	if usage.ingressBytes <= 0 || usage.egressBytes <= 0 {
		t.Fatalf("usage bytes = %d ingress, %d egress", usage.ingressBytes, usage.egressBytes)
	}
}

func TestIngressUsesProvisioningRouteOnlyForACMETLSALPN(t *testing.T) {
	backend := &tlsBackend{
		certificate: testCertificate(t, "route.example"), result: make(chan backendResult, 1),
		nextProtos: []string{"acme-tls/1"},
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var usageOpened atomic.Bool
	server, err := New(listener, Config{
		Lookup: func(string) (Route, bool) { return Route{}, false },
		LookupChallenge: func(hostname string) (worker.RouteBackend, bool) {
			return backend, hostname == "route.example"
		},
		OpenUsage: func(string, uint64, time.Time) UsageConnection {
			usageOpened.Store(true)
			return &testUsageConnection{closed: make(chan struct{})}
		},
		MaxConnections: 8, MaxRouteConnections: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- server.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Drain(ctx)
		<-served
	})

	client, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
		ServerName: "route.example", NextProtos: []string{"acme-tls/1"}, MinVersion: tls.VersionTLS12,
		InsecureSkipVerify: true, // The test certificate is self-signed.
	})
	if err != nil {
		t.Fatal(err)
	}
	if client.ConnectionState().NegotiatedProtocol != "acme-tls/1" {
		t.Fatalf("negotiated ALPN = %q", client.ConnectionState().NegotiatedProtocol)
	}
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	if result := <-backend.result; result.err != nil {
		t.Fatal(result.err)
	}
	if usageOpened.Load() {
		t.Fatal("ACME challenge opened usage accounting")
	}
}

func TestIngressHandsControlTLSOffByExactSNI(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	connections := make(chan net.Conn)
	controlCertificate := testCertificate(t, "control.example")
	server, err := New(listener, Config{
		Lookup:         func(string) (Route, bool) { return Route{}, false },
		ServerHostname: "control.example",
		HandleControl: func(connection net.Conn) bool {
			connections <- connection
			return true
		},
		MaxConnections: 8, MaxRouteConnections: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- server.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Drain(ctx)
		<-served
	})

	controlResult := make(chan error, 1)
	go func() {
		connection := <-connections
		defer connection.Close()
		secured := tls.Server(connection, &tls.Config{
			Certificates: []tls.Certificate{controlCertificate}, MinVersion: tls.VersionTLS12,
		})
		if err := secured.Handshake(); err != nil {
			controlResult <- err
			return
		}
		request := make([]byte, 4)
		if _, err := io.ReadFull(secured, request); err != nil {
			controlResult <- err
			return
		}
		if string(request) != "ping" || !connection.RemoteAddr().(*net.TCPAddr).IP.IsLoopback() {
			controlResult <- errors.New("unexpected control connection")
			return
		}
		_, err := secured.Write([]byte("pong"))
		controlResult <- err
	}()

	client, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
		ServerName: "control.example", MinVersion: tls.VersionTLS12,
		InsecureSkipVerify: true, // The test certificate is self-signed.
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	if string(response) != "pong" {
		t.Fatalf("response = %q", response)
	}
	if err := <-controlResult; err != nil {
		t.Fatal(err)
	}
}

func TestDrainDeadlineForcesBackendClosed(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	backend := &holdingBackend{opened: make(chan struct{}), closed: make(chan struct{})}
	server, err := New(listener, Config{
		Lookup: func(string) (Route, bool) {
			return Route{ID: "route_test", Generation: 1, Backend: backend}, true
		},
		MaxConnections: 2, MaxRouteConnections: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- server.Serve() }()
	connection, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client := tls.Client(connection, &tls.Config{
		ServerName: "route.example", MinVersion: tls.VersionTLS12,
		InsecureSkipVerify: true, // The backend intentionally never completes TLS.
	})
	handshake := make(chan error, 1)
	go func() { handshake <- client.Handshake() }()
	select {
	case <-backend.opened:
	case <-time.After(time.Second):
		t.Fatal("backend did not open")
	}
	drainCtx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err = server.Drain(drainCtx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Drain error = %v, want deadline exceeded", err)
	}
	select {
	case <-backend.closed:
	case <-time.After(time.Second):
		t.Fatal("backend was not force-closed")
	}
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	<-handshake
}

func TestAdmissionRegistersBeforeDrainWait(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server, err := New(listener, Config{
		Lookup:         func(string) (Route, bool) { return Route{}, false },
		MaxConnections: 1, MaxRouteConnections: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	connection, peer := net.Pipe()
	defer peer.Close()
	if !server.admit(connection) {
		t.Fatal("connection was not admitted")
	}
	waited := make(chan struct{})
	go func() {
		server.active.Wait()
		close(waited)
	}()
	select {
	case <-waited:
		t.Fatal("wait completed before the admitted handler")
	case <-time.After(20 * time.Millisecond):
	}
	server.release(connection)
	server.active.Done()
	select {
	case <-waited:
	case <-time.After(time.Second):
		t.Fatal("wait did not complete after the handler")
	}
}

type tlsBackend struct {
	certificate tls.Certificate
	result      chan backendResult
	nextProtos  []string
}

type holdingBackend struct {
	opened chan struct{}
	closed chan struct{}
}

type testUsageConnection struct {
	mu           sync.Mutex
	routeID      string
	generation   uint64
	openedAt     time.Time
	closedAt     time.Time
	ingressBytes int64
	egressBytes  int64
	closed       chan struct{}
}

func (u *testUsageConnection) AddIngress(bytes int64, _ time.Time) {
	u.mu.Lock()
	u.ingressBytes += bytes
	u.mu.Unlock()
}

func (u *testUsageConnection) AddEgress(bytes int64, _ time.Time) {
	u.mu.Lock()
	u.egressBytes += bytes
	u.mu.Unlock()
}

func (u *testUsageConnection) Close(at time.Time) {
	u.mu.Lock()
	u.closedAt = at
	u.mu.Unlock()
	close(u.closed)
}

func (b *holdingBackend) Open(context.Context) (net.Conn, error) {
	ingress, peer := net.Pipe()
	go func() {
		defer close(b.closed)
		defer peer.Close()
		_, replay, err := proxyproto.Decode(peer)
		if err != nil {
			return
		}
		// Decoding the header proves the server has tracked the backend.
		close(b.opened)
		_, _ = io.Copy(io.Discard, replay)
	}()
	return ingress, nil
}

type backendResult struct {
	header  proxyproto.Header
	request string
	err     error
}

func (b *tlsBackend) Open(context.Context) (net.Conn, error) {
	ingress, agent := net.Pipe()
	go func() {
		defer agent.Close()
		header, replay, err := proxyproto.Decode(agent)
		if err != nil {
			b.result <- backendResult{err: err}
			return
		}
		server := tls.Server(&testReaderConn{Conn: agent, reader: replay}, &tls.Config{
			Certificates: []tls.Certificate{b.certificate},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   b.nextProtos,
		})
		if err := server.Handshake(); err != nil {
			b.result <- backendResult{err: err}
			return
		}
		request := make([]byte, 4)
		if _, err = io.ReadFull(server, request); err == nil {
			_, err = server.Write([]byte("pong"))
		}
		b.result <- backendResult{header: header, request: string(request), err: err}
	}()
	return ingress, nil
}

type testReaderConn struct {
	net.Conn
	reader io.Reader
}

func (c *testReaderConn) Read(destination []byte) (int, error) { return c.reader.Read(destination) }

func testCertificate(t *testing.T, hostname string) tls.Certificate {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: hostname},
		DNSNames:     []string{hostname},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}
}
