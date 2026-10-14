package publisher

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io"
	"net"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/inspection"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestRedisForwardingRequiresVisitorTLS(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	received := make(chan int, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		_ = connection.SetReadDeadline(time.Now().Add(5 * time.Second))
		count, _ := connection.Read(make([]byte, 32))
		received <- count
	}()
	route, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "route.example", ServiceProtocol: controlv1.Redis, PublicPort: 6379,
		Target: listener.Addr().String(), Certificate: publicURLTestCertificate(t, "route.example"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })
	visitor := openDatabaseVisitor(t, route, 6379)
	if _, err := visitor.Write([]byte("*1\r\n$4\r\nPING\r\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := visitor.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("plaintext Redis visitor read = %v, want EOF", err)
	}
	if count := awaitPublisherTest(t, received); count != 0 {
		t.Fatalf("plaintext Redis visitor bytes reached private target: %d", count)
	}
}

func TestRedisForwardingVerifiesOptionalTargetTLS(t *testing.T) {
	privateCertificate := publicURLTestCertificate(t, "redis.internal")
	publicCertificate := publicURLTestCertificate(t, "route.example")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	backendResult := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			backendResult <- err
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
		secured := tls.Server(connection, &tls.Config{Certificates: []tls.Certificate{privateCertificate}, MinVersion: tls.VersionTLS12})
		if err := secured.Handshake(); err != nil {
			backendResult <- err
			return
		}
		var request [4]byte
		_, err = io.ReadFull(secured, request[:])
		if err == nil && string(request[:]) != "PING" {
			err = io.ErrUnexpectedEOF
		}
		if err == nil {
			_, err = secured.Write([]byte("PONG"))
		}
		backendResult <- err
	}()
	privateRoots := x509.NewCertPool()
	privateRoots.AddCert(privateCertificate.Leaf)
	route, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "route.example", ServiceProtocol: controlv1.Redis, PublicPort: 6379,
		Target: listener.Addr().String(), TargetTLS: true, TargetTLSName: "redis.internal",
		TargetOptions: localproxy.TargetOptions{RootCAs: privateRoots}, Certificate: publicCertificate,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })
	visitor := openDatabaseVisitor(t, route, 6379)
	secured := tls.Client(visitor, &tls.Config{ServerName: "route.example", RootCAs: rootsForCertificate(t, publicCertificate), MinVersion: tls.VersionTLS12})
	if err := secured.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := secured.Write([]byte("PING")); err != nil {
		t.Fatal(err)
	}
	var response [4]byte
	if _, err := io.ReadFull(secured, response[:]); err != nil || string(response[:]) != "PONG" {
		t.Fatalf("Redis TLS response = %q, %v", response, err)
	}
	if err := awaitPublisherTest(t, backendResult); err != nil {
		t.Fatal(err)
	}
}

func TestRedisForwardingRejectsWrongTargetCertificate(t *testing.T) {
	privateCertificate := publicURLTestCertificate(t, "wrong.internal")
	publicCertificate := publicURLTestCertificate(t, "route.example")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	backendResult := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			backendResult <- err
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
		secured := tls.Server(connection, &tls.Config{Certificates: []tls.Certificate{privateCertificate}, MinVersion: tls.VersionTLS12})
		backendResult <- secured.Handshake()
	}()
	privateRoots := x509.NewCertPool()
	privateRoots.AddCert(privateCertificate.Leaf)
	failed := make(chan struct{}, 1)
	route, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "route.example", ServiceProtocol: controlv1.Redis, PublicPort: 6379,
		Target: listener.Addr().String(), TargetTLS: true, TargetTLSName: "redis.internal",
		TargetOptions: localproxy.TargetOptions{RootCAs: privateRoots}, Certificate: publicCertificate,
		OnTargetFailure: func() { failed <- struct{}{} },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })
	visitor := openDatabaseVisitor(t, route, 6379)
	secured := tls.Client(visitor, &tls.Config{ServerName: "route.example", RootCAs: rootsForCertificate(t, publicCertificate), MinVersion: tls.VersionTLS12})
	if err := secured.Handshake(); err != nil {
		t.Fatal(err)
	}
	if count, err := secured.Read(make([]byte, 1)); err == nil || count != 0 {
		t.Fatalf("untrusted Redis target response = %d bytes, %v", count, err)
	}
	if err := awaitPublisherTest(t, backendResult); err == nil {
		t.Fatal("Redis target accepted the wrong certificate hostname")
	}
	awaitPublisherTest(t, failed)
}

func TestIntegrationRedisClient(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	if *testRedisAddress == "" {
		t.Skip("requires the Redis integration target")
	}
	certificate := publicURLTestCertificate(t, "route.example")
	observed := make(chan RedisObservation, 8)
	route, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "route.example", ServiceProtocol: controlv1.Redis, PublicPort: 6379,
		Target: *testRedisAddress, Certificate: certificate,
		ObserveRedis: func(event RedisObservation) { observed <- event },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })
	visitor := openDatabaseVisitor(t, route, 6379)
	secured := tls.Client(visitor, &tls.Config{ServerName: "route.example", RootCAs: rootsForCertificate(t, certificate), MinVersion: tls.VersionTLS12})
	if err := secured.Handshake(); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(secured)
	redisCommand(t, secured, reader, "*1\r\n$4\r\nPING\r\n", "-NOAUTH Authentication required.\r\n")
	redisCommand(t, secured, reader, "*2\r\n$4\r\nAUTH\r\n$8\r\ntestpass\r\n", "+OK\r\n")
	redisCommand(t, secured, reader, "*3\r\n$3\r\nSET\r\n$3\r\ntnl\r\n$2\r\nok\r\n", "+OK\r\n")
	redisCommand(t, secured, reader, "*2\r\n$3\r\nGET\r\n$3\r\ntnl\r\n", "$2\r\n")
	response, err := reader.ReadString('\n')
	if err != nil || response != "ok\r\n" {
		t.Fatalf("Redis GET = %q, %v", response, err)
	}
	for _, expected := range []struct {
		command string
		result  inspection.Result
	}{
		{"PING", inspection.ResultError}, {"AUTH", inspection.ResultOK},
		{"SET", inspection.ResultOK}, {"GET", inspection.ResultOK},
	} {
		event := nextRedisObservation(t, observed)
		if event.Command != expected.command || event.Result != expected.result || event.ReceivedAt.IsZero() || event.Duration < 0 {
			t.Fatalf("Redis result = %#v, want %#v", event, expected)
		}
	}
}

var testRedisAddress = flag.String("tnl-test-redis-address", "", "disposable Redis server host and port")

func redisCommand(t *testing.T, connection net.Conn, reader *bufio.Reader, command, expected string) {
	t.Helper()
	if _, err := io.WriteString(connection, command); err != nil {
		t.Fatal(err)
	}
	response, err := reader.ReadString('\n')
	if err != nil || response != expected {
		t.Fatalf("Redis response = %q, %v; want %q", response, err, expected)
	}
}
