package publisher

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/proxyproto"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestDatabaseForwardingRequiresVisitorAndTargetTLS(t *testing.T) {
	for _, protocol := range []controlv1.PublicURLServiceProtocol{controlv1.Postgres, controlv1.Mysql} {
		t.Run(string(protocol), func(t *testing.T) {
			visitorCertificate := publicURLTestCertificate(t, "route.example")
			backendCertificate := publicURLTestCertificate(t, "db.internal")
			backendRoots := x509.NewCertPool()
			backendRoots.AddCert(backendCertificate.Leaf)
			visitorRoots := x509.NewCertPool()
			visitorRoots.AddCert(visitorCertificate.Leaf)
			port := uint16(5432)
			if protocol == controlv1.Mysql {
				port = 3306
			}
			address, received := startDatabaseTarget(t, protocol, backendCertificate)
			route, err := NewPublicURLServer(PublicURLServerConfig{
				Hostname: "route.example", ServiceProtocol: protocol, PublicPort: port,
				Target: address, TargetTLSName: "db.internal", TargetOptions: localproxy.TargetOptions{RootCAs: backendRoots},
				Certificate: visitorCertificate,
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = route.Close() })
			visitor := openDatabaseVisitor(t, route, port)
			if protocol == controlv1.Postgres {
				if _, err := visitor.Write(postgresGSSRequest[:]); err != nil {
					t.Fatal(err)
				}
				readDatabaseByte(t, visitor, 'N')
				if _, err := visitor.Write(postgresSSLRequest[:]); err != nil {
					t.Fatal(err)
				}
				readDatabaseByte(t, visitor, 'S')
			} else {
				greeting := readDatabasePacket(t, visitor, 8)
				if string(greeting) != "greeting" {
					t.Fatalf("mysql greeting = %q", greeting)
				}
				if _, err := visitor.Write(mysqlTestSSLRequest()); err != nil {
					t.Fatal(err)
				}
			}
			secured := tls.Client(visitor, &tls.Config{ServerName: "route.example", RootCAs: visitorRoots, MinVersion: tls.VersionTLS12})
			if err := secured.Handshake(); err != nil {
				t.Fatal(err)
			}
			if _, err := secured.Write([]byte("startup!")); err != nil {
				t.Fatal(err)
			}
			var response [5]byte
			if _, err := io.ReadFull(secured, response[:]); err != nil || string(response[:]) != "ready" {
				t.Fatalf("database response = %q, %v", response, err)
			}
			if got := awaitPublisherTest(t, received); got != "startup!" {
				t.Fatalf("private target received %q", got)
			}
			_ = secured.Close()
		})
	}
}

func TestDatabaseTLSPassthroughKeepsTargetCertificate(t *testing.T) {
	for _, protocol := range []controlv1.PublicURLServiceProtocol{controlv1.Postgres, controlv1.Mysql} {
		t.Run(string(protocol), func(t *testing.T) {
			backendCertificate := publicURLTestCertificate(t, "route.example")
			visitorCertificate := publicURLTestCertificate(t, "route.example")
			roots := x509.NewCertPool()
			roots.AddCert(backendCertificate.Leaf)
			port := uint16(5432)
			if protocol == controlv1.Mysql {
				port = 3306
			}
			address, received := startDatabaseTarget(t, protocol, backendCertificate)
			route, err := NewPublicURLServer(PublicURLServerConfig{
				Hostname: "route.example", ServiceProtocol: protocol, PublicPort: port,
				Target: address, DatabaseTLSPassthrough: true, Certificate: visitorCertificate,
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = route.Close() })
			visitor := openDatabaseVisitor(t, route, port)
			if protocol == controlv1.Postgres {
				if _, err := visitor.Write(postgresSSLRequest[:]); err != nil {
					t.Fatal(err)
				}
				readDatabaseByte(t, visitor, 'S')
			} else {
				if greeting := readDatabasePacket(t, visitor, 8); greeting != "greeting" {
					t.Fatalf("mysql greeting = %q", greeting)
				}
				if _, err := visitor.Write(mysqlTestSSLRequest()); err != nil {
					t.Fatal(err)
				}
			}
			secured := tls.Client(visitor, &tls.Config{ServerName: "route.example", RootCAs: roots, MinVersion: tls.VersionTLS12})
			if err := secured.Handshake(); err != nil {
				t.Fatal(err)
			}
			if _, err := secured.Write([]byte("startup!")); err != nil {
				t.Fatal(err)
			}
			var response [5]byte
			if _, err := io.ReadFull(secured, response[:]); err != nil || string(response[:]) != "ready" {
				t.Fatalf("passthrough response = %q, %v", response, err)
			}
			if got := awaitPublisherTest(t, received); got != "startup!" {
				t.Fatalf("private target received %q", got)
			}
			_ = secured.Close()
		})
	}
}

func TestPostgresDatabaseForwardingRejectsPlaintext(t *testing.T) {
	visitorCertificate := publicURLTestCertificate(t, "route.example")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	forwarded := make(chan int, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			forwarded <- -1
			return
		}
		defer connection.Close()
		_ = connection.SetReadDeadline(time.Now().Add(5 * time.Second))
		count, _ := connection.Read(make([]byte, 8))
		forwarded <- count
	}()
	route, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "route.example", ServiceProtocol: controlv1.Postgres, PublicPort: 5432,
		Target: listener.Addr().String(), Certificate: visitorCertificate,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })
	visitor := openDatabaseVisitor(t, route, 5432)
	if _, err := visitor.Write([]byte{0, 0, 0, 8, 0, 3, 0, 0}); err != nil {
		t.Fatal(err)
	}
	if _, err := visitor.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("plaintext startup read = %v, want EOF", err)
	}
	if count := awaitPublisherTest(t, forwarded); count != 0 {
		t.Fatalf("plaintext visitor bytes reached the target: %d", count)
	}
}

func TestDatabaseForwardingRejectsWrongTargetCertificate(t *testing.T) {
	for _, protocol := range []controlv1.PublicURLServiceProtocol{controlv1.Postgres, controlv1.Mysql} {
		t.Run(string(protocol), func(t *testing.T) {
			wrongCertificate := publicURLTestCertificate(t, "wrong.internal")
			roots := x509.NewCertPool()
			roots.AddCert(wrongCertificate.Leaf)
			port := uint16(5432)
			if protocol == controlv1.Mysql {
				port = 3306
			}
			address, received := startDatabaseTarget(t, protocol, wrongCertificate, true)
			route, err := NewPublicURLServer(PublicURLServerConfig{
				Hostname: "route.example", ServiceProtocol: protocol, PublicPort: port,
				Target: address, TargetTLSName: "db.internal", TargetOptions: localproxy.TargetOptions{RootCAs: roots},
				Certificate: publicURLTestCertificate(t, "route.example"),
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = route.Close() })
			visitor := openDatabaseVisitor(t, route, port)
			if protocol == controlv1.Postgres {
				if _, err := visitor.Write(postgresSSLRequest[:]); err != nil {
					t.Fatal(err)
				}
			} else {
				_ = readDatabasePacket(t, visitor, 8)
				if _, err := visitor.Write(mysqlTestSSLRequest()); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := visitor.Read(make([]byte, 1)); err != io.EOF {
				t.Fatalf("untrusted target visitor read = %v, want EOF", err)
			}
			if got := awaitPublisherTest(t, received); got != "tls_rejected" {
				t.Fatalf("target handshake result = %q", got)
			}
		})
	}
}

func TestDatabasePassthroughRejectsWrongSNIWithoutSendingClientHello(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	forwarded := make(chan int, 1)
	go func() {
		backend, err := listener.Accept()
		if err != nil {
			forwarded <- -1
			return
		}
		defer backend.Close()
		_ = backend.SetDeadline(time.Now().Add(5 * time.Second))
		var request [8]byte
		if _, err := io.ReadFull(backend, request[:]); err != nil || request != postgresSSLRequest {
			forwarded <- -1
			return
		}
		if _, err := backend.Write([]byte{'S'}); err != nil {
			forwarded <- -1
			return
		}
		count, _ := backend.Read(make([]byte, 1))
		forwarded <- count
	}()
	route, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "route.example", ServiceProtocol: controlv1.Postgres, PublicPort: 5432,
		Target: listener.Addr().String(), DatabaseTLSPassthrough: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })
	visitor := openDatabaseVisitor(t, route, 5432)
	if _, err := visitor.Write(postgresSSLRequest[:]); err != nil {
		t.Fatal(err)
	}
	readDatabaseByte(t, visitor, 'S')
	secured := tls.Client(visitor, &tls.Config{ServerName: "other.example", MinVersion: tls.VersionTLS12})
	if err := secured.Handshake(); err == nil {
		t.Fatal("passthrough accepted the wrong public URL SNI")
	}
	if count := awaitPublisherTest(t, forwarded); count != 0 {
		t.Fatalf("unrecognized ClientHello reached the database: %d bytes", count)
	}
}

func startDatabaseTarget(t *testing.T, protocol controlv1.PublicURLServiceProtocol, certificate tls.Certificate, rejectTLS ...bool) (string, <-chan string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	received := make(chan string, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
		if protocol == controlv1.Postgres {
			var request [8]byte
			if _, err := io.ReadFull(connection, request[:]); err != nil || request != postgresSSLRequest {
				t.Errorf("target SSLRequest = %x, %v", request, err)
				return
			}
			if _, err := connection.Write([]byte{'S'}); err != nil {
				t.Error(err)
				return
			}
		} else {
			if _, err := connection.Write(mysqlTestPacket(0, []byte("greeting"))); err != nil {
				t.Error(err)
				return
			}
			request := make([]byte, 36)
			if _, err := io.ReadFull(connection, request); err != nil || string(request) != string(mysqlTestSSLRequest()) {
				t.Errorf("target MySQL SSLRequest = %x, %v", request, err)
				return
			}
		}
		secured := tls.Server(connection, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
		if err := secured.Handshake(); err != nil {
			if len(rejectTLS) != 0 && rejectTLS[0] {
				received <- "tls_rejected"
				return
			}
			t.Error(err)
			return
		}
		if len(rejectTLS) != 0 && rejectTLS[0] {
			t.Error("publisher accepted a mismatched private target certificate")
			return
		}
		var startup [8]byte
		if _, err := io.ReadFull(secured, startup[:]); err != nil {
			t.Error(err)
			return
		}
		received <- string(startup[:])
		if _, err := secured.Write([]byte("ready")); err != nil {
			t.Error(err)
		}
	}()
	return listener.Addr().String(), received
}

func openDatabaseVisitor(t *testing.T, route *PublicURLServer, port uint16) net.Conn {
	t.Helper()
	visitor, publisher := net.Pipe()
	t.Cleanup(func() { _ = visitor.Close(); _ = publisher.Close() })
	_ = visitor.SetDeadline(time.Now().Add(5 * time.Second))
	done := make(chan struct{})
	go func() { route.handleVisitor(publisher, false); close(done) }()
	t.Cleanup(func() { _ = visitor.Close(); awaitPublisherTest(t, done) })
	header, err := proxyproto.Encode(proxyproto.Header{
		Source:      netip.MustParseAddrPort("192.0.2.10:40001"),
		Destination: netip.AddrPortFrom(netip.MustParseAddr("203.0.113.10"), port),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := visitor.Write(header); err != nil {
		t.Fatal(err)
	}
	return visitor
}

func readDatabaseByte(t *testing.T, visitor net.Conn, expected byte) {
	t.Helper()
	var received [1]byte
	if _, err := io.ReadFull(visitor, received[:]); err != nil || received[0] != expected {
		t.Fatalf("negotiation response = %q, %v", received, err)
	}
}

func readDatabasePacket(t *testing.T, connection net.Conn, length int) string {
	t.Helper()
	packet := make([]byte, length+4)
	if _, err := io.ReadFull(connection, packet); err != nil {
		t.Fatal(err)
	}
	return string(packet[4:])
}

func mysqlTestSSLRequest() []byte {
	payload := make([]byte, 32)
	binary.LittleEndian.PutUint32(payload, mysqlClientSSL)
	return mysqlTestPacket(1, payload)
}

func mysqlTestPacket(sequence byte, payload []byte) []byte {
	packet := make([]byte, len(payload)+4)
	packet[0], packet[1], packet[2], packet[3] = byte(len(payload)), byte(len(payload)>>8), byte(len(payload)>>16), sequence
	copy(packet[4:], payload)
	return packet
}
