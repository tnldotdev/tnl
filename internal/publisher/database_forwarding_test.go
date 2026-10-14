package publisher

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	projectconfig "github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/proxyproto"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestMySQLPublicPortSelectsCertificateWithoutVisitorSNI(t *testing.T) {
	certificate := publicURLTestCertificate(t, "route.example")
	route, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "route.example", ServiceProtocol: controlv1.Mysql, PublicPort: 3306,
		Target: "127.0.0.1:3306", Certificate: certificate,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer route.Close()
	for _, name := range []string{"", "route.example"} {
		selected, err := route.getCertificate(&tls.ClientHelloInfo{ServerName: name})
		if err != nil || selected == nil || !bytes.Equal(selected.Certificate[0], certificate.Certificate[0]) {
			t.Fatalf("MySQL certificate for SNI %q = %#v, %v", name, selected, err)
		}
	}
	if _, err := route.getCertificate(&tls.ClientHelloInfo{ServerName: "other.example"}); err == nil {
		t.Fatal("accepted a MySQL visitor with mismatched SNI")
	}
	httpRoute, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "route.example", Handler: http.NotFoundHandler(), Certificate: certificate,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer httpRoute.Close()
	if _, err := httpRoute.getCertificate(&tls.ClientHelloInfo{}); err == nil {
		t.Fatal("accepted an HTTP visitor without SNI")
	}
}

func TestPostgresPlaintextCancelIsReportedWithoutForwarding(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	received := make(chan []byte, 1)
	go func() {
		connection, err := target.Accept()
		if err != nil {
			received <- nil
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
		data, _ := io.ReadAll(connection)
		received <- data
	}()
	warning := make(chan struct{}, 1)
	route, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "route.example", ServiceProtocol: controlv1.Postgres, PublicPort: 5432,
		Target: target.Addr().String(), Certificate: publicURLTestCertificate(t, "route.example"),
		OnCancelUnsupported: func() { warning <- struct{}{} },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer route.Close()
	visitor := openDatabaseVisitor(t, route, 5432)
	request := append(postgresCancelRequest[:], make([]byte, 8)...)
	if _, err := visitor.Write(request); err != nil {
		t.Fatal(err)
	}
	select {
	case <-warning:
	case <-time.After(2 * time.Second):
		t.Fatal("cancel request did not trigger a publisher warning")
	}
	select {
	case data := <-received:
		if len(data) != 0 {
			t.Fatalf("plaintext cancel bytes reached the target: %x", data)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("target connection did not close")
	}
}

func TestMySQLInspectionWaitsForVerifiedTargetAuthentication(t *testing.T) {
	visitorCertificate := publicURLTestCertificate(t, "route.example")
	backendCertificate := publicURLTestCertificate(t, "db.internal")
	backendRoots := x509.NewCertPool()
	backendRoots.AddCert(backendCertificate.Leaf)
	visitorRoots := x509.NewCertPool()
	visitorRoots.AddCert(visitorCertificate.Leaf)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	backendDone := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			backendDone <- err
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := connection.Write(mysqlTestPacket(0, []byte("greeting"))); err != nil {
			backendDone <- err
			return
		}
		ssl := make([]byte, 36)
		if _, err := io.ReadFull(connection, ssl); err != nil {
			backendDone <- err
			return
		}
		secured := tls.Server(connection, &tls.Config{Certificates: []tls.Certificate{backendCertificate}, MinVersion: tls.VersionTLS12})
		if err := secured.Handshake(); err != nil {
			backendDone <- err
			return
		}
		if login, err := readMySQLPacket(secured, 64); err != nil || login[3] != 2 ||
			binary.LittleEndian.Uint32(login[4:8])&mysqlClientSSL == 0 {
			backendDone <- fmt.Errorf("private login packet = %x, %v", login, err)
			return
		}
		if _, err := secured.Write(mysqlTestPacket(3, []byte{0, 0, 0, 0, 0, 0, 0})); err != nil {
			backendDone <- err
			return
		}
		query, err := readMySQLPacket(secured, 64)
		if err != nil || query[3] != 0 || string(query[4:]) != "\x03SELECT 1" {
			backendDone <- fmt.Errorf("private query packet = %x, %v", query, err)
			return
		}
		_, err = secured.Write(mysqlTestPacket(1, []byte{0, 0, 0, 0, 0, 0, 0}))
		backendDone <- err
	}()
	observed := make(chan DatabaseObservation, 1)
	route, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "route.example", ServiceProtocol: controlv1.Mysql, PublicPort: 3306,
		Target: listener.Addr().String(), TargetTLS: true, TargetTLSName: "db.internal",
		TargetOptions: localproxy.TargetOptions{RootCAs: backendRoots}, Certificate: visitorCertificate,
		InspectionMode:  projectconfig.InspectionDetailed,
		ObserveDatabase: func(value DatabaseObservation) { observed <- value },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })
	visitor := openDatabaseVisitor(t, route, 3306)
	if got := readDatabasePacket(t, visitor, 8); got != "greeting" {
		t.Fatalf("target greeting = %q", got)
	}
	if _, err := visitor.Write(mysqlTestSSLRequest()); err != nil {
		t.Fatal(err)
	}
	secured := tls.Client(visitor, &tls.Config{ServerName: "route.example", RootCAs: visitorRoots, MinVersion: tls.VersionTLS12})
	if err := secured.Handshake(); err != nil {
		t.Fatal(err)
	}
	login := make([]byte, 32)
	binary.LittleEndian.PutUint32(login, mysqlClientSSL|mysqlClientDeprecateEOF)
	if _, err := secured.Write(mysqlTestPacket(2, login)); err != nil {
		t.Fatal(err)
	}
	if got := readDatabasePacket(t, secured, 7); len(got) != 7 || got[0] != 0 {
		t.Fatalf("authentication response = %x", got)
	}
	if _, err := secured.Write(mysqlTestPacket(0, []byte("\x03SELECT 1"))); err != nil {
		t.Fatal(err)
	}
	if got := readDatabasePacket(t, secured, 7); len(got) != 7 || got[0] != 0 {
		t.Fatalf("query response = %x", got)
	}
	select {
	case value := <-observed:
		if value.Operation != "query" || value.Statement != "SELECT 1" || value.Result != "ok" {
			t.Fatalf("verified target inspection = %#v", value)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("authenticated query was not inspected")
	}
	if err := <-backendDone; err != nil {
		t.Fatal(err)
	}
}

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
				Target: address, TargetTLS: true, TargetTLSName: "db.internal", TargetOptions: localproxy.TargetOptions{RootCAs: backendRoots},
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
				Target: address, TargetTLS: true, TargetTLSName: "db.internal", TargetOptions: localproxy.TargetOptions{RootCAs: roots},
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

func TestDatabaseVisitorCountsTowardApplicationLimits(t *testing.T) {
	publicCertificate := publicURLTestCertificate(t, "route.example")
	backendCertificate := publicURLTestCertificate(t, "db.internal")
	backendRoots := x509.NewCertPool()
	backendRoots.AddCert(backendCertificate.Leaf)
	address, received := startDatabaseTarget(t, controlv1.Postgres, backendCertificate)
	route, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "route.example", ServiceProtocol: controlv1.Postgres, PublicPort: 5432,
		Target: address, TargetTLS: true, TargetTLSName: "db.internal", TargetOptions: localproxy.TargetOptions{RootCAs: backendRoots},
		Certificate: publicCertificate, Limits: ApplicationLimits{Requests: 1},
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
	visitorRoots := x509.NewCertPool()
	visitorRoots.AddCert(publicCertificate.Leaf)
	secured := tls.Client(visitor, &tls.Config{ServerName: "route.example", MinVersion: tls.VersionTLS12,
		RootCAs: visitorRoots})
	if err := secured.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := secured.Write([]byte("startup!")); err != nil {
		t.Fatal(err)
	}
	var response [5]byte
	if _, err := io.ReadFull(secured, response[:]); err != nil || string(response[:]) != "ready" {
		t.Fatalf("first database response = %q, %v", response, err)
	}
	if got := awaitPublisherTest(t, received); got != "startup!" {
		t.Fatalf("first database request = %q", got)
	}
	_ = secured.Close()
	select {
	case <-route.admission.completed:
	case <-time.After(5 * time.Second):
		t.Fatal("database connection did not complete its request budget")
	}
	second := openDatabaseVisitor(t, route, 5432)
	if _, err := second.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("over-budget database connection = %v, want EOF", err)
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
	visitor, err := dialDatabaseVisitor(t, route, port)
	if err != nil {
		t.Fatal(err)
	}
	return visitor
}

func dialDatabaseVisitor(t *testing.T, route *PublicURLServer, port uint16) (net.Conn, error) {
	t.Helper()
	visitor, publisher := net.Pipe()
	t.Cleanup(func() { _ = visitor.Close(); _ = publisher.Close() })
	if err := visitor.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return nil, err
	}
	done := make(chan struct{})
	go func() { route.handleVisitor(publisher, false); close(done) }()
	t.Cleanup(func() { _ = visitor.Close(); awaitPublisherTest(t, done) })
	header, err := proxyproto.Encode(proxyproto.Header{
		Source:      netip.MustParseAddrPort("192.0.2.10:40001"),
		Destination: netip.AddrPortFrom(netip.MustParseAddr("203.0.113.10"), port),
	})
	if err != nil {
		return nil, err
	}
	if _, err := visitor.Write(header); err != nil {
		return nil, err
	}
	return visitor, nil
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
