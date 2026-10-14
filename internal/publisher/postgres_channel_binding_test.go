package publisher

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/streamcopy"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestPostgresPlusChoiceReturnsActionableError(t *testing.T) {
	client, publisher := net.Pipe()
	t.Cleanup(func() { client.Close(); publisher.Close() })
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	_ = publisher.SetDeadline(time.Now().Add(2 * time.Second))
	startup := []byte{0, 0, 0, 8, 0, 3, 0, 0}
	response := make(chan error, 1)
	go func() {
		if _, err := client.Write(startup); err != nil {
			response <- err
			return
		}
		choice := postgresChoiceTestMessage('p', postgresPlusMethod)
		if _, err := client.Write(choice); err != nil {
			response <- err
			return
		}
		var header [5]byte
		if _, err := io.ReadFull(client, header[:]); err != nil {
			response <- err
			return
		}
		if header[0] != 'E' {
			response <- errors.New("missing PostgreSQL ErrorResponse")
			return
		}
		body := make([]byte, int(binary.BigEndian.Uint32(header[1:]))-4)
		if _, err := io.ReadFull(client, body); err != nil {
			response <- err
			return
		}
		var pgError pgproto3.ErrorResponse
		if err := pgError.Decode(body); err != nil {
			response <- err
			return
		}
		if pgError.Code != "28000" || pgError.Severity != "FATAL" ||
			!strings.Contains(pgError.Message, "channel_binding=disable") {
			response <- errors.New("PostgreSQL client error did not explain the next step")
			return
		}
		response <- nil
	}()
	reader := &postgresAuthChoiceConn{Conn: publisher}
	got := make([]byte, len(startup))
	if _, err := io.ReadFull(reader, got); err != nil || !bytes.Equal(got, startup) {
		t.Fatalf("startup = %x, %v", got, err)
	}
	if _, err := reader.Read(make([]byte, 64)); !errors.Is(err, errPostgresChannelBinding) {
		t.Fatalf("channel binding choice = %v", err)
	}
	if err := <-response; err != nil {
		t.Fatal(err)
	}
}

func TestPostgresAuthChoicePreservesOtherFrames(t *testing.T) {
	for _, test := range []struct {
		name string
		data []byte
	}{
		{"opaque fixture", []byte("startup!")},
		{"ordinary SCRAM", append(append([]byte{0, 0, 0, 8, 0, 3, 0, 0},
			postgresChoiceTestMessage('p', []byte("SCRAM-SHA-256\x00\x00\x00\x00\x03n,,"))...),
			postgresChoiceTestMessage('Q', []byte("SELECT 1\x00"))...)},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, publisher := net.Pipe()
			defer publisher.Close()
			go func() {
				_, _ = client.Write(test.data)
				client.Close()
			}()
			got, err := io.ReadAll(&postgresAuthChoiceConn{Conn: publisher})
			if err != nil || !bytes.Equal(got, test.data) {
				t.Fatalf("forwarded bytes = %x, %v", got, err)
			}
		})
	}
}

func TestPostgresAuthChoiceCompletesVisitorTLSAfterTargetHalfClose(t *testing.T) {
	visitor, publisher := inspectionTCPPair(t)
	target, backend := inspectionTCPPair(t)
	certificate := publicURLTestCertificate(t, "route.example")
	securedPublisher := tls.Server(publisher, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}})
	securedVisitor := tls.Client(visitor, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "route.example", RootCAs: rootsForCertificate(t, certificate)})
	for _, connection := range []net.Conn{visitor, publisher, target, backend} {
		if err := connection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	handshake := make(chan error, 1)
	go func() { handshake <- securedPublisher.Handshake() }()
	if err := securedVisitor.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-handshake; err != nil {
		t.Fatal(err)
	}
	copyDone := make(chan error, 1)
	copyFinished := false
	go func() {
		_, err := streamcopy.Copy(&postgresAuthChoiceConn{Conn: securedPublisher}, target)
		copyDone <- err
	}()
	t.Cleanup(func() {
		_ = visitor.Close()
		_ = publisher.Close()
		_ = target.Close()
		_ = backend.Close()
		if !copyFinished {
			select {
			case <-copyDone:
			case <-time.After(3 * time.Second):
				t.Error("publisher forwarding did not stop after closing both ends")
			}
		}
	})
	startup := []byte{0, 0, 0, 8, 0, 3, 0, 0}
	if _, err := securedVisitor.Write(startup); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(startup))
	if _, err := io.ReadFull(backend, got); err != nil || !bytes.Equal(got, startup) {
		t.Fatalf("target startup = %x, %v", got, err)
	}
	if err := backend.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	var response [1]byte
	if _, err := securedVisitor.Read(response[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("visitor did not receive target EOF through TLS: %v", err)
	}
	_ = securedVisitor.Close()
	select {
	case err := <-copyDone:
		copyFinished = true
		if err != nil {
			t.Fatalf("publisher forwarding shutdown: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("publisher forwarding did not stop after visitor closed")
	}
}

func TestPostgresDifferentTLSCertificatesRejectPLUSBeforeTarget(t *testing.T) {
	visitorCertificate := publicURLTestCertificate(t, "route.example")
	backendCertificate := publicURLTestCertificate(t, "db.internal")
	visitorRoots := x509.NewCertPool()
	visitorRoots.AddCert(visitorCertificate.Leaf)
	backendRoots := x509.NewCertPool()
	backendRoots.AddCert(backendCertificate.Leaf)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	forwardedProof := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			forwardedProof <- err
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
		var sslRequest [8]byte
		if _, err := io.ReadFull(connection, sslRequest[:]); err != nil || sslRequest != postgresSSLRequest {
			forwardedProof <- errors.New("target did not receive visitor SSLRequest")
			return
		}
		if _, err := connection.Write([]byte{'S'}); err != nil {
			forwardedProof <- err
			return
		}
		secured := tls.Server(connection, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{backendCertificate}})
		if err := secured.Handshake(); err != nil {
			forwardedProof <- err
			return
		}
		startup := make([]byte, 8)
		if _, err := io.ReadFull(secured, startup); err != nil {
			forwardedProof <- err
			return
		}
		challenge, err := (&pgproto3.AuthenticationSASL{AuthMechanisms: []string{"SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"}}).Encode(nil)
		if err != nil {
			forwardedProof <- err
			return
		}
		if _, err := secured.Write(challenge); err != nil {
			forwardedProof <- err
			return
		}
		_ = secured.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		var proof [1]byte
		if _, err := secured.Read(proof[:]); err == nil {
			forwardedProof <- errors.New("PLUS proof was forwarded across different TLS certificates")
			return
		}
		forwardedProof <- nil
	}()
	route, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "route.example", ServiceProtocol: controlv1.Postgres, PublicPort: 5432,
		Target: listener.Addr().String(), TargetTLS: true, TargetTLSName: "db.internal",
		TargetOptions: localproxy.TargetOptions{RootCAs: backendRoots}, Certificate: visitorCertificate,
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
	secured := tls.Client(visitor, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "route.example", RootCAs: visitorRoots})
	if err := secured.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := secured.Write([]byte{0, 0, 0, 8, 0, 3, 0, 0}); err != nil {
		t.Fatal(err)
	}
	var header [5]byte
	if _, err := io.ReadFull(secured, header[:]); err != nil || header[0] != 'R' {
		t.Fatalf("backend authentication challenge = %x, %v", header, err)
	}
	body := make([]byte, int(binary.BigEndian.Uint32(header[1:]))-4)
	if _, err := io.ReadFull(secured, body); err != nil {
		t.Fatal(err)
	}
	if _, err := secured.Write(postgresChoiceTestMessage('p', postgresPlusMethod)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(secured, header[:]); err != nil || header[0] != 'E' {
		t.Fatalf("client rejection = %x, %v", header, err)
	}
	body = make([]byte, int(binary.BigEndian.Uint32(header[1:]))-4)
	if _, err := io.ReadFull(secured, body); err != nil {
		t.Fatal(err)
	}
	var problem pgproto3.ErrorResponse
	if err := problem.Decode(body); err != nil || problem.Code != "28000" || !strings.Contains(problem.Message, "channel_binding=disable") {
		t.Fatalf("client diagnosis = %#v, %v", problem, err)
	}
	if err := <-forwardedProof; err != nil {
		t.Fatal(err)
	}
}

func postgresChoiceTestMessage(kind byte, body []byte) []byte {
	packet := make([]byte, 5+len(body))
	packet[0] = kind
	binary.BigEndian.PutUint32(packet[1:], uint32(len(body)+4))
	copy(packet[5:], body)
	return packet
}
