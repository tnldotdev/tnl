package publisher

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	mysql "github.com/go-sql-driver/mysql"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/targettransport"
	"github.com/tnldotdev/tnl/internal/testutil"
)

func nativeMySQLPacket(sequence byte, payload []byte) []byte {
	return append([]byte{byte(len(payload)), byte(len(payload) >> 8), byte(len(payload) >> 16), sequence}, payload...)
}
func nativeMySQLGreeting() []byte {
	flags := uint32(managedMySQLProtocol41 | managedMySQLSSL | 1<<19 | 1<<15 | 1)
	challenge := []byte("abcdefghijklmnopqrst")
	payload := []byte("\x0a8.4-test\x00")
	payload = binary.LittleEndian.AppendUint32(payload, 1)
	payload = append(payload, challenge[:8]...)
	payload = append(payload, 0)
	payload = binary.LittleEndian.AppendUint16(payload, uint16(flags))
	payload = append(payload, 0x21, 2, 0)
	payload = binary.LittleEndian.AppendUint16(payload, uint16(flags>>16))
	payload = append(payload, 21)
	payload = append(payload, make([]byte, 10)...)
	payload = append(payload, challenge[8:]...)
	payload = append(payload, 0)
	payload = append(payload, []byte("caching_sha2_password\x00")...)
	return nativeMySQLPacket(0, payload)
}

func TestManagedMySQLNativeAuthSwitchAndFullAuthentication(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	root, certificate := testutil.TLSCertificate(t, []string{"service.example.test"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(root)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	backendDone := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			backendDone <- err
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(8 * time.Second))
		_, err = connection.Write(nativeMySQLGreeting())
		if err != nil {
			backendDone <- err
			return
		}
		request, err := targettransport.ReadMySQLPacket(connection, 32)
		if err != nil || len(request) != 36 || request[3] != 1 {
			backendDone <- fmt.Errorf("server-first SSLRequest: %v", err)
			return
		}
		secured := tls.Server(connection, &tls.Config{Certificates: []tls.Certificate{certificate}})
		if err = secured.HandshakeContext(ctx); err != nil {
			backendDone <- err
			return
		}
		login, err := targettransport.ReadMySQLPacket(secured, 1<<20)
		if err != nil || login[3] != 2 {
			backendDone <- fmt.Errorf("native login sequence: %v", err)
			return
		}
		switchPlugin := append([]byte("\xfecaching_sha2_password\x00"), []byte("abcdefghijklmnopqrst\x00")...)
		_, err = secured.Write(nativeMySQLPacket(3, switchPlugin))
		if err != nil {
			backendDone <- err
			return
		}
		response, err := targettransport.ReadMySQLPacket(secured, 512)
		if err != nil || response[3] != 4 {
			backendDone <- fmt.Errorf("auth switch sequence: %v", err)
			return
		}
		clear(response)
		_, err = secured.Write(nativeMySQLPacket(5, []byte{1, 4}))
		if err != nil {
			backendDone <- err
			return
		}
		password, err := targettransport.ReadMySQLPacket(secured, 512)
		if err != nil || password[3] != 6 || string(password[4:]) != "testpass\x00" {
			backendDone <- fmt.Errorf("native TLS full authentication: %v", err)
			return
		}
		clear(password)
		_, err = secured.Write(nativeMySQLPacket(7, []byte{0, 0, 0, 2, 0, 0, 0}))
		if err != nil {
			backendDone <- err
			return
		}
		ping, err := targettransport.ReadMySQLPacket(secured, 32)
		if err != nil || ping[3] != 0 || ping[4] != 0x0e {
			backendDone <- fmt.Errorf("command replay or sequence corruption: %v", err)
			return
		}
		_, err = secured.Write(nativeMySQLPacket(1, []byte{0, 0, 0, 2, 0, 0, 0}))
		backendDone <- err
	}()
	front, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer front.Close()
	forwardDone := make(chan error, 1)
	go func() {
		connection, err := front.Accept()
		if err != nil {
			forwardDone <- err
			return
		}
		defer connection.Close()
		forwardDone <- (ManagedStream{Protocol: config.ProtocolMySQL, Hostname: "service.example.test", Target: listener.Addr().String(), TLS: &tls.Config{Certificates: []tls.Certificate{certificate}}, TargetTLS: &tls.Config{ServerName: "service.example.test", RootCAs: roots}, Visitor: ConnectorVisitor{Check: func(context.Context) (ManagedVisitorDecision, error) {
			return ManagedVisitorDecision{Allowed: true, ValidUntil: time.Now().Add(time.Minute)}, nil
		}}}).Forward(ctx, connection)
	}()
	const key = "managed-native-switch"
	if err := mysql.RegisterTLSConfig(key, &tls.Config{ServerName: "service.example.test", RootCAs: roots, GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		t.Error("connector requested application client certificate")
		return nil, ErrManagedTLS
	}}); err != nil {
		t.Fatal(err)
	}
	defer mysql.DeregisterTLSConfig(key)
	database, err := sql.Open("mysql", "tnl_client:testpass@tcp("+front.Addr().String()+")/?tls="+key+"&timeout=5s")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-backendDone; err != nil {
		t.Fatal(err)
	}
	_ = database.Close()
	cancel()
	select {
	case err := <-forwardDone:
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("native adapter did not join")
	}
}
