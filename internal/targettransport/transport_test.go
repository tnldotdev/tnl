package targettransport

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
)

func TestPreflightNegotiatesOnceWithoutApplicationBytes(t *testing.T) {
	certificateSource := httptest.NewTLSServer(nil)
	defer certificateSource.Close()
	certificate := certificateSource.TLS.Certificates[0]
	roots := x509.NewCertPool()
	roots.AddCert(certificateSource.Certificate())
	for _, protocol := range []config.ProtocolName{config.ProtocolHTTP, config.ProtocolTCP, config.ProtocolPostgres, config.ProtocolMySQL} {
		for _, valid := range []bool{true, false} {
			t.Run(string(protocol)+map[bool]string{true: "/verified", false: "/wrong-name"}[valid], func(t *testing.T) {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				done := make(chan error, 1)
				go func() {
					backend, err := listener.Accept()
					if err != nil {
						done <- err
						return
					}
					defer backend.Close()
					_ = backend.SetDeadline(time.Now().Add(3 * time.Second))
					switch protocol {
					case config.ProtocolPostgres:
						var request [8]byte
						_, err = io.ReadFull(backend, request[:])
						if err != nil || request != PostgresSSLRequest {
							done <- errors.New("preflight did not send one PostgreSQL SSLRequest")
							return
						}
						_, err = backend.Write([]byte{'S'})
					case config.ProtocolMySQL:
						greeting := testGreeting()
						_, err = backend.Write(greeting)
						if err == nil {
							var request []byte
							request, err = ReadMySQLPacket(backend, 32)
							if err == nil && (len(request) != 36 || request[3] != 1 || binary.LittleEndian.Uint32(request[4:])&MySQLClientSSL == 0) {
								err = errors.New("invalid MySQL SSLRequest")
							}
						}
					}
					if err != nil {
						done <- err
						return
					}
					secured := tls.Server(backend, &tls.Config{Certificates: []tls.Certificate{certificate}})
					if err := secured.Handshake(); err != nil {
						if valid {
							done <- err
						} else {
							done <- nil
						}
						return
					}
					var application [1]byte
					if n, _ := secured.Read(application[:]); n != 0 {
						done <- errors.New("preflight sent authentication or application bytes")
						return
					}
					done <- nil
				}()
				name := certificateSource.Certificate().DNSNames[0]
				if !valid {
					name = "wrong.target.test"
				}
				err = (Transport{Protocol: protocol, TLS: &tls.Config{RootCAs: roots, ServerName: name}}).Preflight(t.Context(), listener.Addr().String())
				if valid && err != nil {
					t.Fatal(err)
				}
				if !valid {
					reason, definition, ok := failure.Describe(err)
					var cause *tls.CertificateVerificationError
					if !ok || reason != failure.TargetTLSRejected || definition.Retry != failure.RetryAfterChange || !errors.As(err, &cause) {
						t.Fatalf("lost verified failure classification: %v", err)
					}
				}
				if err := <-done; err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func testGreeting() []byte {
	flags := uint32(MySQLClientSSL | MySQLClientProtocol41)
	payload := append([]byte{10}, []byte("8.0-test\x00")...)
	payload = append(payload, make([]byte, 4+8+1)...)
	payload = binary.LittleEndian.AppendUint16(payload, uint16(flags))
	payload = append(payload, 45, 0, 0)
	payload = binary.LittleEndian.AppendUint16(payload, uint16(flags>>16))
	payload = append(payload, 21)
	payload = append(payload, make([]byte, 10+13)...)
	return append([]byte{byte(len(payload)), 0, 0, 0}, payload...)
}

func TestTargetTransportRejectsTrustBypassesAndPreservesCancellation(t *testing.T) {
	for _, verification := range []*tls.Config{
		{ServerName: "target.test", InsecureSkipVerify: true},
		{ServerName: "target.test", VerifyConnection: func(tls.ConnectionState) error { return nil }},
		{ServerName: "target.test", VerifyPeerCertificate: func([][]byte, [][]*x509.Certificate) error { return nil }},
		{},
	} {
		err := (Transport{Protocol: config.ProtocolTCP, TLS: verification}).Preflight(t.Context(), "invalid-address")
		reason, _, ok := failure.Describe(err)
		if !ok || reason != failure.InvalidTarget {
			t.Fatal("unsafe trust reached dialing", err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := (Transport{Protocol: config.ProtocolTCP}).Preflight(ctx, "127.0.0.1:1"); !errors.Is(err, context.Canceled) {
		t.Fatal("lost cancellation", err)
	}
	if _, err := MySQLSSLRequest(bytes.Repeat([]byte{0}, 80)); !errors.Is(err, ErrDatabaseTLS) {
		t.Fatal("malformed greeting accepted", err)
	}
}
