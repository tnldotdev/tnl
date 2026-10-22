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
	"github.com/tnldotdev/tnl/internal/observability"
)

func TestPreflightNegotiatesOnceWithoutApplicationBytes(t *testing.T) {
	certificateSource := httptest.NewTLSServer(nil)
	defer certificateSource.Close()
	certificate := certificateSource.TLS.Certificates[0]
	roots := x509.NewCertPool()
	roots.AddCert(certificateSource.Certificate())
	for _, protocol := range []config.ProtocolName{config.ProtocolHTTP, config.ProtocolTCP, config.ProtocolPostgres, config.ProtocolMySQL, config.ProtocolKubernetes} {
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
				metrics := observability.New("publisher")
				defer metrics.Shutdown(context.Background())
				err = (Transport{Protocol: protocol, TLS: &tls.Config{RootCAs: roots, ServerName: name}}).Preflight(observability.WithMetrics(t.Context(), metrics), listener.Addr().String())
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
				families, err := metrics.Gather()
				if err != nil {
					t.Fatal(err)
				}
				seen := map[string]bool{}
				for _, family := range families {
					if family.GetName() != "tnl_publisher_operation_duration_seconds" && family.GetName() != "tnl_publisher_tls_handshakes_total" {
						continue
					}
					for _, point := range family.Metric {
						labels := map[string]string{}
						for _, label := range point.Label {
							labels[label.GetName()] = label.GetValue()
						}
						if labels["tnl_service_protocol"] != string(protocol) || labels["tnl_component"] != "publisher" {
							t.Fatal("real preflight or handshake omitted its known protocol", family.GetName(), labels)
						}
						if family.GetName() == "tnl_publisher_tls_handshakes_total" {
							wantOutcome := "rejected"
							if valid {
								wantOutcome = "success"
							}
							if labels["tnl_outcome"] != wantOutcome || labels["tnl_tls_leg"] != "target" {
								t.Fatal("TLS facts lost their owned trust outcome", labels)
							}
						}
						seen[family.GetName()] = true
					}
				}
				if len(seen) != 2 {
					t.Fatal("preflight did not reach its operation and TLS instruments", seen)
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

func TestPreflightConnectionPreservesCancellationCause(t *testing.T) {
	for _, protocol := range []config.ProtocolName{config.ProtocolHTTP, config.ProtocolTCP, config.ProtocolPostgres, config.ProtocolMySQL, config.ProtocolKubernetes} {
		t.Run(string(protocol), func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			ctx, cancel := context.WithCancelCause(t.Context())
			cause := errors.New("owner stopped during native negotiation")
			cancel(cause)
			err := (Transport{Protocol: protocol, TLS: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "service.example.test"}}).PreflightConnection(ctx, client)
			if !errors.Is(err, cause) {
				t.Fatalf("native negotiation lost its owner cancellation: %v", err)
			}
		})
	}
}
