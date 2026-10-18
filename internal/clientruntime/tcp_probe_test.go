package clientruntime

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPublicTCPReadinessNegotiatesProtocolsAndVerifiesTLS(t *testing.T) {
	fixture := httptest.NewTLSServer(http.NotFoundHandler())
	certificate := fixture.TLS.Certificates[0]
	pool := x509.NewCertPool()
	pool.AddCert(fixture.Certificate())
	fixture.Close()
	for _, protocol := range []string{"postgres", "mysql", "redis", "ssh"} {
		t.Run(protocol, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan error, 1)
			go func() {
				connection, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
				if protocol == "ssh" {
					_, err = connection.Write([]byte("SSH-2.0-readiness-test\r\n"))
					done <- err
					return
				}
				if protocol == "postgres" {
					var preface [8]byte
					if _, err = io.ReadFull(connection, preface[:]); err != nil {
						done <- err
						return
					}
					if preface != [8]byte{0, 0, 0, 8, 4, 210, 22, 47} {
						done <- io.ErrUnexpectedEOF
						return
					}
					_, err = connection.Write([]byte{'S'})
				}
				if protocol == "mysql" {
					_, err = connection.Write([]byte{1, 0, 0, 0, 10})
					if err == nil {
						var ssl [36]byte
						_, err = io.ReadFull(connection, ssl[:])
						if ssl[3] != 1 || ssl[5]&8 == 0 {
							err = io.ErrUnexpectedEOF
						}
					}
				}
				if err != nil {
					done <- err
					return
				}
				secure := tls.Server(connection, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
				if err = secure.Handshake(); err != nil {
					done <- err
					return
				}
				if protocol == "redis" {
					packet := make([]byte, len("*1\r\n$4\r\nPING\r\n"))
					_, err = io.ReadFull(secure, packet)
					if err == nil {
						_, err = secure.Write([]byte("+PONG\r\n"))
					}
				}
				done <- err
			}()
			service := Service{RegistrationID: "reg_current", PublishRunNumber: 9, Target: "127.0.0.1:1", PublicURL: listener.Addr().String(), ServiceProtocol: protocol}
			result := ProbeTCP(t.Context(), service, TCPProbeOptions{TLSConfig: &tls.Config{RootCAs: pool}})
			if !result.Ready || result.PublishRunNumber != 9 || result.Target != service.Target {
				t.Fatalf("public %s probe=%+v", protocol, result)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
	t.Run("untrusted certificate", func(t *testing.T) {
		server := httptest.NewTLSServer(http.NotFoundHandler())
		defer server.Close()
		err := CheckPublicTCP(t.Context(), TCPProbeOptions{Protocol: "redis", Address: server.Listener.Addr().String()})
		if err == nil {
			t.Fatal("readiness accepted an untrusted public certificate")
		}
	})
}

func TestPublicTCPReadinessRequiresBannerAndHonorsCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		connection, err := listener.Accept()
		if err == nil {
			defer connection.Close()
			_, _ = io.Copy(io.Discard, connection)
		}
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	if err := CheckPublicTCP(ctx, TCPProbeOptions{Protocol: "ssh", Address: listener.Addr().String()}); err == nil {
		t.Fatal("a bare TCP listener passed SSH readiness")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("probe cancellation leaked connection")
	}
}
