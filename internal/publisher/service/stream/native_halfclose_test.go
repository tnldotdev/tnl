package stream_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	servicestream "github.com/tnldotdev/tnl/internal/publisher/service/stream"
)

func TestNativeStreamHalfCloseKeepsOppositeDirection(t *testing.T) {
	for _, connector := range []bool{false, true} {
		for _, targetTLS := range []bool{false, true} {
			for _, visitorFirst := range []bool{false, true} {
				t.Run(fmt.Sprintf("connector=%t/target_tls=%t/visitor_first=%t", connector, targetTLS, visitorFirst), func(t *testing.T) {
					certificates := serviceCertificates(t)
					const hostname = "opaque.production.storefront.example.test"
					target, err := net.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					defer target.Close()
					front, err := net.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					defer front.Close()
					allow := func(context.Context) (servicestream.Decision, error) {
						return servicestream.Decision{Allowed: true, ValidUntil: time.Now().Add(time.Minute)}, nil
					}
					var auth servicestream.Authentication = servicestream.CertificateVisitor{Check: func(ctx context.Context, _ *x509.Certificate) (servicestream.Decision, error) {
						return allow(ctx)
					}}
					if connector {
						auth = servicestream.ConnectorVisitor{Admission: servicestream.AdmissionFixture{Check: allow}}
					}
					endpoint := servicestream.Stream{Protocol: config.ProtocolTCP, Hostname: hostname, Target: target.Addr().String(),
						TLS: &tls.Config{Certificates: []tls.Certificate{certificates.server}}, Visitor: auth}
					if targetTLS {
						endpoint.TargetTLS = &tls.Config{ServerName: hostname, RootCAs: certificates.roots}
					}
					ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
					defer cancel()
					done := make(chan error, 1)
					joined := make(chan struct{})
					go func() {
						defer close(joined)
						incoming, err := front.Accept()
						if err != nil {
							done <- err
							return
						}
						defer incoming.Close()
						done <- endpoint.Forward(ctx, incoming)
					}()
					defer func() {
						cancel()
						_ = front.Close()
						select {
						case <-joined:
						case <-time.After(time.Second):
							t.Error("native stream copy or guard did not join")
						}
					}()
					verification := &tls.Config{ServerName: hostname, RootCAs: certificates.roots}
					if !connector {
						verification.Certificates = []tls.Certificate{certificates.client}
					}
					client, err := tls.DialWithDialer(&net.Dialer{Deadline: time.Now().Add(5 * time.Second)}, "tcp", front.Addr().String(), verification)
					if err != nil {
						t.Fatal(err)
					}
					defer client.Close()
					_ = client.SetDeadline(time.Now().Add(5 * time.Second))
					_ = target.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second))
					raw, err := target.Accept()
					if err != nil {
						t.Fatal(err)
					}
					defer raw.Close()
					_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
					var backend net.Conn = raw
					if targetTLS {
						secured := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{certificates.server}})
						if err := secured.HandshakeContext(ctx); err != nil {
							t.Fatal(err)
						}
						backend = secured
					}
					send := func(conn net.Conn, payload string) {
						t.Helper()
						if _, err := io.WriteString(conn, payload); err != nil {
							t.Fatal("half-closed peer lost its remaining write direction", err)
						}
						if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
							t.Fatal(err)
						}
					}
					receive := func(conn net.Conn, payload string) {
						t.Helper()
						got, err := io.ReadAll(conn)
						if err != nil || string(got) != payload {
							t.Fatalf("half-close changed bytes or lost clean EOF: %q, %v", got, err)
						}
					}
					if visitorFirst {
						send(client, "request")
						receive(backend, "request")
					} else {
						send(backend, "response")
						receive(client, "response")
					}
					select {
					case err := <-done:
						t.Fatal("one half-close ended the opposite direction", err)
					default:
					}
					if visitorFirst {
						send(backend, "response")
						receive(client, "response")
					} else {
						send(client, "request")
						receive(backend, "request")
					}
					select {
					case err := <-done:
						if err != nil {
							t.Fatal("clean duplex completion failed", err)
						}
					case <-ctx.Done():
						t.Fatal("native stream did not join after both EOFs")
					}
				})
			}
		}
	}
}
