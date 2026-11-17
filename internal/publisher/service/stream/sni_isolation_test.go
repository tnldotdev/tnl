package stream_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	servicestream "github.com/tnldotdev/tnl/internal/publisher/service/stream"
)

func TestServiceTLSWildcardSNIIsServiceBound(t *testing.T) {
	certificates := serviceCertificates(t)
	leaf, err := x509.ParseCertificate(certificates.server.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	const hostname = "web.production.storefront.example.test"
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "*.production.storefront.example.test" {
		t.Fatal("SNI isolation fixture needs one shared wildcard certificate", leaf.DNSNames)
	}
	for _, test := range []struct {
		name, sni string
		allowed   bool
	}{
		{"exact", hostname, true},
		{"uppercase_same_name", strings.ToUpper(hostname), true},
		{"covered_sibling", "api.production.storefront.example.test", false},
		{"another_covered_sibling", "other.production.storefront.example.test", false},
		{"configured_alias_is_not_tcp_authority", "r-aaaaaaaaaaaaaaaaaaaaaaaaaa.production.storefront.example.test", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			// a certificate-name failure must not substitute for service sni isolation.
			if _, err := leaf.Verify(x509.VerifyOptions{
				DNSName: test.sni, Roots: certificates.roots,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}); err != nil {
				t.Fatal("shared certificate does not verify the tested SNI", err)
			}
			incoming, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			target, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				_ = incoming.Close()
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			until, _ := ctx.Deadline()
			payload := []byte("only the selected service")
			var authorizations, targetConnections atomic.Int32
			// tcp isolates the shared tls/sni gate from later http authority checks.
			stream := servicestream.Stream{
				Protocol: config.ProtocolTCP, Hostname: hostname, RunHostname: "r-aaaaaaaaaaaaaaaaaaaaaaaaaa.production.storefront.example.test", Target: target.Addr().String(),
				TLS: &tls.Config{
					Certificates: []tls.Certificate{certificates.server},
					MinVersion:   tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
				},
				Visitor: servicestream.CertificateVisitor{Check: func(_ context.Context, client *x509.Certificate) (servicestream.Decision, error) {
					authorizations.Add(1)
					if !bytes.Equal(client.Raw, certificates.client.Certificate[0]) {
						return servicestream.Decision{}, errors.New("another client certificate reached authorization")
					}
					_, err := client.Verify(x509.VerifyOptions{
						Roots:     certificates.roots,
						KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
					})
					return servicestream.Decision{Allowed: err == nil, ValidUntil: time.Now().Add(time.Minute)}, err
				}},
			}
			forwarded, targetDone := make(chan error, 1), make(chan error, 1)
			var workers sync.WaitGroup
			var targetMu sync.Mutex
			var acceptedTarget net.Conn
			var client *tls.Conn
			finish := sync.OnceFunc(func() {
				cancel()
				_ = incoming.Close()
				_ = target.Close()
				if client != nil {
					_ = client.Close()
				}
				targetMu.Lock()
				if acceptedTarget != nil {
					_ = acceptedTarget.Close()
				}
				targetMu.Unlock()
				workers.Wait()
			})
			t.Cleanup(finish)
			workers.Add(2)
			go func() {
				defer workers.Done()
				connection, err := incoming.Accept()
				if err != nil {
					forwarded <- err
					return
				}
				defer connection.Close()
				forwarded <- stream.Forward(ctx, connection)
			}()
			go func() {
				defer workers.Done()
				connection, err := target.Accept()
				if err != nil {
					targetDone <- err
					return
				}
				targetConnections.Add(1)
				targetMu.Lock()
				acceptedTarget = connection
				stopped := ctx.Err() != nil
				targetMu.Unlock()
				defer connection.Close()
				if stopped {
					targetDone <- context.Cause(ctx)
					return
				}
				if err := connection.SetDeadline(until); err != nil {
					targetDone <- err
					return
				}
				body, err := io.ReadAll(connection)
				if err == nil && !bytes.Equal(body, payload) {
					err = errors.New("SNI selection changed target bytes")
				}
				if err == nil {
					_, err = connection.Write(body)
				}
				if err == nil {
					err = connection.(*net.TCPConn).CloseWrite()
				}
				targetDone <- err
			}()
			raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", incoming.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			client = tls.Client(raw, &tls.Config{
				RootCAs: certificates.roots, ServerName: test.sni,
				Certificates: []tls.Certificate{certificates.client},
				MinVersion:   tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
			})
			if err := client.SetDeadline(until); err != nil {
				t.Fatal(err)
			}
			handshakeErr := client.HandshakeContext(ctx)
			if !test.allowed {
				var serverErr error
				select {
				case serverErr = <-forwarded:
				case <-ctx.Done():
					t.Fatal("covered sibling did not receive a server-side TLS rejection", context.Cause(ctx))
				}
				finish()
				var verification *tls.CertificateVerificationError
				if handshakeErr == nil || errors.As(handshakeErr, &verification) || !errors.Is(serverErr, servicestream.ErrEndpoint) {
					t.Fatal("covered sibling was not rejected by the service's SNI boundary", handshakeErr, serverErr)
				}
				if authorizations.Load() != 0 || targetConnections.Load() != 0 {
					t.Fatal("covered sibling reached authorization or target", authorizations.Load(), targetConnections.Load())
				}
				return
			}
			if handshakeErr != nil {
				var serverErr error
				select {
				case serverErr = <-forwarded:
				case <-ctx.Done():
					serverErr = context.Cause(ctx)
				}
				t.Fatalf("selected service SNI %q failed TLS: client=%v server=%v authorizations=%d target_connections=%d",
					test.sni, handshakeErr, serverErr, authorizations.Load(), targetConnections.Load())
			}
			state := client.ConnectionState()
			if state.Version != tls.VersionTLS13 || len(state.VerifiedChains) == 0 ||
				len(state.PeerCertificates) == 0 || !bytes.Equal(state.PeerCertificates[0].Raw, certificates.server.Certificate[0]) {
				t.Fatal("selected service did not retain verified TLS with the shared wildcard certificate")
			}
			if _, err := client.Write(payload); err != nil {
				t.Fatal(err)
			}
			if err := client.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			response, err := io.ReadAll(client)
			if err != nil || !bytes.Equal(response, payload) {
				t.Fatal("selected service did not carry its target bytes", string(response), err)
			}
			select {
			case err := <-targetDone:
				if err != nil {
					t.Fatal("selected target failed", err)
				}
			case <-ctx.Done():
				t.Fatal("selected target did not join", context.Cause(ctx))
			}
			select {
			case err := <-forwarded:
				if err != nil {
					t.Fatal("selected service stream did not finish cleanly", err)
				}
			case <-ctx.Done():
				t.Fatal("selected service stream did not join", context.Cause(ctx))
			}
			finish()
			if authorizations.Load() != 1 || targetConnections.Load() != 1 {
				t.Fatal("selected SNI lost or duplicated authorization/target selection", authorizations.Load(), targetConnections.Load())
			}
		})
	}
}
