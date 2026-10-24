package publisher_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/publisher"
)

func TestManagedOpaqueThroughOriginalDestination(t *testing.T) {
	certificates := serviceCertificates(t)
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	payload := []byte{0, 1, 2, 3, 255, 0, 19, 4}
	done := make(chan error, 1)
	go func() {
		connection, err := target.Accept()
		if err != nil {
			done <- err
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
		buffer := make([]byte, len(payload))
		if _, err = io.ReadFull(connection, buffer); err == nil {
			if !bytes.Equal(buffer, payload) {
				t.Error("opaque application bytes changed")
			}
			_, err = connection.Write(buffer)
		}
		done <- err
	}()
	const host = "opaque.production.storefront.example.test"
	stream := publisher.ServiceStream{Protocol: config.ProtocolTCP, Hostname: host, Target: target.Addr().String(), TLS: &tls.Config{Certificates: []tls.Certificate{certificates.server}}, Visitor: publisher.CertificateVisitor{Check: func(_ context.Context, state tls.ConnectionState) (publisher.ServiceVisitorDecision, error) {
		leaf := state.PeerCertificates[0]
		_, err := leaf.Verify(x509.VerifyOptions{Roots: certificates.roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
		return publisher.ServiceVisitorDecision{Allowed: err == nil, ValidUntil: time.Now().Add(time.Minute)}, err
	}}}
	address := managedIngressListener(t, stream)
	client, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", address, &tls.Config{RootCAs: certificates.roots, ServerName: host, Certificates: []tls.Certificate{certificates.client}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(client, response); err != nil || !bytes.Equal(response, payload) {
		t.Fatalf("opaque response = %x, %v", response, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
