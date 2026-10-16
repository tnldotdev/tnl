package ingress

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"testing"

	"github.com/tnldotdev/tnl/internal/proxyproto"
	"github.com/tnldotdev/tnl/internal/routebackend"
)

func TestIngressRestrictedSSHUsesPendingTLS(t *testing.T) {
	a, b := net.Pipe()
	ownIngressConn(t, a)
	ownIngressConn(t, b)
	backend := &pendingDatabaseBackend{connection: a}
	certificate := testCertificate(t, "ssh.example")
	received := make(chan proxyproto.Header, 1)
	worker := ingressWorker(t, func() { _ = a.Close(); _ = b.Close() }, func() error {
		defer b.Close()
		header, replay, err := proxyproto.Decode(b)
		if err != nil {
			return err
		}
		secured := tls.Server(&readerConn{Conn: b, reader: replay}, &tls.Config{Certificates: []tls.Certificate{certificate}})
		if err := secured.HandshakeContext(t.Context()); err != nil {
			return err
		}
		received <- header
		// ingress can carry the encrypted pre-authentication exchange without
		// promoting SSH to ordinary capacity or assuming a raw SSH banner.
		_, err = secured.Write([]byte("pending"))
		return err
	})
	s, address := startIngress(t, Config{RequireProxyHeader: true, LookupPort: func(uint16) (PublicURL, LookupReason) {
		return PublicURL{ID: "ssh", PublishRunNumber: 1, AccessMode: "restricted", AllowAll: true,
			ServiceProtocol: "ssh", PublicPort: testPublicPort(2222), Backends: []routebackend.Backend{backend}}, LookupCurrent
	}})
	client := separatedVisitor(t, address, "198.51.100.1:40001", 2222)
	roots := x509.NewCertPool()
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(leaf)
	secured := tls.Client(client, &tls.Config{ServerName: "ssh.example", RootCAs: roots})
	if err := secured.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	header := ingressAwait(t, received)
	if header.Source.String() != "198.51.100.1:40001" || header.Destination.Port() != 2222 {
		t.Fatal("pending TLS changed trusted visitor metadata")
	}
	if s.Load() != 0 || backend.pending.Load() != 1 || backend.ordinary.Load() != 0 {
		t.Fatal("restricted SSH bypassed pending capacity")
	}
	var answer [7]byte
	if _, err := io.ReadFull(secured, answer[:]); err != nil || string(answer[:]) != "pending" {
		t.Fatalf("pending TLS exchange = %q, %v", answer, err)
	}
	if err := ingressAwait(t, worker); err != nil {
		t.Fatal(err)
	}
}
