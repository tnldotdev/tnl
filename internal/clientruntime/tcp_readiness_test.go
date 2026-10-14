package clientruntime

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http/httptest"
	"testing"
	"time"
)

func readinessTCPServer(t *testing.T, handler func(net.Conn)) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			visitor, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer visitor.Close()
				_ = visitor.SetDeadline(time.Now().Add(5 * time.Second))
				handler(visitor)
			}()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done })
	return listener.Addr().String()
}

func TestPublicTCPReadinessChecksPostgresVisitorTLS(t *testing.T) {
	certificate := httptest.NewTLSServer(nil)
	defer certificate.Close()
	roots := x509.NewCertPool()
	roots.AddCert(certificate.Certificate())
	address := readinessTCPServer(t, func(visitor net.Conn) {
		var startup [8]byte
		if _, err := io.ReadFull(visitor, startup[:]); err != nil || startup != postgresSSLRequest {
			t.Errorf("PostgreSQL SSL request = %v, %v", startup, err)
			return
		}
		_, _ = visitor.Write([]byte{'S'})
		_ = tls.Server(visitor, certificate.TLS).Handshake()
	})
	if err := ProbeTCP(t.Context(), address, "postgres", roots); err != nil {
		t.Fatalf("public PostgreSQL TLS: %v", err)
	}
	if err := ProbeTCP(t.Context(), address, "postgres", x509.NewCertPool()); err == nil {
		t.Fatal("untrusted public certificate passed readiness")
	}
}

func TestPublicTCPReadinessBoundsAndQualifiesProtocolChecks(t *testing.T) {
	mysql := readinessTCPServer(t, func(visitor net.Conn) {
		_, _ = visitor.Write([]byte{4, 0, 0, 0, 10, '8', '.', 0})
	})
	if err := ProbeTCP(t.Context(), mysql, "mysql", nil); err != nil {
		t.Fatalf("public MySQL greeting: %v", err)
	}
	ssh := readinessTCPServer(t, func(visitor net.Conn) {
		_, _ = visitor.Write([]byte("SSH-2.0-test\r\n"))
	})
	if err := ProbeTCP(t.Context(), ssh, "ssh", nil); err != nil {
		t.Fatalf("public SSH banner: %v", err)
	}
	bad := readinessTCPServer(t, func(visitor net.Conn) {
		_, _ = visitor.Write([]byte{4, 0, 0, 0, 9, '8', '.', 0})
	})
	if err := ProbeTCP(t.Context(), bad, "mysql", nil); err == nil {
		t.Fatal("invalid public greeting passed readiness")
	}
	if err := ProbeTCP(t.Context(), ssh, "unknown", nil); err == nil {
		t.Fatal("unknown service protocol passed readiness")
	}
}

func TestPublicTCPReadinessVerifiesRedisCertificate(t *testing.T) {
	certificate := httptest.NewTLSServer(nil)
	defer certificate.Close()
	roots := x509.NewCertPool()
	roots.AddCert(certificate.Certificate())
	address := readinessTCPServer(t, func(visitor net.Conn) {
		_ = tls.Server(visitor, certificate.TLS).Handshake()
	})
	if err := ProbeTCP(t.Context(), address, "redis", roots); err != nil {
		t.Fatalf("public Redis visitor TLS: %v", err)
	}
	if err := ProbeTCP(t.Context(), address, "redis", x509.NewCertPool()); err == nil {
		t.Fatal("untrusted Redis public certificate passed readiness")
	}
}
