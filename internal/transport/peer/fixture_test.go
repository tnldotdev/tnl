package peer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
)

type streamConn struct{ *quic.Stream }

func (s *streamConn) LocalAddr() net.Addr  { return logicalAddr{role: 0} }
func (s *streamConn) RemoteAddr() net.Addr { return logicalAddr{role: 1} }
func (s *streamConn) CloseWrite() error    { return s.Stream.Close() }
func (s *streamConn) Close() error         { s.CancelRead(0); s.CancelWrite(0); return nil }
func awaitPath(t *testing.T, ctx context.Context, left, right *Endpoint, expected int) {
	t.Helper()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for left.ActivePath() != expected || right.ActivePath() != expected || !left.PathHealthy(expected) || !right.PathHealthy(expected) {
		select {
		case <-ctx.Done():
			t.Fatalf("path %d not established: left=%d healthy=%t right=%d healthy=%t", expected,
				left.ActivePath(), left.PathHealthy(expected), right.ActivePath(), right.PathHealthy(expected))
		case <-ticker.C:
		}
	}
}
func peerTLS(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"peer.test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	server := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, NextProtos: []string{muxsession.ALPN}}
	client := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "peer.test", NextProtos: []string{muxsession.ALPN}}
	return server, client
}
func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	left, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	right, err := listener.AcceptTCP()
	if err != nil {
		_ = left.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = left.Close(); _ = right.Close() })
	return left, right
}
