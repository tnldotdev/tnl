package publisher

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/privatetrust"
	"github.com/tnldotdev/tnl/internal/streamcopy"
	"github.com/tnldotdev/tnl/internal/targettransport"
)

func privateTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
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
		left.Close()
		t.Fatal(err)
	}
	for _, conn := range []*net.TCPConn{left, right} {
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		t.Cleanup(func() { _ = conn.Close() })
	}
	return left, right
}

// opaque private streams carry encrypted client-managed TLS and database
// cancellation alike. a local half-close must retain the provider's response.
func TestPrivateOpaqueCancellationRetainsResponseAfterEOF(t *testing.T) {
	visitor, local := privateTCPPair(t)
	provider, target := privateTCPPair(t)
	done := make(chan error, 1)
	go func() { _, err := streamcopy.Copy(local, provider); done <- err }()
	cancelPacket := []byte{0, 0, 0, 16, 4, 210, 22, 46, 's', 'e', 'c', 'r', 'e', 't', '!', '!'}
	if _, err := visitor.Write(cancelPacket); err != nil {
		t.Fatal(err)
	}
	if err := visitor.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(target)
	if err != nil || !bytes.Equal(got, cancelPacket) {
		t.Fatalf("opaque cancellation changed: %x, %v", got, err)
	}
	if _, err := io.WriteString(target, "response-after-eof"); err != nil {
		t.Fatal(err)
	}
	if err := target.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(visitor)
	if err != nil || string(response) != "response-after-eof" {
		t.Fatalf("half-close lost response: %q, %v", response, err)
	}
	if err := awaitPublisherTest(t, done); err != nil {
		t.Fatal(err)
	}
}

func TestPrivateDatabaseWrongHostnameNeverReceivesLogin(t *testing.T) {
	visitor, _ := privateTCPPair(t)
	provider, target := privateTCPPair(t)
	control := newCertificateTestControl(t, "db.internal", publicURLCertificateTestPlan())
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: control.signer.Certificate[0]}), 0o600); err != nil {
		t.Fatal(err)
	}
	expected := "other.internal"
	trust, err := privatetrust.NewCache(nil).Capture(t.Context(), root, provider.RemoteAddr().String(), config.TrustSource{CA: "ca.pem", Hostname: &expected})
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithTimeout(t.Context(), 5*time.Second)
	defer stop()
	serverDone := make(chan error, 1)
	go func() {
		var request [8]byte
		if _, err := io.ReadFull(target, request[:]); err != nil {
			serverDone <- err
			return
		}
		if request != [8]byte{0, 0, 0, 8, 4, 210, 22, 47} {
			serverDone <- errors.New("invalid PostgreSQL SSLRequest")
			return
		}
		if _, err := target.Write([]byte{'S'}); err != nil {
			serverDone <- err
			return
		}
		secured := tls.Server(target, &tls.Config{Certificates: []tls.Certificate{control.signer}})
		serverDone <- secured.HandshakeContext(ctx)
	}()
	done := make(chan error, 1)
	go func() {
		verification, err := trust.Verifier()
		if err == nil {
			_, err = (targettransport.Transport{Protocol: config.ProtocolPostgres, TLS: verification}).Secure(ctx, provider)
		}
		done <- err
	}()
	if _, err := io.WriteString(visitor, "private-login-secret"); err != nil {
		t.Fatal(err)
	}
	var hostname x509.HostnameError
	if err := awaitPublisherTest(t, done); !errors.As(err, &hostname) {
		t.Fatalf("wrong database hostname accepted or misclassified: %v", err)
	}
	if err := awaitPublisherTest(t, serverDone); err == nil {
		t.Fatal("provider completed TLS despite hostname rejection")
	}
}
