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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	"github.com/tnldotdev/tnl/internal/transport/streamcopy"
	"github.com/tnldotdev/tnl/internal/transport/targettransport"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
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

func TestNativeTLSCloseNotifyKeepsOuterPermissionRenewalsAndResponse(t *testing.T) {
	target, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	client, server := privateTCPPair(t)
	started := time.Now()
	certificate := publicURLTestCertificate(t, "native.test")
	var deadline atomic.Int64
	renewed := make(chan struct{}, 1)
	reader := tunnel.NewNativeRequestReader(server, nil, func(tunnelv1.NativeVisitorPermission) error {
		deadline.Store(time.Now().Add(5 * time.Second).UnixNano())
		renewed <- struct{}{}
		return nil
	})
	service := ServiceStream{Protocol: config.ProtocolTCP, Hostname: "native.test", Target: target.Addr().String(),
		TLS: &tls.Config{Certificates: []tls.Certificate{certificate}}, Visitor: ConnectorVisitor{Check: func(context.Context) (ServiceVisitorDecision, error) {
			deadline.CompareAndSwap(0, time.Now().Add(1200*time.Millisecond).UnixNano())
			return ServiceVisitorDecision{Allowed: true, ValidUntil: time.Unix(0, deadline.Load())}, nil
		}}}
	finished := make(chan error, 1)
	go func() { finished <- service.Forward(t.Context(), reader) }()
	targetDone := make(chan error, 1)
	go func() {
		conn, err := target.AcceptTCP()
		if err != nil {
			targetDone <- err
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		var request []byte
		request, err = io.ReadAll(conn)
		if err != nil || string(request) != "request" {
			targetDone <- errors.Join(err, errors.New("native target lost request half-close"))
			return
		}
		select {
		case <-renewed:
		case <-time.After(2 * time.Second):
			targetDone <- errors.New("outer permission frame stopped after TLS close_notify")
			return
		}
		time.Sleep(1500 * time.Millisecond) // beyond the original decision deadline
		_, err = io.WriteString(conn, "response-after-renewal")
		if err == nil {
			err = conn.CloseWrite()
		}
		targetDone <- err
	}()
	writer := tunnel.NewNativeRequestWriter(client)
	secured := tls.Client(writer, &tls.Config{RootCAs: rootsForCertificate(t, certificate), ServerName: "native.test", MinVersion: tls.VersionTLS12})
	if err := secured.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(secured, "request"); err != nil {
		t.Fatal(err)
	}
	if err := writer.CloseTLSWrite(secured); err != nil {
		t.Fatal(err)
	}
	renewalDone := make(chan error, 1)
	go func() {
		renewalDone <- writer.Renew(tunnelv1.NativeVisitorPermission{Token: "signed-visitor-token", PublicKey: strings.Repeat("A", 43), Signature: strings.Repeat("A", 86)})
	}()
	select {
	case err := <-renewalDone:
		if err != nil {
			select {
			case stopped := <-finished:
				t.Fatalf("renewal failed after %s: %v; publisher: %v", time.Since(started), err, stopped)
			default:
				t.Fatalf("renewal failed after %s: %v", time.Since(started), err)
			}
		}
	case err := <-targetDone:
		t.Fatal("target stopped before permission renewal", err)
	}
	response := make([]byte, len("response-after-renewal"))
	if _, err := io.ReadFull(secured, response); err != nil || string(response) != "response-after-renewal" {
		t.Fatal("response stopped after the unconsumed TLS renewal", string(response), err)
	}
	if err := awaitPublisherTest(t, targetDone); err != nil {
		t.Fatal(err)
	}
	if err := awaitPublisherTest(t, finished); err != nil {
		t.Fatal(err)
	}
}

func TestNativeResponseHalfCloseLetsVisitorFinishItsRequest(t *testing.T) {
	target, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	client, server := privateTCPPair(t)
	certificate := publicURLTestCertificate(t, "native.test")
	reader := tunnel.NewNativeRequestReader(server, nil, func(tunnelv1.NativeVisitorPermission) error { return nil })
	service := ServiceStream{Protocol: config.ProtocolTCP, Hostname: "native.test", Target: target.Addr().String(),
		TLS: &tls.Config{Certificates: []tls.Certificate{certificate}}, Visitor: ConnectorVisitor{Check: func(context.Context) (ServiceVisitorDecision, error) {
			return ServiceVisitorDecision{Allowed: true, ValidUntil: time.Now().Add(time.Minute)}, nil
		}}}
	finished := make(chan error, 1)
	go func() { finished <- service.Forward(t.Context(), reader) }()
	targetDone := make(chan error, 1)
	go func() {
		conn, err := target.AcceptTCP()
		if err != nil {
			targetDone <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		var request [7]byte
		if _, err := io.ReadFull(conn, request[:]); err != nil || string(request[:]) != "request" {
			targetDone <- errors.Join(err, errors.New("target did not receive visitor request"))
			return
		}
		if _, err := io.WriteString(conn, "response"); err != nil {
			targetDone <- err
			return
		}
		if err := conn.CloseWrite(); err != nil {
			targetDone <- err
			return
		}
		_, err = io.Copy(io.Discard, conn)
		targetDone <- err
	}()
	writer := tunnel.NewNativeRequestWriter(client)
	secured := tls.Client(writer, &tls.Config{RootCAs: rootsForCertificate(t, certificate), ServerName: "native.test", MinVersion: tls.VersionTLS12})
	if err := secured.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(secured, "request"); err != nil {
		t.Fatal(err)
	}
	var response [8]byte
	if _, err := io.ReadFull(secured, response[:]); err != nil || string(response[:]) != "response" {
		t.Fatal("response ended before its content", string(response[:]), err)
	}
	if _, err := secured.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatal("target response EOF waited for visitor request EOF", err)
	}
	if err := writer.CloseTLSWrite(secured); err != nil {
		t.Fatal(err)
	}
	if err := awaitPublisherTest(t, targetDone); err != nil {
		t.Fatal(err)
	}
	if err := awaitPublisherTest(t, finished); err != nil {
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
	trust, err := targettrust.NewCache(nil).Capture(t.Context(), root, provider.RemoteAddr().String(), config.TrustSource{CA: "ca.pem", Hostname: &expected})
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
