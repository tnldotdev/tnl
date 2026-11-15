package ingress

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	serverhttp "github.com/tnldotdev/tnl/internal/serverhttp"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
)

const forwardingClusterSecret = "forwarding-cluster-secret-012345678901"

type forwardingTestMaterial struct {
	authority    *x509.Certificate
	authorityKey *ecdsa.PrivateKey
	roots        *x509.CertPool
	relay        tls.Certificate
	serverName   string
}

func newForwardingTestMaterial(t *testing.T) forwardingTestMaterial {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	authorityKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate authority key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "forwarding test authority"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	authorityDER, err := x509.CreateCertificate(rand.Reader, template, template, &authorityKey.PublicKey, authorityKey)
	if err != nil {
		t.Fatalf("issue authority certificate: %v", err)
	}
	authority, err := x509.ParseCertificate(authorityDER)
	if err != nil {
		t.Fatalf("parse authority certificate: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(authority)
	return forwardingTestMaterial{
		authority: authority, authorityKey: authorityKey, roots: roots,
		relay: issueForwardingTestCertificate(t, authority, authorityKey, "relay.example"), serverName: "relay.example",
	}
}

func issueForwardingTestCertificate(t *testing.T, authority *x509.Certificate, authorityKey *ecdsa.PrivateKey, hostname string) tls.Certificate {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate relay key: %v", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: hostname}, DNSNames: []string{hostname},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, authority, &privateKey.PublicKey, authorityKey)
	if err != nil {
		t.Fatalf("issue relay certificate: %v", err)
	}
	privateKeyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal relay key: %v", err)
	}
	certificate, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKeyDER}),
	)
	if err != nil {
		t.Fatalf("parse relay key pair: %v", err)
	}
	return certificate
}

func newTestForwarder(t *testing.T, material forwardingTestMaterial) *Forwarder {
	t.Helper()
	forwarder, err := NewForwarder(ForwarderConfig{
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: material.roots}, ClusterSecret: forwardingClusterSecret,
	})
	if err != nil {
		t.Fatalf("NewForwarder: %v", err)
	}
	t.Cleanup(func() {
		if err := forwarder.Close(); err != nil && !errors.Is(err, muxsession.ErrClosed) && !errors.Is(err, io.EOF) {
			t.Errorf("Forwarder.Close: %v", err)
		}
	})
	return forwarder
}

type forwardingTestServer struct {
	listener net.Listener
	cancel   context.CancelFunc
	accepted atomic.Int32
	errors   chan error
	active   sync.WaitGroup
}

func startForwardingTestServer(t *testing.T, material forwardingTestMaterial, handle func(context.Context, muxsession.Session) error) *forwardingTestServer {
	t.Helper()
	return startForwardingTestServerWithCertificate(t, material, material.relay, handle)
}

func startForwardingTestServerWithCertificate(t *testing.T, material forwardingTestMaterial, certificate tls.Certificate, handle func(context.Context, muxsession.Session) error) *forwardingTestServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	server := &forwardingTestServer{listener: listener, cancel: cancel, errors: make(chan error, 16)}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
	done := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		ingressAwait(t, done)
		for err := range server.errors {
			t.Errorf("forwarding test server: %v", err)
		}
	})
	server.active.Add(1)
	go func() {
		defer func() { server.active.Done(); server.active.Wait(); close(server.errors); close(done) }()
		for {
			connection, err := listener.Accept()
			if err != nil {
				if ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
					server.errors <- err
				}
				return
			}
			server.active.Add(1)
			go func() {
				defer server.active.Done()
				defer connection.Close()
				stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
				defer stop()
				_ = connection.SetDeadline(time.Now().Add(fixtureTimeout))
				transport, err := muxsession.AcceptTLSYamux(ctx, connection, tlsConfig, muxsession.TLSYamuxConfig{})
				if err != nil {
					if ctx.Err() == nil {
						server.errors <- err
					}
					return
				}
				defer transport.Close()
				server.accepted.Add(1)
				if err := handle(ctx, transport); err != nil && ctx.Err() == nil {
					server.errors <- err
				}
			}()
		}
	}()
	return server
}

func (s *forwardingTestServer) address() string { return s.listener.Addr().String() }

func forwardingTestSecrets(t *testing.T) serverhttp.BearerSecrets {
	t.Helper()
	secrets, err := serverhttp.NewBearerSecrets(forwardingClusterSecret, "")
	if err != nil {
		t.Fatal(err)
	}
	return secrets
}
