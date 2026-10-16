package sshclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

type tlsFixture struct {
	roots          *x509.CertPool
	server, client tls.Certificate
}

func newTLSFixture(t *testing.T) tlsFixture {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	issue := func(serial int64, usage x509.ExtKeyUsage) tls.Certificate {
		pub, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: []string{"ssh.example"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{usage}, KeyUsage: x509.KeyUsageDigitalSignature}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, pub, key)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private}
	}
	return tlsFixture{roots: roots, server: issue(2, x509.ExtKeyUsageServerAuth), client: issue(3, x509.ExtKeyUsageClientAuth)}
}

func serveTLS(t *testing.T, fixture tlsFixture, handle func(*tls.Conn) error) (string, <-chan error) {
	t.Helper()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{fixture.server}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: fixture.roots})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	done := make(chan error, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer raw.Close()
		_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
		conn := raw.(*tls.Conn)
		if err := conn.Handshake(); err != nil {
			done <- err
			return
		}
		done <- handle(conn)
	}()
	return listener.Addr().String(), done
}

func TestConnectMutualTLSAndHalfClose(t *testing.T) {
	f := newTLSFixture(t)
	address, done := serveTLS(t, f, func(conn *tls.Conn) error {
		state := conn.ConnectionState()
		if state.ServerName != "ssh.example" || len(state.VerifiedChains) == 0 || !bytes.Equal(state.PeerCertificates[0].Raw, f.client.Certificate[0]) {
			return errors.New("missing exact SNI or verified client identity")
		}
		data, err := io.ReadAll(conn)
		if err != nil || string(data) != "request" {
			return fmt.Errorf("read request %q: %w", data, err)
		}
		// the reply is deliberately sent only after receiving the TLS half-close.
		_, err = io.WriteString(conn, "complete reply")
		return err
	})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var out bytes.Buffer
	err := ConnectWithOptions(ctx, ConnectOptions{Address: address, ServerName: "ssh.example", Certificate: f.client, RootCAs: f.roots}, strings.NewReader("request"), &out)
	if err != nil {
		t.Fatal(err)
	}
	if out.String() != "complete reply" {
		t.Fatal(out.String())
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestConnectRejectsUntrustedTLS(t *testing.T) {
	for _, kind := range []string{"hostname", "server root", "client identity"} {
		t.Run(kind, func(t *testing.T) {
			f := newTLSFixture(t)
			address, done := serveTLS(t, f, func(conn *tls.Conn) error { _, err := io.Copy(io.Discard, conn); return err })
			options := ConnectOptions{Address: address, ServerName: "ssh.example", Certificate: f.client, RootCAs: f.roots}
			switch kind {
			case "hostname":
				options.ServerName = "other.example"
			case "server root":
				options.RootCAs = x509.NewCertPool()
			case "client identity":
				options.Certificate = newTLSFixture(t).client
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			err := ConnectWithOptions(ctx, options, strings.NewReader("data"), io.Discard)
			if err == nil {
				t.Fatal("accepted untrusted TLS connection")
			}
			var owned *Error
			if !errors.As(err, &owned) {
				t.Fatalf("lost owned classification: %v", err)
			}
			if kind == "hostname" {
				var mismatch x509.HostnameError
				if !errors.As(err, &mismatch) {
					t.Fatalf("lost hostname cause: %v", err)
				}
			}
			if kind == "server root" {
				var untrusted x509.UnknownAuthorityError
				if !errors.As(err, &untrusted) {
					t.Fatalf("lost verification cause: %v", err)
				}
			}
			if err := <-done; err == nil {
				t.Fatal("server accepted untrusted connection")
			}
		})
	}
}

func TestConnectCancellationAndPeerEOFDontWaitForStdin(t *testing.T) {
	for _, cancelSession := range []bool{true, false} {
		t.Run(fmt.Sprintf("cancel=%t", cancelSession), func(t *testing.T) {
			f := newTLSFixture(t)
			ready := make(chan struct{})
			address, serverDone := serveTLS(t, f, func(conn *tls.Conn) error {
				close(ready)
				if cancelSession {
					_, err := io.Copy(io.Discard, conn)
					return err
				}
				return nil
			})
			stdin, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer stdin.Close()
			defer writer.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				done <- ConnectWithOptions(ctx, ConnectOptions{Address: address, ServerName: "ssh.example", Certificate: f.client, RootCAs: f.roots}, stdin, io.Discard)
			}()
			select {
			case <-ready:
			case <-ctx.Done():
				t.Fatal("TLS did not become ready")
			}
			if cancelSession {
				cancel()
			}
			select {
			case err := <-done:
				if cancelSession && !errors.Is(err, context.Canceled) || !cancelSession && err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("blocked stdin prevented session completion")
			}
			// callers unblock their owned stdio after the transport returns.
			_ = stdin.Close()
			select {
			case <-serverDone:
			case <-time.After(2 * time.Second):
				t.Fatal("network connection was not closed")
			}
		})
	}
}

type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

func TestConnectPreservesStdioFailure(t *testing.T) {
	f := newTLSFixture(t)
	address, done := serveTLS(t, f, func(conn *tls.Conn) error { _, err := io.Copy(io.Discard, conn); return err })
	cause := errors.New("private reader detail")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	err := ConnectWithOptions(ctx, ConnectOptions{Address: address, ServerName: "ssh.example", Certificate: f.client, RootCAs: f.roots}, failingReader{cause}, io.Discard)
	if !errors.Is(err, cause) || strings.Contains(err.Error(), cause.Error()) {
		t.Fatalf("cause not retained safely: %v", err)
	}
	<-done
}

func TestConnectCancelsHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	f := newTLSFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- Connect(ctx, listener.Addr().String(), "ssh.example", f.client, strings.NewReader(""), io.Discard)
	}()
	select {
	case conn := <-accepted:
		defer conn.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("connection not accepted")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("TLS handshake did not cancel")
	}
}
