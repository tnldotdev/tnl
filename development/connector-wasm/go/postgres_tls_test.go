package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestPostgresTLSUsesSSLRequestAndVerifiesServiceCertificate(t *testing.T) {
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "service.test"}, DNSNames: []string{"service.test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, public, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	for _, name := range []string{"service.test", "wrong.test"} {
		t.Run(name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				var request [8]byte
				if _, err := io.ReadFull(server, request[:]); err != nil {
					done <- err
					return
				}
				if !bytes.Equal(request[:], []byte{0, 0, 0, 8, 4, 210, 22, 47}) {
					t.Error("startup bytes preceded postgres SSLRequest")
				}
				if _, err := server.Write([]byte{'S'}); err != nil {
					done <- err
					return
				}
				secure := tls.Server(server, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12})
				done <- secure.HandshakeContext(ctx)
			}()
			secure, err := postgresTLS(ctx, client, &tls.Config{RootCAs: pool, ServerName: name, MinVersion: tls.VersionTLS12})
			if name == "service.test" {
				if err != nil {
					t.Fatal(err)
				}
				_ = secure.NetConn().Close()
			} else if err == nil {
				t.Fatal("wrong service certificate accepted")
			}
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal("TLS negotiation did not join")
			}
		})
	}
}

func TestPostgresTLSRefusalAndCancellationSendNoStartup(t *testing.T) {
	for _, refuse := range []bool{false, true} {
		client, server := net.Pipe()
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		done := make(chan struct{})
		go func() {
			defer close(done)
			var request [8]byte
			_, _ = io.ReadFull(server, request[:])
			if refuse {
				_, _ = server.Write([]byte{'N'})
			}
			var extra [1]byte
			if n, _ := server.Read(extra[:]); n != 0 {
				t.Error("application bytes sent without verified TLS")
			}
		}()
		if _, err := postgresTLS(ctx, client, &tls.Config{ServerName: "service.test"}); err == nil {
			t.Fatal("unverified postgres stream promoted")
		} else if !refuse && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("postgres negotiation lost its deadline cause", err)
		}
		cancel()
		_ = client.Close()
		_ = server.Close()
		<-done
	}
}

func TestPostgresTLSRetainsExplicitCancellationCauseDuringSSLResponseRead(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(context.Canceled)
	result := make(chan error, 1)
	go func() {
		_, err := postgresTLS(ctx, client, &tls.Config{ServerName: "service.test"})
		result <- err
	}()
	if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var request [8]byte
	if _, err := io.ReadFull(server, request[:]); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("fixture authority cancelled")
	cancel(sentinel)
	select {
	case err := <-result:
		if !errors.Is(err, sentinel) {
			t.Fatal("SSLResponse read lost the original cancellation cause", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled SSLResponse read did not join")
	}
	var extra [1]byte
	if n, _ := server.Read(extra[:]); n != 0 {
		t.Fatal("application bytes sent after cancellation")
	}
}
