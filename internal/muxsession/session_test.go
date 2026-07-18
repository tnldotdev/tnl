package muxsession

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
)

type pairFactory func(*testing.T) (Session, Session)

func TestSessionContract(t *testing.T) {
	factories := map[string]pairFactory{
		"quic":      newQUICPair,
		"tls_yamux": newTLSYamuxPair,
	}
	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			t.Run("full duplex and half close", func(t *testing.T) {
				client, server := factory(t)
				assertRoundTrip(t, client, server, "hello")
			})
			t.Run("concurrent streams", func(t *testing.T) {
				client, server := factory(t)
				assertConcurrentStreams(t, client, server)
			})
			t.Run("accept cancellation", func(t *testing.T) {
				_, server := factory(t)
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				if _, err := server.AcceptStream(ctx); !errors.Is(err, context.Canceled) {
					t.Fatalf("AcceptStream error = %v; want context.Canceled", err)
				}
			})
			t.Run("close unblocks accept", func(t *testing.T) {
				_, server := factory(t)
				result := make(chan error, 1)
				go func() {
					_, err := server.AcceptStream(context.Background())
					result <- err
				}()
				if err := server.Close(); err != nil {
					t.Fatalf("Close: %v", err)
				}
				select {
				case err := <-result:
					if !errors.Is(err, ErrClosed) {
						t.Fatalf("AcceptStream error = %v; want ErrClosed", err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("AcceptStream remained blocked after session close")
				}
			})
			t.Run("reset isolates stream", func(t *testing.T) {
				client, server := factory(t)
				stream, err := client.OpenStream(t.Context())
				if err != nil {
					t.Fatalf("OpenStream: %v", err)
				}
				if _, err := stream.Write([]byte("x")); err != nil {
					t.Fatalf("Write: %v", err)
				}
				peer, err := server.AcceptStream(t.Context())
				if err != nil {
					t.Fatalf("AcceptStream: %v", err)
				}
				if err := stream.Reset(7); err != nil {
					t.Fatalf("Reset: %v", err)
				}
				_ = peer.Close()
				assertRoundTrip(t, client, server, "still alive")
			})
		})
	}
}

func TestQUICConnectorKeepsIdleSessionAlive(t *testing.T) {
	const idleTimeout = time.Second
	clientConfig := &quic.Config{MaxIdleTimeout: idleTimeout}
	client, server := newQUICPairWithConfig(t, &quic.Config{MaxIdleTimeout: idleTimeout}, clientConfig)

	time.Sleep(2 * idleTimeout)
	assertRoundTrip(t, client, server, "after idle")
	if clientConfig.KeepAlivePeriod != 0 {
		t.Fatalf("caller QUIC keepalive period = %s; want unchanged zero value", clientConfig.KeepAlivePeriod)
	}
}

func assertRoundTrip(t *testing.T, client, server Session, message string) {
	t.Helper()
	clientStream, err := client.OpenStream(t.Context())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	defer clientStream.Close()
	if _, err := clientStream.Write([]byte(message)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	if err := clientStream.CloseWrite(); err != nil {
		t.Fatalf("close request: %v", err)
	}

	serverStream, err := server.AcceptStream(t.Context())
	if err != nil {
		t.Fatalf("AcceptStream: %v", err)
	}
	defer serverStream.Close()
	request, err := io.ReadAll(serverStream)
	if err != nil {
		t.Fatalf("read request: %v", err)
	}
	if string(request) != message {
		t.Fatalf("request = %q; want %q", request, message)
	}
	if _, err := serverStream.Write([]byte("reply: " + message)); err != nil {
		t.Fatalf("write response: %v", err)
	}
	if err := serverStream.CloseWrite(); err != nil {
		t.Fatalf("close response: %v", err)
	}
	response, err := io.ReadAll(clientStream)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if want := "reply: " + message; string(response) != want {
		t.Fatalf("response = %q; want %q", response, want)
	}
}

func assertConcurrentStreams(t *testing.T, client, server Session) {
	t.Helper()
	const count = 16
	serverDone := make(chan error, 1)
	go func() {
		var workers sync.WaitGroup
		for range count {
			stream, err := server.AcceptStream(context.Background())
			if err != nil {
				serverDone <- err
				return
			}
			workers.Go(func() {
				defer stream.Close()
				request, err := io.ReadAll(stream)
				if err == nil {
					_, err = stream.Write(request)
				}
				if err == nil {
					err = stream.CloseWrite()
				}
				if err != nil {
					_ = stream.Reset(1)
				}
			})
		}
		workers.Wait()
		serverDone <- nil
	}()

	var clients sync.WaitGroup
	errorsFound := make(chan error, count)
	for index := range count {
		clients.Go(func() {
			stream, err := client.OpenStream(context.Background())
			if err != nil {
				errorsFound <- err
				return
			}
			defer stream.Close()
			message := fmt.Sprintf("stream-%d", index)
			if _, err := stream.Write([]byte(message)); err != nil {
				errorsFound <- err
				return
			}
			if err := stream.CloseWrite(); err != nil {
				errorsFound <- err
				return
			}
			response, err := io.ReadAll(stream)
			if err != nil {
				errorsFound <- err
				return
			}
			if string(response) != message {
				errorsFound <- fmt.Errorf("response = %q; want %q", response, message)
			}
		})
	}
	clients.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Error(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server: %v", err)
	}
}

func newQUICPair(t *testing.T) (Session, Session) {
	t.Helper()
	return newQUICPairWithConfig(t, nil, nil)
}

func newQUICPairWithConfig(t *testing.T, serverConfig, clientConfig *quic.Config) (Session, Session) {
	t.Helper()
	serverTLS, clientTLS := testTLSConfigs(t)
	listener, err := ListenQUIC("127.0.0.1:0", serverTLS, QUICConfig{Config: serverConfig})
	if err != nil {
		t.Fatalf("ListenQUIC: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	type result struct {
		session Session
		err     error
	}
	accepted := make(chan result, 1)
	go func() {
		session, err := listener.Accept(context.Background())
		accepted <- result{session: session, err: err}
	}()
	client, err := (QUICConnector{TLSConfig: clientTLS, Config: QUICConfig{Config: clientConfig}}).Connect(t.Context(), Endpoint{
		Address: listener.Addr().String(), ServerName: "relay.test",
	})
	if err != nil {
		t.Fatalf("connect QUIC: %v", err)
	}
	var server Session
	select {
	case result := <-accepted:
		if result.err != nil {
			t.Fatalf("accept QUIC: %v", result.err)
		}
		server = result.session
	case <-time.After(5 * time.Second):
		t.Fatal("accept QUIC timed out")
	}
	t.Cleanup(func() { _ = client.Close() })
	t.Cleanup(func() { _ = server.Close() })
	return client, server
}

func newTLSYamuxPair(t *testing.T) (Session, Session) {
	t.Helper()
	serverTLS, clientTLS := testTLSConfigs(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen TCP: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	type result struct {
		session Session
		err     error
	}
	accepted := make(chan result, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			accepted <- result{err: err}
			return
		}
		session, err := AcceptTLSYamux(context.Background(), connection, serverTLS, TLSYamuxConfig{})
		accepted <- result{session: session, err: err}
	}()
	client, err := (TLSYamuxConnector{TLSConfig: clientTLS}).Connect(t.Context(), Endpoint{
		Address: listener.Addr().String(), ServerName: "relay.test",
	})
	if err != nil {
		t.Fatalf("connect TLS/yamux: %v", err)
	}
	var server Session
	select {
	case result := <-accepted:
		if result.err != nil {
			t.Fatalf("accept TLS/yamux: %v", result.err)
		}
		server = result.session
	case <-time.After(5 * time.Second):
		t.Fatal("accept TLS/yamux timed out")
	}
	t.Cleanup(func() { _ = client.Close() })
	t.Cleanup(func() { _ = server.Close() })
	return client, server
}

func testTLSConfigs(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "relay.test"},
		DNSNames:     []string{"relay.test"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	roots := x509.NewCertPool()
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	roots.AddCert(certificate)
	server := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: privateKey}}}
	client := &tls.Config{RootCAs: roots}
	return server, client
}
