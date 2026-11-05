package muxsession

import (
	"bytes"
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
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
)

type pairFactory func(*testing.T) (Session, Session)

// a basic UDP listener survives a bounded amount
// of packet loss while held streams and fresh responses share a QUIC session.
func TestQUICHeldAndFreshStreamsWithPacketLoss(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	serverTLS, err := transportTLSConfig(serverTLS, "", true)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	impaired := &impairedQUICPacketConn{PacketConn: packet}
	transport := &quic.Transport{Conn: impaired}
	defer transport.Close()
	listener, err := transport.Listen(serverTLS, quicConfig(nil))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	accepted := make(chan *quic.Conn, 1)
	acceptErrors := make(chan error, 1)
	go func() {
		connection, err := listener.Accept(ctx)
		if err != nil {
			acceptErrors <- err
			return
		}
		accepted <- connection
	}()
	client, err := (QUICConnector{TLSConfig: clientTLS}).Connect(ctx, Endpoint{
		Address: packet.LocalAddr().String(), ServerName: "relay.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var server Session
	select {
	case conn := <-accepted:
		server = &quicSession{connection: conn}
	case err := <-acceptErrors:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()
	impaired.enabled.Store(true)

	const held, fresh = 4, 100
	response := bytes.Repeat([]byte("r"), 4096)
	serverErrors := make(chan error, fresh+held)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		var workers sync.WaitGroup
		defer workers.Wait()
		for range held + fresh {
			stream, err := server.AcceptStream(ctx)
			if err != nil {
				serverErrors <- err
				return
			}
			workers.Go(func() {
				defer stream.Close()
				_ = stream.SetDeadline(time.Now().Add(15 * time.Second))
				kind := make([]byte, 1)
				if _, err := io.ReadFull(stream, kind); err != nil {
					serverErrors <- err
					return
				}
				if kind[0] == 'h' {
					_, _ = io.Copy(io.Discard, stream)
					return
				}
				request := make([]byte, len(response))
				if _, err := io.ReadFull(stream, request); err != nil {
					serverErrors <- err
					return
				}
				if _, err := stream.Write(response); err != nil {
					serverErrors <- err
					return
				}
				if err := stream.CloseWrite(); err != nil {
					serverErrors <- err
				}
			})
		}
	}()
	heldStreams := make([]Stream, held)
	for index := range heldStreams {
		stream, err := client.OpenStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer stream.Close()
		if _, err := stream.Write([]byte("h")); err != nil {
			t.Fatal(err)
		}
		heldStreams[index] = stream
	}
	clientErrors := make(chan error, fresh)
	var clients sync.WaitGroup
	sem := make(chan struct{}, 32)
	start := time.Now()
	for index := range fresh {
		at := start.Add(time.Duration(index) * 10 * time.Millisecond)
		if delay := time.Until(at); delay > 0 {
			time.Sleep(delay)
		}
		clients.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			stream, err := client.OpenStream(ctx)
			if err != nil {
				clientErrors <- err
				return
			}
			defer stream.Close()
			_ = stream.SetDeadline(time.Now().Add(15 * time.Second))
			if _, err := stream.Write(append([]byte("f"), response...)); err != nil {
				clientErrors <- err
				return
			}
			if err := stream.CloseWrite(); err != nil {
				clientErrors <- err
				return
			}
			got := make([]byte, len(response))
			if _, err := io.ReadFull(stream, got); err != nil {
				clientErrors <- err
				return
			}
			if !bytes.Equal(got, response) {
				clientErrors <- errors.New("incorrect QUIC stream response")
			}
		})
	}
	clients.Wait()
	for _, stream := range heldStreams {
		if _, err := stream.Write([]byte("h")); err != nil {
			t.Errorf("held stream ended: %v", err)
		}
		_ = stream.CloseWrite()
	}
	select {
	case <-serverDone:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	close(clientErrors)
	for err := range clientErrors {
		t.Error(err)
	}
	close(serverErrors)
	for err := range serverErrors {
		t.Error(err)
	}
	if impaired.dropped.Load() == 0 {
		t.Fatal("packet loss was not exercised")
	}
}

type impairedQUICPacketConn struct {
	net.PacketConn
	enabled atomic.Bool
	packets atomic.Uint64
	dropped atomic.Uint64
}

func (c *impairedQUICPacketConn) WriteTo(p []byte, address net.Addr) (int, error) {
	if c.enabled.Load() {
		time.Sleep(2 * time.Millisecond)
		if c.packets.Add(1)%60 == 0 {
			c.dropped.Add(1)
			return len(p), nil
		}
	}
	return c.PacketConn.WriteTo(p, address)
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

func TestQUICConnectorConfig(t *testing.T) {
	if got := quicConnectorConfig(nil).InitialPacketSize; got != compatibleQUICPacketSize {
		t.Errorf("default initial packet size = %d; want %d", got, compatibleQUICPacketSize)
	}
	config := &quic.Config{InitialPacketSize: 1300}
	if got := quicConnectorConfig(config).InitialPacketSize; got != 1300 {
		t.Errorf("explicit initial packet size = %d; want 1300", got)
	}
	if config.InitialPacketSize != 1300 {
		t.Fatal("caller QUIC config was modified")
	}
}

func TestQUICListenerSocketModes(t *testing.T) {
	for _, basic := range []bool{false, true} {
		t.Run(fmt.Sprintf("basic=%t", basic), func(t *testing.T) {
			config := QUICConfig{Config: &quic.Config{EnableDatagrams: true}}
			if basic {
				config.UDPNetwork = "udp4"
				config.BasicPacketConn = true
				config.Config.InitialPacketSize = 1200
				config.Config.DisablePathMTUDiscovery = true
			}
			testQUICListenerSocketMode(t, config)
		})
	}
}

func testQUICListenerSocketMode(t *testing.T, config QUICConfig) {
	t.Helper()
	serverTLS, clientTLS := testTLSConfigs(t)
	wrapped, err := ListenQUIC("127.0.0.1:0", serverTLS, config)
	if err != nil {
		t.Fatalf("listen QUIC: %v", err)
	}
	t.Cleanup(func() { _ = wrapped.Close() })
	address := wrapped.Addr().String()
	_, ordinaryUDP := wrapped.transport.Conn.(*net.UDPConn)
	if ordinaryUDP == config.BasicPacketConn {
		t.Fatalf("ordinary UDP capabilities = %t; basic packet connection = %t", ordinaryUDP, config.BasicPacketConn)
	}
	if wrapped.packetConn.LocalAddr().(*net.UDPAddr).IP.To4() == nil {
		t.Fatal("listener did not bind IPv4")
	}
	if config.Config.Allow0RTT || config.Config.MaxIncomingStreams != 0 {
		t.Fatal("caller QUIC config was modified")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	type acceptResult struct {
		session Session
		err     error
	}
	accepted := make(chan acceptResult, 1)
	joined := make(chan struct{})
	t.Cleanup(func() { cancel(); _ = wrapped.Close(); muxAwait(t, joined) })
	go func() {
		defer close(joined)
		connection, err := wrapped.Accept(ctx)
		if connection != nil {
			defer connection.Close()
		}
		accepted <- acceptResult{session: connection, err: err}
		if err == nil {
			<-ctx.Done()
		}
	}()
	client, err := (QUICConnector{TLSConfig: clientTLS, Config: QUICConfig{Config: &quic.Config{EnableDatagrams: true}}}).Connect(ctx, Endpoint{
		Address: address, ServerName: "relay.test",
	})
	if err != nil {
		t.Fatalf("connect QUIC: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	// dialing can return before the server has accepted the connection. keep both
	// sessions alive until acceptance is observed before testing closure.
	server := muxAwait(t, accepted)
	if server.err != nil {
		t.Fatalf("accept QUIC: %v", server.err)
	}
	state := client.(AcceptedPeer).TLSConnectionState()
	if len(state.VerifiedChains) == 0 || state.ServerName != "relay.test" || state.NegotiatedProtocol != ALPN || state.Version != tls.VersionTLS13 {
		t.Fatal("client lost verified relay TLS identity or ALPN")
	}
	for _, pair := range [][2]Session{{client, server.session}, {server.session, client}} {
		sender, receiver := pair[0].(DatagramSession), pair[1].(DatagramSession)
		if !sender.SupportsDatagrams() {
			t.Fatal("QUIC DATAGRAMs were not negotiated")
		}
		if err := sender.SendDatagram(ctx, []byte("packet")); err != nil {
			t.Fatal(err)
		}
		if got, err := receiver.ReceiveDatagram(ctx); err != nil || string(got) != "packet" {
			t.Fatalf("receive datagram = %q, %v", got, err)
		}
	}
	if err := wrapped.StopAccepting(); err != nil {
		t.Fatal(err)
	}
	assertRoundTrip(t, client, server.session, "drain QUIC")
	if err := client.Close(); err != nil {
		t.Fatalf("close client: %v", err)
	}
	if err := server.session.Close(); err != nil && !errors.Is(err, ErrClosed) {
		t.Fatalf("close server: %v", err)
	}
	cancel()
	muxAwait(t, joined)
	if err := wrapped.Close(); err != nil {
		t.Fatalf("close QUIC listener: %v", err)
	}
	reopened, err := net.ListenPacket("udp4", address)
	if err != nil {
		t.Fatalf("reopen UDP after listener close: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if err := reopened.Close(); err != nil {
		t.Fatalf("close reopened UDP socket: %v", err)
	}
}

func TestQUICListenerUDPNetwork(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)
	if listener, err := ListenQUIC("[::1]:0", serverTLS, QUICConfig{UDPNetwork: "udp4"}); err == nil {
		_ = listener.Close()
		t.Fatal("IPv4 listener accepted an IPv6 listen address")
	}
}

func assertRoundTrip(t *testing.T, client, server Session, message string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	clientStream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	defer clientStream.Close()
	_ = clientStream.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := clientStream.Write([]byte(message)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	if err := clientStream.CloseWrite(); err != nil {
		t.Fatalf("close request: %v", err)
	}

	serverStream, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("AcceptStream: %v", err)
	}
	defer serverStream.Close()
	_ = serverStream.SetDeadline(time.Now().Add(5 * time.Second))
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
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	serverJoined, clientsJoined := make(chan struct{}), make(chan struct{})
	t.Cleanup(func() {
		cancel()
		_ = client.Close()
		_ = server.Close()
		muxAwait(t, clientsJoined)
		muxAwait(t, serverJoined)
	})
	errorsFound := make(chan error, 2*count)
	serverDone := make(chan error, 1)
	go func() {
		defer close(serverJoined)
		var workers sync.WaitGroup
		defer workers.Wait()
		for range count {
			stream, err := server.AcceptStream(ctx)
			if err != nil {
				serverDone <- err
				return
			}
			workers.Go(func() {
				defer stream.Close()
				_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
				request, err := io.ReadAll(stream)
				if err == nil {
					_, err = stream.Write(request)
				}
				if err == nil {
					err = stream.CloseWrite()
				}
				if err != nil {
					errorsFound <- err
					_ = stream.Reset(1)
				}
			})
		}
		workers.Wait()
		serverDone <- nil
	}()

	var clients sync.WaitGroup
	for index := range count {
		clients.Go(func() {
			stream, err := client.OpenStream(ctx)
			if err != nil {
				errorsFound <- err
				return
			}
			defer stream.Close()
			_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
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
	go func() { clients.Wait(); close(clientsJoined) }()
	muxAwait(t, clientsJoined)
	if err := muxAwait(t, serverDone); err != nil {
		t.Fatalf("server: %v", err)
	}
	close(errorsFound)
	for err := range errorsFound {
		t.Error(err)
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
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	done := make(chan struct{})
	t.Cleanup(func() { cancel(); _ = listener.Close(); muxAwait(t, done) })

	type result struct {
		session Session
		err     error
	}
	accepted := make(chan result, 1)
	go func() {
		defer close(done)
		session, err := listener.Accept(ctx)
		if session != nil {
			defer session.Close()
		}
		accepted <- result{session: session, err: err}
		if err == nil {
			<-ctx.Done()
		}
	}()
	client, err := (QUICConnector{TLSConfig: clientTLS, Config: QUICConfig{Config: clientConfig}}).Connect(ctx, Endpoint{
		Address: listener.Addr().String(), ServerName: "relay.test",
	})
	if err != nil {
		t.Fatalf("connect QUIC: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
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
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	done := make(chan struct{})
	t.Cleanup(func() { cancel(); _ = listener.Close(); muxAwait(t, done) })

	type result struct {
		session Session
		err     error
	}
	accepted := make(chan result, 1)
	go func() {
		defer close(done)
		connection, err := listener.Accept()
		if err != nil {
			accepted <- result{err: err}
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
		session, err := AcceptTLSYamux(ctx, connection, serverTLS, TLSYamuxConfig{})
		if session != nil {
			defer session.Close()
		}
		accepted <- result{session: session, err: err}
		if err == nil {
			<-ctx.Done()
		}
	}()
	client, err := (TLSYamuxConnector{TLSConfig: clientTLS}).Connect(ctx, Endpoint{
		Address: listener.Addr().String(), ServerName: "relay.test",
	})
	if err != nil {
		t.Fatalf("connect TLS/yamux: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
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
	t.Cleanup(func() { _ = server.Close() })
	return client, server
}

func testTLSConfigs(t testing.TB) (*tls.Config, *tls.Config) {
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
