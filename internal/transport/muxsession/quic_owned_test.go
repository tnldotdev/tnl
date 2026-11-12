package muxsession

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
)

type ownedQUICClosePacket struct {
	net.PacketConn
	err    error
	closes atomic.Int32
}

func (p *ownedQUICClosePacket) Close() error {
	p.closes.Add(1)
	return errors.Join(p.PacketConn.Close(), p.err)
}

func ownedQUICTransport(t *testing.T, closeErr error) (*QUICTransport, *ownedQUICClosePacket) {
	t.Helper()
	transport, err := ListenQUICTransport("udp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	// leave quic-go's actual socket unchanged; observe only the owner's Close.
	packet := &ownedQUICClosePacket{PacketConn: transport.packet, err: closeErr}
	transport.packet = packet
	t.Cleanup(func() { _ = transport.Close() })
	return transport, packet
}

func assertOwnedQUICSocketClosed(t *testing.T, packet *ownedQUICClosePacket) {
	t.Helper()
	if packet.closes.Load() != 1 {
		t.Fatal("owned UDP socket was not closed exactly once", packet.closes.Load())
	}
	if _, err := packet.WriteTo([]byte("closed"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}); !errors.Is(err, net.ErrClosed) {
		t.Fatal("owned UDP socket is still writable after cleanup", err)
	}
}

func TestQUICOwnedFailedDialClosesSocketAndKeepsCleanupError(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	serverTLS, clientTLS := testTLSConfigs(t)
	listener, err := ListenQUIC("127.0.0.1:0", serverTLS, QUICConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	closeErr := errors.New("owned packet close failed")
	transport, packet := ownedQUICTransport(t, closeErr)
	session, err := (OwnedQUICConnector{TLSConfig: clientTLS}).connect(ctx, Endpoint{Address: listener.Addr().String(), ServerName: "wrong.example"}, transport)
	var hostname x509.HostnameError
	var cleanup *QUICTransportCloseError
	if session != nil || !errors.As(err, &hostname) || !errors.As(err, &cleanup) || !errors.Is(err, closeErr) {
		t.Fatal("failed owned dial lost its TLS or socket cleanup error", err)
	}
	assertOwnedQUICSocketClosed(t, packet)
	if err := transport.Close(); !errors.Is(err, closeErr) || packet.closes.Load() != 1 {
		t.Fatal("failed attempt left another closing owner", err)
	}
	// the exported connector must return a nil interface, not a typed nil.
	if session, err := (OwnedQUICConnector{}).Connect(ctx, Endpoint{}); session != nil || err == nil {
		t.Fatal("invalid owned dial returned a session", session, err)
	}
}

func TestQUICOwnedCanceledDialClosesSocketAndJoinsCauses(t *testing.T) {
	ctx, stop := context.WithTimeout(t.Context(), 5*time.Second)
	defer stop()
	remote, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	if err := remote.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, clientTLS := testTLSConfigs(t)
	closeErr := errors.New("canceled packet close failed")
	cause := errors.New("publisher stopped")
	transport, packet := ownedQUICTransport(t, closeErr)
	dialCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(cause)
	done := make(chan error, 1)
	go func() {
		session, err := (OwnedQUICConnector{TLSConfig: clientTLS}).connect(dialCtx, Endpoint{Address: remote.LocalAddr().String(), ServerName: "relay.test"}, transport)
		if session != nil {
			err = errors.Join(errors.New("canceled dial returned a session"), session.Close())
		}
		done <- err
	}()
	if _, _, err := remote.ReadFrom(make([]byte, 1500)); err != nil {
		t.Fatal("owned dial did not enter UDP", err)
	}
	cancel(cause)
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || !errors.Is(err, cause) || !errors.Is(err, closeErr) {
			t.Fatal("canceled owned dial lost cancellation or cleanup identity", err)
		}
	case <-ctx.Done():
		t.Fatal("canceled owned dial did not join")
	}
	assertOwnedQUICSocketClosed(t, packet)
	if session, err := (OwnedQUICConnector{}).Connect(dialCtx, Endpoint{}); session != nil || !errors.Is(err, context.Canceled) || !errors.Is(err, cause) {
		t.Fatal("already canceled owned dial lost its causes", err)
	}
}

func TestQUICOwnedSessionKeepsNativeCapabilitiesAndSocketUntilClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	serverTLS, clientTLS := testTLSConfigs(t)
	config := QUICConfig{Config: &quic.Config{EnableDatagrams: true}}
	listener, err := ListenQUIC("127.0.0.1:0", serverTLS, config)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	closeErr := errors.New("session packet close failed")
	dialCtx, finishDial := context.WithCancel(ctx)
	session, err := (OwnedQUICConnector{TLSConfig: clientTLS, Config: config}).Connect(dialCtx, Endpoint{Address: listener.Addr().String(), ServerName: "relay.test"})
	finishDial()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	native, ok := session.(*quicSession)
	if !ok || native.owned == nil {
		t.Fatal("owned connector did not return a native session with its UDP owner")
	}
	transport := native.owned
	packet := &ownedQUICClosePacket{PacketConn: transport.packet, err: closeErr}
	transport.packet = packet
	server, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if packet.closes.Load() != 0 {
		t.Fatal("successful QUIC did not retain its concrete UDP owner")
	}
	peer := session.(AcceptedPeer)
	if peer.LocalAddr().String() != transport.LocalAddr().String() || peer.TLSConnectionState().NegotiatedProtocol != ALPN || session.(IPBoundPeer).RemoteIPBound() {
		t.Fatal("owned session lost its native peer capabilities")
	}
	assertRoundTrip(t, session, server, "owned socket remains live after dial cancellation")
	datagrams := session.(DatagramSession)
	if !datagrams.SupportsDatagrams() {
		t.Fatal("owned session lost its native datagram capability")
	}
	if err := datagrams.SendDatagram(ctx, []byte("owned datagram")); err != nil {
		t.Fatal(err)
	}
	if got, err := server.(DatagramSession).ReceiveDatagram(ctx); err != nil || string(got) != "owned datagram" {
		t.Fatal("owned datagram did not arrive", string(got), err)
	}
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			var cleanup *QUICTransportCloseError
			if err := session.Close(); !errors.Is(err, closeErr) || !errors.As(err, &cleanup) {
				t.Error("concurrent session close lost its cleanup error", err)
			}
		})
	}
	workers.Wait()
	assertOwnedQUICSocketClosed(t, packet)
}

func TestQUICBorrowedSessionsNeverAcquireSocketOwnership(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	serverTLS, clientTLS := testTLSConfigs(t)
	listener, err := ListenQUIC("127.0.0.1:0", serverTLS, QUICConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	transport, packet := ownedQUICTransport(t, nil)
	connector := QUICConnector{TLSConfig: clientTLS, Dialer: transport}
	endpoint := Endpoint{Address: listener.Addr().String(), ServerName: "wrong.example"}
	if session, err := connector.Connect(ctx, endpoint); session != nil || err == nil || packet.closes.Load() != 0 {
		t.Fatal("failed borrowed dial acquired the transport owner", err)
	}
	endpoint.ServerName = "relay.test"
	for range 2 {
		session, err := connector.Connect(ctx, endpoint)
		if err != nil {
			t.Fatal(err)
		}
		server, err := listener.Accept(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if session.(*quicSession).owned != nil {
			t.Fatal("borrowed session gained another socket closing owner")
		}
		assertRoundTrip(t, session, server, "borrowed socket can be reused")
		if err := session.Close(); err != nil || packet.closes.Load() != 0 {
			t.Fatal("borrowed session closed its owner's socket", err)
		}
		_ = server.Close()
	}
	if err := transport.Close(); err != nil {
		t.Fatal(err)
	}
	assertOwnedQUICSocketClosed(t, packet)
}
