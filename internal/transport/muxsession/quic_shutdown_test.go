package muxsession

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestQUICListenerCloseReleasesAcceptedSocket(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	listener, err := ListenQUIC("127.0.0.1:0", serverTLS, QUICConfig{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	type acceptedSession struct {
		session Session
		err     error
	}
	accepted := make(chan acceptedSession, 1)
	joined := make(chan struct{})
	t.Cleanup(func() { cancel(); _ = listener.Close(); muxAwait(t, joined) })
	go func() {
		defer close(joined)
		session, err := listener.Accept(ctx)
		accepted <- acceptedSession{session, err}
	}()
	client, err := (QUICConnector{TLSConfig: clientTLS}).Connect(ctx, Endpoint{Address: listener.Addr().String(), ServerName: "relay.test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	server := muxAwait(t, accepted)
	if server.err != nil {
		t.Fatal(server.err)
	}
	t.Cleanup(func() { _ = server.session.Close() })
	if err := listener.StopAccepting(); err != nil {
		t.Fatal(err)
	}
	assertRoundTrip(t, client, server.session, "drain accepted QUIC")
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	rebound, err := net.ListenPacket("udp", address)
	if err != nil {
		t.Fatalf("UDP socket retained after listener close: %v", err)
	}
	_ = rebound.Close()
	if err := listener.Close(); err != nil {
		t.Fatalf("repeated close: %v", err)
	}
}
