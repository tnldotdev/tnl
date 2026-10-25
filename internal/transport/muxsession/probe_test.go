package muxsession

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"
)

func TestRelayProbeCancellationInterruptsEstablishedNonceRead(t *testing.T) {
	serverConfig, clientConfig := testTLSConfigs(t)
	clientConfig.NextProtos = []string{ProbeALPN}
	clientConfig.ServerName = "relay.test"
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		server, err := listener.Accept()
		if err != nil {
			finished <- err
			return
		}
		_, _, err = AcceptTLSYamuxOrProbe(ctx, server, serverConfig, TLSYamuxConfig{})
		finished <- err
	}()
	client, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	secure := tls.Client(client, clientConfig)
	if err := secure.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	if secure.ConnectionState().NegotiatedProtocol != ProbeALPN {
		t.Fatal("probe did not negotiate the exact ALPN")
	}
	// the peer holds the connection open without sending any nonce bytes.
	cancel()
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("canceled probe completed without a nonce")
		}
	case <-time.After(time.Second):
		t.Fatal("probe remained blocked on a nonce after cancellation")
	}
}
