package muxsession

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
)

func TestSharedQUICListenerAcceptsOnlyTunnelALPNs(t *testing.T) {
	serverTLS, roots := testTLSConfigs(t)
	listener, err := ListenQUICProtocols("127.0.0.1:0", serverTLS, QUICConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for _, candidate := range []struct {
		connector Connector
		alpn      string
	}{
		{QUICConnector{TLSConfig: roots}, ALPN}, {PrivateQUICConnector{TLSConfig: roots}, PrivateALPN},
	} {
		client, err := candidate.connector.Connect(ctx, Endpoint{Address: listener.Addr().String(), ServerName: "relay.test"})
		if err != nil {
			t.Fatal(err)
		}
		server, err := listener.Accept(ctx)
		if err != nil {
			t.Fatal(err)
		}
		state := server.(interface{ TLSConnectionState() tls.ConnectionState }).TLSConnectionState()
		if state.NegotiatedProtocol != candidate.alpn || state.ServerName != "relay.test" {
			t.Fatalf("shared listener lost its verified role: %+v", state)
		}
		_ = client.Close()
		_ = server.Close()
	}
	unknown := roots.Clone()
	unknown.ServerName, unknown.NextProtos = "relay.test", []string{"unrecognized/1"}
	if peer, err := quic.DialAddr(ctx, listener.Addr().String(), unknown, nil); err == nil {
		_ = peer.CloseWithError(0, "")
		t.Fatal("shared infrastructure accepted an unknown ALPN")
	}
}
