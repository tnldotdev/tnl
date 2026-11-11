package muxsession

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func testQUICTransport(t testing.TB) *QUICTransport {
	t.Helper()
	transport, err := ListenQUICTransport("udp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := transport.Close(); err != nil {
			t.Error(err)
		}
	})
	return transport
}

func TestQUICConnectorRequiresBorrowedDialer(t *testing.T) {
	_, roots := testTLSConfigs(t)
	_, err := (QUICConnector{TLSConfig: roots}).Connect(t.Context(), Endpoint{Address: "127.0.0.1:1", ServerName: "relay.test"})
	if err == nil || !strings.Contains(err.Error(), "owner-supplied dialer") {
		t.Fatal("connector without a dialer did not fail before dialing", err)
	}
}

func TestQUICTransportSharesSocketUntilOwnerCloses(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	serverTLS, clientTLS := testTLSConfigs(t)
	listener, err := ListenQUIC("127.0.0.1:0", serverTLS, QUICConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	transport := testQUICTransport(t)
	connector := QUICConnector{TLSConfig: clientTLS, Dialer: transport}
	canceled, stop := context.WithCancel(ctx)
	stop()
	endpoint := Endpoint{Address: listener.Addr().String(), ServerName: "relay.test"}
	if session, err := connector.Connect(canceled, endpoint); session != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled dial lost its cancellation", err)
	}
	var clients, servers [2]Session
	for i := range clients {
		clients[i], err = connector.Connect(ctx, endpoint)
		if err != nil {
			t.Fatal(err)
		}
		defer clients[i].Close()
		servers[i], err = listener.Accept(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer servers[i].Close()
		if got := clients[i].(AcceptedPeer).LocalAddr().String(); got != transport.packet.LocalAddr().String() {
			t.Fatal("relay connection opened a different socket", got)
		}
	}
	_ = clients[0].Close()
	assertRoundTrip(t, clients[1], servers[1], "sibling remains open")
	if err := transport.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-clients[1].Done():
	case <-ctx.Done():
		t.Fatal("owner close left a borrowed connection alive")
	}
	if _, err := transport.packet.WriteTo([]byte("closed"), listener.Addr()); !errors.Is(err, net.ErrClosed) {
		t.Fatal("owner close left the physical socket open", err)
	}
}
