package stream

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
)

func TestConnectorOwnsOneRelayUDPSocketUntilClose(t *testing.T) {
	f := newConfiguredConnectorFixture(t, "quic", "", func(_ *connectorFixture, config *Config) {
		config.RelayTCP = muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
			return nil, net.ErrClosed
		})
	})
	setup, stop := context.WithTimeout(t.Context(), 3*time.Second)
	defer stop()
	p, err := prepareConnectorConnection(t.Context(), setup, f.config, f.device)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if p.udpTransport == nil {
		t.Fatal("connector did not retain its UDP transport")
	}
	address := p.udpTransport.LocalAddr().String()
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	var remotes [2]string
	for slot, sessions := range f.sessions {
		remotes[slot] = sessions[len(sessions)-1].(muxsession.AcceptedPeer).RemoteAddr().String()
	}
	f.mu.Unlock()
	for _, remote := range remotes {
		_, got, err := net.SplitHostPort(remote)
		if err != nil || got != port {
			t.Fatal("relay legs did not borrow the connector's socket", address, remotes, err)
		}
	}
	p.Close()
	if session, err := p.config.RelayQUIC.Connect(setup, f.endpoints[0]); session != nil || err == nil {
		t.Fatal("closed connector silently opened another UDP transport", err)
	}
	packet, err := net.ListenPacket("udp", address)
	if err != nil {
		t.Fatal("connector close did not release its physical socket", err)
	}
	_ = packet.Close()
}
