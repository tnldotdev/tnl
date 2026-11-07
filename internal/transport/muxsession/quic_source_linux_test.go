package muxsession

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
)

func TestQUICWildcardListenerReplySource(t *testing.T) {
	// linux routes all of 127/8 locally, so this needs neither interface aliases
	// nor elevated privileges. exercise IPv4 on both IPv4-only and dual-stack sockets.
	for _, network := range []string{"udp4", "udp"} {
		for _, reserved := range []bool{false, true} {
			for _, pinned := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/reserved=%t/pinned=%t", network, reserved, pinned), func(t *testing.T) {
					serverTLS, clientTLS := testTLSConfigs(t)
					config := QUICConfig{UDPNetwork: network}
					if pinned {
						config.PinnedRemoteIPLimit = 4
					}
					var listener *QUICListener
					var err error
					if reserved {
						packet, listenErr := net.ListenPacket(network, ":0")
						if listenErr != nil {
							t.Fatal(listenErr)
						}
						listener, err = ListenQUICPacket(packet, serverTLS, config)
					} else {
						listener, err = ListenQUIC(":0", serverTLS, config)
					}
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = listener.Close() })
					local := listener.Addr().(*net.UDPAddr)
					if !local.IP.IsUnspecified() {
						t.Fatalf("listener did not bind a wildcard: %s", local)
					}
					clientTLS, err = transportTLSConfig(clientTLS, "relay.test", false)
					if err != nil {
						t.Fatal(err)
					}
					ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
					t.Cleanup(cancel)
					var pairs [][2]Session
					for _, ip := range []string{"127.0.0.1", "127.0.0.2"} {
						remote := &net.UDPAddr{IP: net.ParseIP(ip), Port: local.Port}
						packet, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, remote)
						if err != nil {
							t.Fatal(err)
						}
						t.Cleanup(func() { _ = packet.Close() })
						// a connected UDP socket discards replies from the wrong source IP,
						// enforcing the same address constraint as a stateful firewall or NAT.
						transport := &quic.Transport{Conn: connectedQUICPacketConn{packet}}
						t.Cleanup(func() { _ = transport.Close() })
						connection, err := transport.Dial(ctx, remote, clientTLS, quicConnectorConfig(nil))
						if err != nil {
							t.Fatalf("connect to %s: %v", remote, err)
						}
						client := &quicSession{connection: connection}
						t.Cleanup(func() { _ = client.Close() })
						server, err := listener.Accept(ctx)
						if err != nil {
							t.Fatal(err)
						}
						t.Cleanup(func() { _ = server.Close() })
						pairs = append(pairs, [2]Session{client, server})
					}
					// keep both connections alive and alternate traffic so source metadata
					// cannot accidentally be shared across connections on the listener.
					for range 2 {
						for i, pair := range pairs {
							assertRoundTrip(t, pair[0], pair[1], fmt.Sprintf("connection %d", i))
						}
					}
				})
			}
		}
	}
}

// hide unconnected UDP methods from quic-go and send through the connected socket.
type connectedQUICPacketConn struct{ net.PacketConn }

func (c connectedQUICPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	return c.PacketConn.(*net.UDPConn).Write(b)
}
