package muxsession

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
)

func TestRelayTransportRejectsRetiredALPNAndWrongHostname(t *testing.T) {
	for _, name := range []string{"quic", "quic-basic", "tls-tcp"} {
		tcp := name == "tls-tcp"
		for _, variant := range []string{"current", "classical only", "retired alpn", "unknown alpn", "wrong hostname", "untrusted certificate"} {
			t.Run(name+"/"+variant, func(t *testing.T) {
				serverTLS, roots := testTLSConfigs(t)
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				var address string
				var accept func() (Session, error)
				var closeListener func() error
				if tcp {
					listener, err := net.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					address, closeListener = listener.Addr().String(), listener.Close
					accept = func() (Session, error) {
						conn, err := listener.Accept()
						if err != nil {
							return nil, err
						}
						return AcceptTLSYamux(ctx, conn, serverTLS, TLSYamuxConfig{})
					}
				} else {
					config := QUICConfig{}
					if name == "quic-basic" {
						config.UDPNetwork, config.BasicPacketConn = "udp4", true
						config.Config = &quic.Config{InitialPacketSize: 1200, DisablePathMTUDiscovery: true}
					}
					listener, err := ListenQUIC("127.0.0.1:0", serverTLS, config)
					if err != nil {
						t.Fatal(err)
					}
					address, closeListener = listener.Addr().String(), listener.Close
					accept = func() (Session, error) { return listener.Accept(ctx) }
				}
				done := make(chan error, 1)
				go func() {
					session, err := accept()
					if session != nil {
						defer session.Close()
						state := session.(AcceptedPeer).TLSConnectionState()
						if state.CurveID != tls.X25519MLKEM768 {
							t.Error("relay lost hybrid post-quantum key agreement")
						}
						if state.NegotiatedProtocol != ALPN || state.ServerName != "relay.test" {
							t.Error("relay lost verified transport identity")
						}
					}
					done <- err
				}()
				t.Cleanup(func() { cancel(); _ = closeListener(); <-done })
				client := roots.Clone()
				client.ServerName, client.NextProtos = "relay.test", []string{ALPN}
				switch variant {
				case "classical only":
					client.CurvePreferences = []tls.CurveID{tls.X25519}
				case "retired alpn":
					client.NextProtos = []string{"tnl-connector/1"}
				case "unknown alpn":
					client.NextProtos = []string{"unrecognized/1"}
				case "wrong hostname":
					client.ServerName = "another.relay.test"
				case "untrusted certificate":
					_, client = testTLSConfigs(t)
					client.ServerName, client.NextProtos = "relay.test", []string{ALPN}
				}
				var err error
				if tcp {
					connection, problem := (&tls.Dialer{Config: client}).DialContext(ctx, "tcp", address)
					err = problem
					if connection != nil {
						_ = connection.Close()
					}
				} else {
					remote, problem := net.ResolveUDPAddr("udp", address)
					if problem != nil {
						t.Fatal(problem)
					}
					connection, problem := testQUICTransport(t).DialQUIC(ctx, remote, client, nil)
					err = problem
					if connection != nil {
						_ = connection.CloseWithError(0, "")
					}
				}
				if (err == nil) != (variant == "current") {
					t.Fatalf("transport boundary: %v", err)
				}
			})
		}
	}
}
