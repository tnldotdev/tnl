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
	for _, tcp := range []bool{false, true} {
		name := "quic"
		if tcp {
			name = "tls-tcp"
		}
		for _, variant := range []string{"current", "retired alpn", "unknown alpn", "wrong hostname", "untrusted certificate"} {
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
					listener, err := ListenQUIC("127.0.0.1:0", serverTLS, QUICConfig{})
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
					connection, problem := quic.DialAddr(ctx, address, client, nil)
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
