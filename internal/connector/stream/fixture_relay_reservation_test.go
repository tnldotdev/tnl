package stream

import (
	"crypto/tls"
	"errors"
	"net"
	"syscall"
	"testing"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
)

func TestConnectorFixtureReservesUDPWhileTestingTCPFallback(t *testing.T) {
	foreignHello := make(chan string, 2)
	foreignListeners := 0
	f := newConfiguredConnectorFixture(t, "wss", "", func(f *connectorFixture, _ *Config) {
		for _, endpoint := range f.endpoints {
			// TCP alone does not reserve UDP. model a different relay acquiring
			// the advertised port before the connector starts its QUIC attempt.
			packet, err := net.ListenPacket("udp", endpoint.Address)
			if errors.Is(err, syscall.EADDRINUSE) {
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			foreignListeners++
			t.Cleanup(func() { _ = packet.Close() })
			foreign, err := muxsession.ListenQUICPacket(packet, &tls.Config{
				GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
					select {
					case foreignHello <- hello.ServerName:
					default:
					}
					return nil, errors.New("foreign relay has no certificate for this hostname")
				},
			}, muxsession.QUICConfig{Config: fixtureDatagramConfig()})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = foreign.Close() })
		}
		f.wantStartupError = foreignListeners != 0
	})
	if foreignListeners != 0 {
		var alert *quic.TransportError
		if !errors.As(f.serveErr, &alert) || !alert.Remote || alert.ErrorCode != 0x150 {
			t.Fatal("foreign relay did not produce the remote TLS internal-error alert", f.serveErr)
		}
		select {
		case hostname := <-foreignHello:
			if hostname != "db.example" {
				t.Fatal("QUIC changed the assigned relay identity", hostname)
			}
		default:
			t.Fatal("startup failure did not come from the foreign TLS certificate owner")
		}
		t.Fatal("TCP-fallback fixture left its UDP endpoint available to another relay:", f.serveErr)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for slot, sessions := range f.sessions {
		if len(sessions) != 1 {
			t.Fatal("TCP fallback did not authenticate exactly one relay leg", slot, len(sessions))
		}
		if _, ok := sessions[0].(muxsession.DatagramSession); ok {
			t.Fatal("TCP-fallback fixture accepted a QUIC leg", slot)
		}
	}
	if f.startupOpened != 1 || f.application.Load() != 0 {
		t.Fatal("TCP fallback did not complete its TLS readiness probe without application bytes")
	}
}
