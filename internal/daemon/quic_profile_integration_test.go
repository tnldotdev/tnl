package daemon

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	daemonconfig "github.com/tnldotdev/tnl/internal/daemon/config"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
)

func TestIntegrationRelayQUICProfiles(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	for _, standalone := range []bool{false, true} {
		for _, profile := range []string{"standard", "fly"} {
			t.Run(fmt.Sprintf("standalone=%t/%s", standalone, profile), func(t *testing.T) {
				f := newServiceRuntimeFixtureTiming(t, standalone, nil, false,
					func(cfg *daemonconfig.Config, _ *http.Transport, _ *testCertificateAuthority) {
						cfg.RelayQUICProfile = profile
					})
				target := startPrivateEchoTarget(t)
				key, err := opaqueid.New(opaqueid.IdempotencyPrefix)
				if err != nil {
					t.Fatal(err)
				}
				service, err := f.identity.routes.CreateService(t.Context(), f.identity.teamID, "quic-profile", key)
				if err != nil {
					t.Fatal(err)
				}
				claimed := make(chan *publisherservice.Claimed, 8)
				f.publisherConnections = claimed
				startPrivateHTTPPublisher(t, f, service, target.address)
				for range 2 {
					select {
					case connection := <-claimed:
						if connection.Transport() != tunnel.TransportQUIC {
							t.Fatal("publisher fell back from QUIC")
						}
					case <-time.After(5 * time.Second):
						t.Fatal("publisher did not claim both verified QUIC connections")
					}
				}
				person, err := f.identity.authority.IdentityContext(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				control, err := connectorstream.NewControl(f.identity.routes, f.identity.state, person.Identity.Id)
				if err != nil {
					t.Fatal(err)
				}
				quic, _ := f.connectors()
				listener, stop := startRuntimeConnector(t, f, service, connectorstream.Config{
					Control: control, IdentityID: person.Identity.Id, RelayQUIC: quic, RelayTCP: privateDisabledConnector(),
				})
				defer stop()
				connection, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
				if err != nil {
					t.Fatal(err)
				}
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
				const message = "QUIC profile carries application bytes\n"
				if _, err := io.WriteString(connection, message); err != nil {
					t.Fatal(err)
				}
				response := make([]byte, len(message))
				if _, err := io.ReadFull(connection, response); err != nil || string(response) != message {
					t.Fatalf("application response = %q, %v", response, err)
				}
			})
		}
	}
}
