package publisher

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestPublicCapacityGuestDeadlineClosesSetupAndIdleConnections(t *testing.T) {
	for _, stage := range []string{"metadata", "tls", "authorized"} {
		t.Run(stage, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				policy, update, _ := visitorfixture.ScopePolicy(t, visitorscope.Scope{Kind: visitorscope.PublicURL, ID: certificateTestPublicURLID}, "route.example", 443, true)
				update.BoundConnections = true
				update.View.ValidUntil = time.Now().Add(3 * time.Second)
				if err := policy.Apply(policy.Begin(), update); err != nil {
					t.Fatal(err)
				}
				route, err := newTestPublicURLServer(t, PublicURLServerConfig{
					Hostname: "route.example", VisitorPolicy: policy, StreamCapacity: 1,
					Certificate: visitorfixture.Certificate(t, "route.example"),
					Handler:     http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }),
				})
				if err != nil {
					t.Fatal(err)
				}
				defer route.Close()
				if err := route.Start(); err != nil {
					t.Fatal(err)
				}
				connection, peer := net.Pipe()
				defer peer.Close()
				done := make(chan struct{})
				header := testPublicStreamHeader(route, tunnelv1.VisitorStreamHeader{})
				go func() {
					defer close(done)
					serveTestPublicVisitor(t, route, connection, header)
				}()
				var visitor net.Conn = peer
				if stage != "metadata" {
					metadata, err := encodeTestPublicMetadata(route, header, proxyproto.Header{Source: netip.MustParseAddrPort("192.0.2.1:1234"), Destination: netip.MustParseAddrPort("127.0.0.1:443")})
					if err != nil {
						t.Fatal(err)
					}
					if _, err := peer.Write(metadata); err != nil {
						t.Fatal(err)
					}
					secured := tls.Client(peer, &tls.Config{RootCAs: visitorfixture.Roots(t, *route.certificate.Load()), ServerName: "route.example"})
					if err := secured.HandshakeContext(t.Context()); err != nil {
						t.Fatal(err)
					}
					visitor = secured
					if stage == "authorized" {
						response, err := capacityRequest(visitor, "/", false)
						if err != nil {
							t.Fatal(err)
						}
						response.Body.Close()
						if response.StatusCode != http.StatusNoContent {
							t.Fatal("visitor was not admitted", response.StatusCode)
						}
					}
				}
				closed := make(chan error, 1)
				go func() { _, err := visitor.Read(make([]byte, 1)); closed <- err }()
				time.Sleep(2 * time.Second)
				synctest.Wait()
				select {
				case err := <-closed:
					t.Fatal("connection closed before guest authority expired", err)
				default:
				}
				route.mu.Lock()
				pending, authorized := route.pendingStreams, route.authorizedStreams
				route.mu.Unlock()
				if stage == "authorized" && (pending != 0 || authorized != 1) || stage != "authorized" && (pending != 1 || authorized != 0) {
					t.Fatalf("connection did not own capacity: pending=%d authorized=%d", pending, authorized)
				}
				// no renewal arrives. the local guest timer must close and retire
				// the socket before either the setup or process lifetime expires.
				time.Sleep(time.Second)
				synctest.Wait()
				select {
				case err := <-closed:
					if err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
						t.Fatal("guest connection was not closed locally", err)
					}
				default:
					t.Fatal("guest connection survived its deadline")
				}
				select {
				case <-done:
				default:
					t.Fatal("expired connection cleanup did not join")
				}
				route.mu.Lock()
				defer route.mu.Unlock()
				if route.pendingStreams != 0 || route.authorizedStreams != 0 || len(route.pendingSources) != 0 {
					t.Fatal("expired guest connection retained capacity")
				}
			})
		})
	}
}
