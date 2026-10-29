package daemon

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	"github.com/tnldotdev/tnl/internal/publisher"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
)

func TestIntegrationPublicRunCapacity(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	for _, standalone := range []bool{false, true} {
		name := "split-two-ingress"
		if standalone {
			name = "standalone"
		}
		for _, transport := range []string{"quic", "tls-tcp"} {
			t.Run(name+"/"+transport, func(t *testing.T) {
				const capacity = 4
				var owner *runtimeTopology
				var config publisher.Config
				var visitors []*integrationVisitor
				var ready func(*testing.T, *integrationPublisher) publisher.Event
				var diagnostics func() string
				var quic, tcp muxsession.Connector
				if standalone {
					f := newStandalonePublishFixture(t, "capacity")
					owner, ready, diagnostics = f.owner, f.waitReady, f.diagnostics
					quic, tcp = f.connectors()
					config = f.identity.publisherConfig("", quic, tcp)
					visitors = []*integrationVisitor{f.visitor}
				} else {
					f := newSplitPublishFixture(t, "capacity")
					owner = f.owner
					diagnostics = func() string { return integrationPublisherDiagnostics(f.inspect, f.pebble.logPath) }
					quic, tcp = f.connectors()
					config = f.identity.publisherConfig("", quic, tcp)
					second := f.ingressConfig
					listeners := runtimeListeners{ingress: serviceRuntimeListener(t), metrics: serviceRuntimeListener(t)}
					second.IngressID = "capacity-second-ingress"
					second.IngressListen, second.MetricsListen = listeners.ingress.Addr().String(), listeners.metrics.Addr().String()
					process := startIntegrationProcessWithOptions(t, second, integrationProcessOptions{serviceHTTPClient: f.serviceHTTP,
						relayClientTLS: f.roots, owner: owner, listeners: listeners})
					t.Cleanup(func() { stopIntegrationProcess(t, process) })
					waitForProcessReady(t, process)
					visitors = []*integrationVisitor{f.visitor, newIntegrationVisitor(t, f.pebble.roots, second.IngressListen, owner)}
					ready = func(t *testing.T, handle *integrationPublisher) publisher.Event {
						event := waitForPublisherReady(t, handle)
						if event.Hostname != f.identity.hostname || event.PublicURL != "https://"+f.identity.hostname {
							t.Fatalf("publisher ready event = %#v", event)
						}
						waitForReadyPublisherConnections(t, f.inspect, event.PublicURLID, event.PublishRunNumber, 2)
						waitForIngressRoutingCurrent(t, f.inspect, 2)
						return event
					}
				}
				release := make(chan struct{})
				unblock := sync.OnceFunc(func() { close(release) })
				defer unblock()
				var active, calls atomic.Int32
				target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					active.Add(1)
					defer active.Add(-1)
					_, _ = io.WriteString(w, "prefix")
					w.(http.Flusher).Flush()
					select {
					case <-release:
						_, _ = io.WriteString(w, "finished")
					case <-r.Context().Done():
					}
				}))
				cleanupIntegrationHTTPServer(t, target, owner)
				config.Target = target.URL
				if transport == "quic" {
					config.TCPConnector, _ = disabledIntegrationConnector("TLS/TCP disabled by capacity test")
				} else {
					config.QUICConnector, _ = disabledIntegrationConnector("QUIC disabled by capacity test")
				}
				var err error
				config, err = prepareIntegrationPublisher(t.Context(), config)
				if err != nil {
					t.Fatal(err)
				}
				native, ok := config.Control.(*publisheridentity.Native)
				if !ok {
					t.Fatal("capacity fixture did not prepare a native publisher")
				}
				config.Control, err = native.WithTraffic(&trafficlimits.Selection{Connections: new(capacity)})
				if err != nil {
					t.Fatal(err)
				}
				handle := startOwnedIntegrationPublisher(t, owner, config, diagnostics)
				event := ready(t, handle)
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				var responses []*http.Response
				defer func() {
					unblock()
					for _, response := range responses {
						_ = response.Body.Close()
					}
				}()
				for n := range capacity {
					r, _ := http.NewRequestWithContext(ctx, "GET", event.PublicURL+"/hold", nil)
					response, err := visitors[n%len(visitors)].client.Do(r)
					if err != nil {
						t.Fatal(err)
					}
					responses = append(responses, response)
					prefix := make([]byte, 6)
					if response.StatusCode != 200 {
						t.Fatal("run could not use all capacity", response.StatusCode)
					}
					if _, err := io.ReadFull(response.Body, prefix); err != nil || string(prefix) != "prefix" {
						t.Fatal("target did not stream", err)
					}
				}
				for _, visitor := range visitors {
					response, _, err := visitor.requestURLContext(ctx, "GET", event.PublicURL+"/overflow", nil)
					if standalone && err != nil {
						// the one ingress can exhaust its local limit before opening
						// publisher TLS. split ingress has room locally and reaches
						// the shared publisher counter instead.
						continue
					}
					if err != nil {
						t.Fatal("overflow did not receive an HTTP capacity rejection", err)
					}
					if response.StatusCode != 503 || response.Header.Get("Tnl-Error-Code") != "TNL_REQUEST_LIMIT_REACHED" {
						t.Fatalf("ingress multiplied run capacity: %d %v", response.StatusCode, response.Header)
					}
				}
				if active.Load() != capacity || calls.Load() != capacity {
					t.Fatalf("capacity: active=%d target calls=%d want %d", active.Load(), calls.Load(), capacity)
				}
				unblock()
				for _, response := range responses {
					body, err := io.ReadAll(response.Body)
					_ = response.Body.Close()
					if err != nil || string(body) != "finished" {
						t.Fatal("overflow evicted an authorized stream", err)
					}
				}
				stopIntegrationPublisher(t, handle)
			})
		}
	}
}
