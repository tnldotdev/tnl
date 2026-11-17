package daemon

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationPublicConnectionCapacityRestoration(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	for _, standalone := range []bool{false, true} {
		topology := "split-two-ingress"
		if standalone {
			topology = "standalone"
		}
		for _, transport := range []string{"quic", "tls-tcp"} {
			t.Run(topology+"/"+transport, func(t *testing.T) {
				const capacity, requestCapacity = 4, 8
				var owner *runtimeTopology
				var identity *integrationPublishingIdentity
				var visitors []*integrationVisitor
				var ready func(*testing.T, *integrationPublisher) controlv1.ServiceRunPreparation
				var diagnostics func() string
				var quic, tcp muxsession.Connector
				if standalone {
					f := newStandalonePublishFixture(t, "connection-capacity")
					owner, identity, ready, diagnostics = f.owner, f.identity, f.waitReady, f.diagnostics
					quic, tcp = f.connectors()
					visitors = []*integrationVisitor{f.visitor}
				} else {
					f := newSplitPublishFixture(t, "connection-capacity")
					owner, identity = f.owner, f.identity
					diagnostics = func() string { return integrationPublisherDiagnostics(f.inspect, f.pebble.logPath) }
					quic, tcp = f.connectors()
					second := f.ingressConfig
					listeners := runtimeListeners{ingress: serviceRuntimeListener(t, owner), metrics: serviceRuntimeListener(t, owner)}
					second.IngressID = "connection-capacity-second-ingress"
					second.IngressListen, second.MetricsListen = listeners.ingress.Addr().String(), listeners.metrics.Addr().String()
					process := startIntegrationProcessWithOptions(t, second, integrationProcessOptions{
						serviceHTTPClient: f.serviceHTTP, relayClientTLS: f.roots, owner: owner, listeners: listeners,
					})
					waitForProcessReady(t, process)
					public := serviceRuntimeListener(t, owner)
					startSplitIngressProxy(t, owner, public, second.IngressListen)
					visitors = []*integrationVisitor{f.visitor, newIntegrationVisitor(t, f.pebble.roots, public.Addr().String(), owner)}
					ready = func(t *testing.T, handle *integrationPublisher) controlv1.ServiceRunPreparation {
						t.Helper()
						run := waitForPublisherReady(t, handle)
						if run.Hostname != identity.hostname {
							t.Fatal("connection-capacity publisher changed its hostname")
						}
						waitForReadyPublisherConnections(t, f.inspect, run.ServiceId, run.RunNumber, 2)
						waitForIngressRoutingCurrent(t, f.inspect, 2)
						waitForAppliedServiceRouting(t, f.inspect, run.ServiceRunId, f.ingress.metricsAddress, process.metricsAddress)
						return run
					}
				}

				release := make(chan struct{})
				unblock := sync.OnceFunc(func() { close(release) })
				defer unblock()
				var active, calls atomic.Int32
				finished := make(chan struct{}, capacity)
				target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					if r.URL.Path != "/hold" {
						t.Error("overflow reached the target despite four owned physical connections")
						w.WriteHeader(http.StatusConflict)
						return
					}
					active.Add(1)
					defer func() {
						active.Add(-1)
						finished <- struct{}{}
					}()
					_, _ = io.WriteString(w, "prefix")
					w.(http.Flusher).Flush()
					select {
					case <-release:
						if _, err := io.WriteString(w, "finished"); err != nil {
							t.Error("admitted response was evicted", err)
						}
					case <-r.Context().Done():
						t.Error("overflow canceled an admitted target request")
					}
				}))
				cleanupIntegrationHTTPServer(t, target, owner)
				if transport == "quic" {
					tcp, _ = disabledIntegrationConnector("TLS/TCP disabled by connection-capacity restoration")
				} else {
					quic, _ = disabledIntegrationConnector("QUIC disabled by connection-capacity restoration")
				}
				saved, cfg := identity.prepareService(t, target.URL, quic, tcp, controlv1.ProjectServiceConfiguration{
					Http: &controlv1.ProjectServiceHTTP{Limits: &controlv1.ProjectHTTPApplicationLimits{Concurrency: new(requestCapacity)}},
				})
				declaration, _, err := identity.routes.GetServiceConfiguration(t.Context(), saved.Id)
				if err != nil || declaration == nil || declaration.Http == nil || declaration.Http.Limits == nil ||
					declaration.Http.Limits.Concurrency == nil || *declaration.Http.Limits.Concurrency != requestCapacity {
					t.Fatal("saved request budget did not leave room above the physical limit", err)
				}
				native, ok := cfg.Control.(*publisheridentity.Native)
				if !ok {
					t.Fatal("connection-capacity fixture did not prepare its native publisher")
				}
				scoped, err := native.WithTraffic(&trafficlimits.Selection{Connections: new(capacity)})
				if err != nil {
					t.Fatal(err)
				}
				cfg.Control, cfg.Access, cfg.StreamCapacity = scoped, scoped.Access, capacity
				cfg.Prepared = func(run controlv1.ServiceRunPreparation) error {
					if run.ServiceId != saved.Id || run.Traffic.Connections != capacity {
						return fmt.Errorf("prepared connection budget differs from the selected four-connection service")
					}
					return nil
				}
				handle := startOwnedIntegrationPublisher(t, owner, cfg, diagnostics)
				run := ready(t, handle)
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				var responses []*http.Response
				defer func() {
					unblock()
					for _, response := range responses {
						_ = response.Body.Close()
					}
				}()
				connections := make(map[net.Conn]bool)
				for n := range capacity {
					var connection net.Conn
					trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
						connection = info.Conn
						if info.Reused {
							t.Error("held application request reused an existing visitor connection")
						}
					}}
					r, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, serviceHTTPAddress(run)+"/hold", nil)
					if err != nil {
						t.Fatal(err)
					}
					response, err := visitors[n%len(visitors)].client.Do(r)
					if err != nil {
						t.Fatal(err)
					}
					responses = append(responses, response)
					if connection == nil || connections[connection] || response.ProtoMajor != 1 ||
						response.TLS == nil || !response.TLS.HandshakeComplete || len(response.TLS.VerifiedChains) == 0 {
						t.Fatal("four requests did not acquire four distinct verified visitor TLS connections")
					}
					connections[connection] = true
					prefix := make([]byte, len("prefix"))
					if response.StatusCode != http.StatusOK {
						t.Fatal("physical budget could not admit four original connections", response.StatusCode)
					}
					if _, err := io.ReadFull(response.Body, prefix); err != nil || string(prefix) != "prefix" {
						t.Fatal("admitted target did not stream its prefix", err)
					}
				}
				for _, visitor := range visitors {
					response, _, err := visitor.requestURLContext(ctx, http.MethodGet, serviceHTTPAddress(run)+"/overflow", nil)
					if standalone && err != nil {
						// preserve the original standalone pre-TLS rejection case,
						// but a hung connection is not a capacity rejection.
						if timeout, ok := err.(net.Error); ok && timeout.Timeout() || ctx.Err() != nil {
							t.Fatal("physical capacity rejection exceeded its original request bound", err)
						}
						continue
					}
					if err != nil {
						t.Fatal("split ingress lost its HTTP physical-capacity rejection", err)
					}
					if response.StatusCode != http.StatusServiceUnavailable ||
						response.Header.Get("Tnl-Error-Code") != "TNL_REQUEST_LIMIT_REACHED" {
						t.Fatal("a fifth physical connection was not rejected", response.StatusCode, response.Header)
					}
				}
				if len(connections) != capacity || active.Load() != capacity || calls.Load() != capacity {
					t.Fatal("ingress multiplied physical run capacity", len(connections), active.Load(), calls.Load())
				}
				unblock()
				for _, response := range responses {
					body, readErr := io.ReadAll(response.Body)
					closeErr := response.Body.Close()
					if readErr != nil || closeErr != nil || string(body) != "finished" {
						t.Fatal("overflow evicted or truncated an admitted response", string(body), readErr, closeErr)
					}
				}
				for range capacity {
					select {
					case <-finished:
					case <-ctx.Done():
						t.Fatal("admitted target handlers did not finish", ctx.Err())
					}
				}
				stopIntegrationPublisher(t, handle)
				if calls.Load() != capacity || active.Load() != 0 {
					t.Fatal("overflow or cleanup replayed or retained target work", calls.Load(), active.Load())
				}
			})
		}
	}
}
