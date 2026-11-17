package daemon

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	publisherinvocation "github.com/tnldotdev/tnl/internal/publisher/invocation"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationPublisherFallbackRestorationCountsPerActualRun(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	for _, transport := range []string{"quic", "tls-tcp"} {
		t.Run(transport, func(t *testing.T) {
			fixture := newStandalonePublishFixture(t, "fallback-count-"+transport)
			var calls atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				_, _ = io.WriteString(w, r.URL.Path)
			}))
			cleanupIntegrationHTTPServer(t, target, fixture.owner)
			quic, tcp := fixture.connectors()
			wantTransport, wantFallbacks := tunnel.TransportQUIC, 0
			if transport == "quic" {
				tcp, _ = disabledIntegrationConnector("TLS/TCP disabled by fallback-count restoration")
			} else {
				quic, _ = disabledIntegrationConnector("QUIC disabled by fallback-count restoration")
				wantTransport, wantFallbacks = tunnel.TransportTLSTCP, 1
			}
			saved, cfg := fixture.identity.prepareService(t, target.URL, quic, tcp, controlv1.ProjectServiceConfiguration{})
			// this case checks per-run callbacks, not the default heartbeat's
			// recovery latency. retain the ten-second replacement observation.
			cfg.HeartbeatInterval = time.Second
			database, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(fixture.owner.directory, "fallback-journal"),
				clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := database.Close(); err != nil {
					t.Error(err)
				}
			})
			journal, err := database.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{
				Command: clientstate.TunnelCommandPublish, Server: fixture.identity.controlOrigin,
				Project: t.TempDir(), Service: "api", ServiceID: saved.Id, ServiceProtocol: "http", Target: target.URL,
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := journal.Finish(ctx, nil); err != nil {
					t.Error(err)
				}
			})
			type notification struct {
				service, run string
				number       uint64
				transport    string
			}
			var mu sync.Mutex
			var preparation controlv1.ServiceRunPreparation
			var preparations int
			var fallbacks, readyNotifications []notification
			cfg.Prepared = func(run controlv1.ServiceRunPreparation) error {
				mu.Lock()
				defer mu.Unlock()
				if preparations != 0 || run.ServiceId != saved.Id || run.ServiceRunId == "" || run.RunNumber < 1 {
					return errors.New("fallback observation did not prepare exactly one actual service run")
				}
				preparations++
				preparation = run
				return nil
			}
			output := &publisherinvocation.Presentation{
				TransportFallback: func(number uint64, actual string) error {
					mu.Lock()
					defer mu.Unlock()
					if preparations != 1 || number != uint64(preparation.RunNumber) || actual != string(tunnel.TransportTLSTCP) {
						return errors.New("fallback callback lost the prepared service run or transport")
					}
					fallbacks = append(fallbacks, notification{preparation.ServiceId, preparation.ServiceRunId, number, actual})
					return nil
				},
				Ready: func(address string, number uint64) error {
					mu.Lock()
					defer mu.Unlock()
					if preparations != 1 || number != uint64(preparation.RunNumber) ||
						address != serviceHTTPAddress(preparation) || len(fallbacks) != wantFallbacks {
						return errors.New("Ready overtook or duplicated this actual run's fallback notification")
					}
					readyNotifications = append(readyNotifications, notification{preparation.ServiceId, preparation.ServiceRunId, number, ""})
					return nil
				},
			}
			type acceptedSlot struct {
				slot    uint8
				session publisherservice.SlotSession
			}
			accepted := make(chan acceptedSlot, 8)
			cfg.Connect = func(ctx context.Context, bound *publisherservice.Bound, slot uint8, options publisherservice.ConnectOptions) (publisherservice.SlotSession, error) {
				// observe the real accepted session; do not synthesize a claimed
				// transport, a readiness status, or a fallback callback.
				session, err := bound.ConnectSlot(ctx, slot, options)
				if err != nil {
					return nil, err
				}
				select {
				case accepted <- acceptedSlot{slot, session}:
					return session, nil
				case <-ctx.Done():
					return nil, errors.Join(context.Cause(ctx), session.Close())
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			handles := make(chan *integrationPublisher, 1)
			done := make(chan error, 1)
			stop := sync.OnceValue(func() error {
				cancel()
				select {
				case err := <-done:
					return err
				case <-time.After(10 * time.Second):
					return errors.New("actual fallback publication and callbacks did not join")
				}
			})
			t.Cleanup(func() {
				if err := stop(); err != nil {
					t.Error(err)
				}
			})
			go func() {
				done <- publisherinvocation.RunServiceCLI(ctx, journal, saved, cfg, output,
					func(ctx context.Context, run publisherservice.RunConfig) error {
						handle := startOwnedIntegrationPublisherContext(t, ctx, fixture.owner, run, fixture.diagnostics)
						handles <- handle
						<-handle.done
						return handle.result()
					})
			}()
			var handle *integrationPublisher
			select {
			case handle = <-handles:
			case <-time.After(30 * time.Second):
				t.Fatal("actual fallback publisher did not start")
			}
			ready := fixture.waitReady(t, handle)
			awaitSlot := func() acceptedSlot {
				t.Helper()
				select {
				case slot := <-accepted:
					if slot.slot > 1 || slot.session.Transport() != wantTransport {
						t.Fatal("actual accepted slot changed transport", slot.slot, slot.session.Transport())
					}
					return slot
				case <-handle.done:
					t.Fatal("publisher stopped before its real slot was accepted", handle.result())
				case <-time.After(10 * time.Second):
					t.Fatal("actual publisher slot did not connect within the existing request bound")
				}
				return acceptedSlot{}
			}
			var first [2]publisherservice.SlotSession
			for range 2 {
				slot := awaitSlot()
				if first[slot.slot] != nil {
					t.Fatal("initial publisher connections did not cover both slots")
				}
				first[slot.slot] = slot.session
			}
			visit := func(path string) {
				t.Helper()
				response, body, err := fixture.visitor.requestURL(http.MethodGet, serviceHTTPAddress(ready)+path, nil)
				if err != nil || response.StatusCode != http.StatusOK || string(body) != path {
					t.Fatal("actual fallback publication did not carry its visitor", path, err)
				}
				assertIntegrationPublicURLCertificate(t, response, ready.Hostname)
			}
			visit("/before-slot-retry")
			if err := first[0].Close(); err != nil {
				t.Fatal("close the actual first slot to exercise replacement", err)
			}
			replacement := awaitSlot()
			if replacement.slot != 0 || replacement.session == first[0] {
				t.Fatal("slot retry replaced the wrong actual connection")
			}
			waitForReadyPublisherConnections(t, fixture.inspect, ready.ServiceId, ready.RunNumber, 2)
			waitForAppliedServiceRouting(t, fixture.inspect, ready.ServiceRunId, fixture.process.metricsAddress)
			visit("/after-slot-retry")
			if err := stop(); err != nil {
				t.Fatal(err)
			}
			var actualRun string
			if err := fixture.inspect.QueryRowContext(integrationOperationContext(t),
				`SELECT id FROM control.service_runs WHERE service_id=$1 AND run_number=$2`,
				ready.ServiceId, ready.RunNumber).Scan(&actualRun); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			defer mu.Unlock()
			if preparations != 1 || preparation.ServiceId != ready.ServiceId || preparation.ServiceRunId != ready.ServiceRunId ||
				actualRun != ready.ServiceRunId || len(fallbacks) != wantFallbacks || len(readyNotifications) == 0 || calls.Load() != 2 {
				t.Fatal("integrated per-run fallback cardinality or identity changed",
					preparations, len(fallbacks), len(readyNotifications), calls.Load())
			}
			for _, observed := range append(append([]notification(nil), fallbacks...), readyNotifications...) {
				if observed.service != ready.ServiceId || observed.run != actualRun || observed.number != uint64(ready.RunNumber) {
					t.Fatal("a slot retry emitted a notification for another service run")
				}
			}
		})
	}
}
