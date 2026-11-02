package daemon

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	"github.com/tnldotdev/tnl/internal/ingress"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/internal/testutil"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type privateObservation struct {
	ingress string
	header  tunnelv1.ServiceForwardingHeader
}

type observingServiceForwarder struct {
	ingress.ServiceForwarder
	id     string
	opened chan<- privateObservation
}

func (f observingServiceForwarder) OpenPrivate(ctx context.Context, relay ingressv1.ServiceRelay, header tunnelv1.ServiceForwardingHeader) (net.Conn, error) {
	stream, err := f.ServiceForwarder.OpenPrivate(ctx, relay, header)
	if err == nil && f.opened != nil {
		select {
		case f.opened <- privateObservation{f.id, header}:
		case <-ctx.Done():
			_ = stream.Close()
			return nil, ctx.Err()
		}
	}
	return stream, err
}

func startSeparatedPrivateIngress(t *testing.T, f *privateSeparatedFixture, index int, _ string, opened chan<- privateObservation) *daemon {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	metrics := observability.New("ingress")
	if f.processContext != nil {
		ctx = observability.WithMetrics(ctx, observability.FromContext(f.processContext("ingress")))
		metrics = observability.FromContext(ctx)
	}
	secrets, err := serviceapi.NewBearerSecrets(serviceRuntimeClusterSecret, "")
	if err != nil {
		t.Fatal(err)
	}
	d := &daemon{serviceHTTP: f.serviceHTTP, relayClientTLS: f.roots, clusterSecret: serviceRuntimeClusterSecret, clusterSecrets: secrets, cancel: cancel, componentDone: make(chan error, 1), startedAt: time.Now()}
	client, err := newIngressControlClient(f.controlConfig.PrivateControlEndpoint(), serviceRuntimeClusterSecret, f.serviceHTTP, f.controlConfig.PrivateControlListen)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprintf("private-ingress-%d", index)
	if err := d.startIngressRuntime(ctx, ingressSettingsFrom(f.controlConfig), metrics, ingressRuntimeConfig{
		client: client, ingressID: id, listener: listener, clusterSecret: serviceRuntimeClusterSecret,
		configurePublicServices: func(config *ingress.PublicServicesConfig) {
			if !f.defaultTiming {
				config.RecheckInterval, config.RecheckTimeout, config.HardAuthorizationTTL = 500*time.Millisecond, 500*time.Millisecond, 3*time.Second
			}
			if f.configurePublicServices != nil {
				f.configurePublicServices(config)
			}
			config.Forwarder = observingServiceForwarder{ServiceForwarder: config.Forwarder, id: id, opened: opened}
		},
	}); err != nil {
		cancel()
		_ = listener.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		err := d.shutdown(time.Second)
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("private ingress shutdown: %v", err)
		}
	})
	privateWait(t, 10*time.Second, func(context.Context) (bool, error) {
		select {
		case err := <-d.componentDone:
			return false, err
		default:
		}
		return d.readyIngress(time.Now()) == nil, nil
	})
	return d
}

type privateEchoTarget struct {
	address    string
	mu         sync.Mutex
	received   map[string]int
	receivedOn map[string]net.Conn
}

func startPrivateEchoTarget(t *testing.T) *privateEchoTarget {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	target := &privateEchoTarget{address: listener.Addr().String(), received: make(map[string]int), receivedOn: make(map[string]net.Conn)}
	var workers sync.WaitGroup
	workers.Go(func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Go(func() {
				defer connection.Close()
				stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
				defer stop()
				reader := bufio.NewReader(connection)
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					target.mu.Lock()
					target.received[line]++
					target.receivedOn[line] = connection
					target.mu.Unlock()
					if _, err := io.WriteString(connection, line); err != nil {
						return
					}
				}
			})
		}
	})
	t.Cleanup(func() { cancel(); _ = listener.Close(); workers.Wait() })
	return target
}

func TestIntegrationSeparatedPrivateTwoIngressTwoRelayLifecycle(t *testing.T) {
	serviceRuntimeLifecycle(t, false)
}

func TestIntegrationStandalonePrivateTwoIngressTwoRelayLifecycle(t *testing.T) {
	serviceRuntimeLifecycle(t, true)
}

func serviceRuntimeLifecycle(t *testing.T, standalone bool) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	for _, transport := range []string{"quic", "tls-tcp"} {
		t.Run(transport, func(t *testing.T) {
			f := newServiceRuntimeFixture(t, standalone, nil)
			target := startPrivateEchoTarget(t)
			key, _ := opaqueid.New(opaqueid.IdempotencyPrefix)
			service, err := f.identity.routes.CreateService(t.Context(), f.identity.teamID, "native-lifecycle", key)
			if err != nil {
				t.Fatal(err)
			}
			startPrivateHTTPPublisher(t, f, service, target.address)
			person, err := f.identity.authority.IdentityContext(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			control, err := connectorstream.NewControl(f.identity.routes, f.identity.state, person.Identity.Id)
			if err != nil {
				t.Fatal(err)
			}
			device, err := control.ConnectorSigner(t.Context(), person.Identity.Id)
			if err != nil {
				t.Fatal(err)
			}
			selected, err := control.ResolveService(t.Context(), service.Id)
			if err != nil || selected.PairReady == nil || len(selected.PairReady.Relays) != 2 || selected.PairReady.Relays[0].RelayLease.RelayServiceId == selected.PairReady.Relays[1].RelayLease.RelayServiceId {
				t.Fatal("publisher selection omitted its two distinct ready relay services", err)
			}
			quic, tcp := f.connectors()
			if transport == "quic" {
				tcp = privateDisabledConnector()
			} else {
				quic = privateDisabledConnector()
			}
			listener, stopConnector := startRuntimeConnector(t, f, service, connectorstream.Config{Control: control, IdentityID: person.Identity.Id, RelayQUIC: quic, RelayTCP: tcp}, revokedConnectorOwnerStop)
			defer stopConnector()
			connection, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err := io.WriteString(connection, "native-lifecycle\n"); err != nil {
				t.Fatal(err)
			}
			response := make([]byte, len("native-lifecycle\n"))
			if _, err := io.ReadFull(connection, response); err != nil || string(response) != "native-lifecycle\n" {
				t.Fatal("native application bytes changed", err)
			}
			var pairCount, claimCount int
			if err := f.inspect.QueryRowContext(t.Context(), `SELECT count(*) FROM control.connector_peer_pairs WHERE service_id=$1 AND publisher_prepared_until>now()`, service.Id).Scan(&pairCount); err != nil || pairCount != 1 {
				t.Fatal("native installation missing", pairCount, err)
			}
			if err := f.inspect.QueryRowContext(t.Context(), `SELECT count(*) FROM control.connector_peer_pair_leg_claims claim JOIN control.connector_peer_pairs pair ON pair.id=claim.pair_id WHERE pair.service_id=$1 AND claim.confirmed_until>now()`, service.Id).Scan(&claimCount); err != nil || claimCount != 2 {
				t.Fatal("native readiness omitted exact relay claims", claimCount, err)
			}
			target.mu.Lock()
			count := target.received["native-lifecycle\n"]
			target.mu.Unlock()
			if count != 1 {
				t.Fatal("native application replayed")
			}
			after, err := control.ResolveService(t.Context(), service.Id)
			if err != nil || after.ServiceRunID != selected.ServiceRunID || after.RunNumber != selected.RunNumber || after.Endpoint == nil || selected.Endpoint == nil || *after.Endpoint != *selected.Endpoint {
				t.Fatal("connector preparation changed the saved endpoint or publisher run", err)
			}
			if err := f.identity.routes.RevokeVisitorDevice(t.Context(), device.Subject.DeviceID); err != nil {
				t.Fatal(err)
			}
			_ = connection.SetReadDeadline(time.Now().Add(6 * time.Second))
			if _, err := connection.Read(make([]byte, 1)); err == nil {
				t.Fatal("revocation kept the native TCP stream open")
			} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				t.Fatal("revocation did not close the admitted connector stream", err)
			}
			if _, err := control.ResolveService(t.Context(), service.Id); err == nil {
				t.Fatal("revoked device selected another publisher run")
			}
			var publicURLs int
			if err := f.inspect.QueryRowContext(t.Context(), `SELECT count(*) FROM control.public_urls`).Scan(&publicURLs); err != nil || publicURLs != 0 {
				t.Fatal("connector created public URL state", publicURLs, err)
			}
		})
	}
}
