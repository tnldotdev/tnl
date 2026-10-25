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

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	"github.com/tnldotdev/tnl/internal/ingress"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// only socket discovery is redirected for standalone's ephemeral test ports.
// device enrollment, pair allocation, selection and trust use NewControl.
type separatedVisitorControl struct {
	connectorstream.Control
	dialAddress string
}

func (c *separatedVisitorControl) ConnectorAssignment(ctx context.Context, service string, subject tunnelv1.VisitorSubject, slot uint8) (connectorstream.Assignment, error) {
	a, err := c.Control.ConnectorAssignment(ctx, service, subject, slot)
	if err != nil {
		return connectorstream.Assignment{}, err
	}
	if c.dialAddress != "" {
		a.Endpoint.Address = c.dialAddress
	}
	return a, nil
}

func (c *separatedVisitorControl) ReleaseConnectorAssignment(ctx context.Context, id string) error {
	return c.Control.(interface {
		ReleaseConnectorAssignment(context.Context, string) error
	}).ReleaseConnectorAssignment(ctx, id)
}

func (c *separatedVisitorControl) Close() error {
	return c.Control.(interface{ Close() error }).Close()
}

type privateObservation struct {
	ingress string
	header  tunnelv1.ServiceForwardingHeader
}

// readiness is one admitted TLS-only visitor. consume its observation before
// correlating later application sockets with their exact ingress/relay paths.
func connectorReadinessObservation(t *testing.T, opened <-chan privateObservation) privateObservation {
	t.Helper()
	select {
	case probe := <-opened:
		if probe.header.Connector == nil {
			t.Fatal("connector readiness bypassed stream admission")
		}
		return probe
	case <-time.After(time.Second):
		t.Fatal("connector reported ready without a verified visitor stream")
		return privateObservation{}
	}
}

type observingServiceForwarder struct {
	ingress.ServiceForwarder
	id     string
	opened chan<- privateObservation
}

func (f observingServiceForwarder) OpenPrivate(ctx context.Context, relay ingressv1.ServiceRelay, header tunnelv1.ServiceForwardingHeader, events *tunnel.ReturnEvents) (net.Conn, error) {
	stream, err := f.ServiceForwarder.OpenPrivate(ctx, relay, header, events)
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

func startSeparatedPrivateIngress(t *testing.T, f *privateSeparatedFixture, index int, transport string, opened chan<- privateObservation) *daemon {
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
	ports, err := f.controlConfig.ServicePortInventory()
	if err != nil {
		t.Fatal(err)
	}
	var listener net.Listener
	for range 32 {
		listener, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		if !ports.Contains(listener.Addr().(*net.TCPAddr).Port) {
			break
		}
		_ = listener.Close()
		listener = nil
	}
	if listener == nil {
		t.Fatal("could not select a private connector port outside the service inventory")
	}
	id := fmt.Sprintf("private-ingress-%d", index)
	hostname := id + ".split.integration.test"
	if err := d.startIngressRuntime(ctx, ingressSettingsFrom(f.controlConfig), metrics, ingressRuntimeConfig{
		client: client, ingressID: id, listener: listener, clusterSecret: serviceRuntimeClusterSecret,
		privateHostname: hostname, privateAddress: listener.Addr().String(), disableConnectorQUIC: transport == "tls-tcp",
		configurePrivate: func(config *ingress.ConnectorConfig) {
			if f.configurePrivate != nil {
				f.configurePrivate(config)
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
	address  string
	mu       sync.Mutex
	received map[string]int
}

func startPrivateEchoTarget(t *testing.T) *privateEchoTarget {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	target := &privateEchoTarget{address: listener.Addr().String(), received: make(map[string]int)}
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
			opened := make(chan privateObservation, 64)
			f := newServiceRuntimeFixture(t, standalone, opened)
			ingressIDs := [2]string{"private-ingress-0", "private-ingress-1"}
			var stopIngress func()
			var ingressRuntimes []*ingressRuntime
			if standalone {
				ingressRuntimes = f.composed.ingresses
				ingressIDs = [2]string{standaloneIngressID, standalonePrivateIngressID}
				stopIngress = func() {
					for _, runtime := range f.composed.ingresses {
						if runtime.controller.Lease().IngressId == standaloneIngressID {
							_ = runtime.private.Close()
						}
					}
				}
			} else {
				ingresses := [2]*daemon{startSeparatedPrivateIngress(t, f, 0, transport, opened), startSeparatedPrivateIngress(t, f, 1, transport, opened)}
				for _, process := range ingresses {
					ingressRuntimes = append(ingressRuntimes, process.ingresses...)
				}
				stopIngress = func() { _ = ingresses[0].ingresses[0].private.Close() }
			}
			target := startPrivateEchoTarget(t)
			key, _ := opaqueid.New(opaqueid.IdempotencyPrefix)
			service, err := f.identity.routes.CreateService(t.Context(), f.identity.teamID, "private", key)
			if err != nil {
				t.Fatal(err)
			}
			enrollment, err := f.identity.routes.CreatePublisherEnrollment(t.Context(), controlv1.CreatePublisherEnrollmentRequest{TeamId: service.TeamId, ServiceId: &service.Id, Kind: controlv1.CreatePublisherEnrollmentRequestKindInstalled, Name: "service-runtime"})
			if err != nil {
				t.Fatal(err)
			}
			native, identity, err := publisheridentity.EnrollNative(t.Context(), f.identity.state, f.identity.routes, f.identity.authority, enrollment.EnrollmentKey)
			if err != nil {
				t.Fatal(err)
			}
			quic, tcp := f.connectors()
			if transport == "tls-tcp" {
				quic = privateDisabledConnector()
			} else {
				tcp = privateDisabledConnector()
			}
			publisherCtx, stopPublisher := context.WithCancel(t.Context())
			ready, publisherDone := make(chan struct{}), make(chan error, 1)
			gate := make(chan struct{})
			var slotsMu sync.Mutex
			var slots [2]*publisherservice.Claimed
			var attempts [2]int
			go func() {
				publisherDone <- publisherservice.Publish(publisherCtx, publisherservice.RunConfig{
					Control: f.identity.routes, State: f.identity.state, Access: native.Access, Identity: identity, ServiceID: service.Id, Target: target.address,
					Metadata: controlv1.ServiceMetadata{Protocol: service.Protocol, TargetTls: service.TargetTls, TrustRevision: service.TrustRevision, PublisherPool: service.PublisherPool}, HeartbeatInterval: 100 * time.Millisecond,
					Ready: func() error { close(ready); return nil }, Connect: func(ctx context.Context, bound *publisherservice.Bound, slot uint8) (publisherservice.SlotSession, error) {
						slotsMu.Lock()
						attempts[slot]++
						n := attempts[slot]
						slotsMu.Unlock()
						if slot == 0 && n > 1 {
							select {
							case <-gate:
							case <-ctx.Done():
								return nil, ctx.Err()
							}
						}
						claimed, err := bound.ConnectSlotWithTransports(ctx, slot, false, quic, tcp)
						if err == nil {
							slotsMu.Lock()
							slots[slot] = claimed
							slotsMu.Unlock()
						}
						return claimed, err
					},
				})
			}()
			t.Cleanup(func() {
				stopPublisher()
				select {
				case err := <-publisherDone:
					if err != nil {
						t.Errorf("private publisher shutdown: %v", err)
					}
				case <-time.After(12 * time.Second):
					t.Error("private publisher did not join")
				}
			})
			select {
			case <-ready:
			case err := <-publisherDone:
				publisherDone <- err
				t.Fatalf("publisher stopped before two-slot readiness: %v", err)
			case <-time.After(15 * time.Second):
				t.Fatal("publisher never became ready")
			}
			person, err := f.identity.authority.IdentityContext(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			production, err := connectorstream.NewControl(f.identity.routes, f.identity.state, person.Identity.Id)
			if err != nil {
				t.Fatal(err)
			}
			device, err := production.ConnectorSigner(t.Context(), person.Identity.Id)
			if err != nil {
				t.Fatal(err)
			}
			control := &separatedVisitorControl{Control: production}
			if standalone {
				control.dialAddress = f.sharedTCP
				if transport == "quic" {
					control.dialAddress = f.sharedQUIC
				}
			}
			selected, err := control.ResolveService(t.Context(), service.Id)
			if err != nil {
				t.Fatal(err)
			}
			visitor, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			visitorCtx, stopVisitor := context.WithCancel(t.Context())
			visitorReady, visitorDone := make(chan struct{}), make(chan error, 1)
			visitorStopped := false
			go func() {
				visitorDone <- connectorstream.Serve(visitorCtx, visitor, connectorstream.Config{Control: control, ServiceID: service.Id, IdentityID: person.Identity.Id, Protocol: "tcp", TrustRevision: service.TrustRevision, Endpoint: service.Endpoint, ServiceTLS: f.visitorRoots, Ready: func() error { close(visitorReady); return nil }})
			}()
			t.Cleanup(func() {
				stopVisitor()
				if !visitorStopped {
					select {
					case err := <-visitorDone:
						if err != nil {
							t.Errorf("visitor shutdown: %v", err)
						}
					case <-time.After(5 * time.Second):
						t.Error("visitor did not join")
					}
				}
				finish, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				var reservations int
				if err := f.inspect.QueryRowContext(finish, `SELECT count(*) FROM control.connector_sessions WHERE device_id=$1 AND revoked_at IS NULL`, device.Subject.DeviceID).Scan(&reservations); err != nil || reservations != 0 {
					t.Errorf("connector shutdown retained assignments: count=%d err=%v", reservations, err)
				}
			})
			select {
			case <-visitorReady:
			case <-time.After(10 * time.Second):
				t.Fatal("visitor did not authenticate both ingresses")
			}
			connectorReadinessObservation(t, opened)
			var boundSessions, distinctIngresses, readyRelays, distinctRelays int
			if err := f.inspect.QueryRowContext(t.Context(), `SELECT count(*),count(DISTINCT ingress_id) FROM control.connector_sessions WHERE device_id=$1 AND bound_at IS NOT NULL`, device.Subject.DeviceID).Scan(&boundSessions, &distinctIngresses); err != nil || boundSessions != 2 || distinctIngresses != 2 {
				t.Fatalf("visitor did not bind two ingress identities: %d/%d %v", boundSessions, distinctIngresses, err)
			}
			if err := f.inspect.QueryRowContext(t.Context(), `SELECT count(*),count(DISTINCT relay_service_id) FROM control.service_connection_slots WHERE service_run_id=$1 AND state='ready' AND session_open`, selected.ServiceRunID).Scan(&readyRelays, &distinctRelays); err != nil || readyRelays != 2 || distinctRelays != 2 {
				t.Fatalf("publisher did not claim both relays: %d %v", readyRelays, err)
			}
			type held struct {
				conn        net.Conn
				observation privateObservation
				payload     string
			}
			var heldConnections []held
			t.Cleanup(func() {
				for _, held := range heldConnections {
					_ = held.conn.Close()
				}
			})
			open := func(n int) held {
				t.Helper()
				conn, err := net.DialTimeout("tcp", visitor.Addr().String(), time.Second)
				if err != nil {
					t.Fatal(err)
				}
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				payload := fmt.Sprintf("private-command-%d\n", n)
				if _, err := io.WriteString(conn, payload); err != nil {
					t.Fatal(err)
				}
				response := make([]byte, len(payload))
				if _, err := io.ReadFull(conn, response); err != nil || string(response) != payload {
					t.Fatalf("opaque private bytes: %q %v", response, err)
				}
				var observation privateObservation
				select {
				case observation = <-opened:
				case <-time.After(time.Second):
					t.Fatal("no trusted ingress forwarding observation")
				}
				value := held{conn, observation, payload}
				_ = conn.SetDeadline(time.Time{})
				heldConnections = append(heldConnections, value)
				return value
			}
			var survivor, ingressLost, relayLost *held
			for n := 0; n < 32 && (survivor == nil || ingressLost == nil || relayLost == nil); n++ {
				connection := open(n)
				if connection.observation.ingress == ingressIDs[1] && connection.observation.header.ConnectionSlot == 1 && survivor == nil {
					survivor = &connection
				} else if connection.observation.ingress == ingressIDs[0] && ingressLost == nil {
					ingressLost = &connection
				} else if connection.observation.ingress == ingressIDs[1] && connection.observation.header.ConnectionSlot == 0 && relayLost == nil {
					relayLost = &connection
				} else {
					_ = connection.conn.Close()
				}
			}
			if survivor == nil || ingressLost == nil || relayLost == nil {
				t.Fatal("did not observe both independent ingress and relay paths")
			}
			if standalone {
				// let the original short lease-bound leaves expire. the same
				// shared listener must present renewed control-issued leaves,
				// while the already admitted visitor keeps its original path.
				var previous time.Time
				for _, runtime := range f.composed.ingresses {
					certificate, err := runtime.serviceCertificate.TLSConfig().GetCertificate(nil)
					if err != nil {
						t.Fatal(err)
					}
					if certificate.Leaf.NotAfter.After(previous) {
						previous = certificate.Leaf.NotAfter
					}
				}
				privateWait(t, 8*time.Second, func(context.Context) (bool, error) { return time.Now().After(previous.Add(50 * time.Millisecond)), nil })
				for slot := range uint8(2) {
					assignment, err := control.ConnectorAssignment(t.Context(), service.Id, device.Subject, slot)
					if err != nil {
						t.Fatal(err)
					}
					nonce, err := tunnelv1.NewConnectorSessionNonce()
					if err != nil {
						t.Fatal(err)
					}
					hello := tunnelv1.ConnectorSessionHello{ProtocolVersion: tunnelv1.Version, Kind: "connector_session", ServiceID: service.Id, SessionID: assignment.SessionID,
						Credential: assignment.Credential, Subject: device.Subject, Nonce: nonce}
					digest, err := hello.Claim().Digest()
					if err != nil {
						t.Fatal(err)
					}
					hello.Signature = device.Sign(digest)
					var connector muxsession.Connector = muxsession.ConnectorQUIC{TLSConfig: assignment.TransportTLS}
					if transport == "tls-tcp" {
						connector = muxsession.ConnectorMuxTLS{TLSConfig: assignment.TransportTLS}
					}
					setup, cancel := context.WithTimeout(t.Context(), 3*time.Second)
					peer, err := connector.Connect(setup, assignment.Endpoint)
					if err != nil {
						cancel()
						t.Fatalf("renewed infrastructure TLS: %v", err)
					}
					session, err := tunnel.DialConnector(setup, peer, hello)
					cancel()
					if err != nil {
						t.Fatalf("renewed lease-bound mux authentication: %v", err)
					}
					_ = session.Close()
					// a private SNI must not accept the publisher ALPN even on
					// the shared infrastructure socket and with trusted roots.
					var wrongRole muxsession.Connector = muxsession.QUICConnector{TLSConfig: assignment.TransportTLS}
					if transport == "tls-tcp" {
						wrongRole = muxsession.TLSYamuxConnector{TLSConfig: assignment.TransportTLS}
					}
					attempt, finish := context.WithTimeout(t.Context(), time.Second)
					unexpected, err := wrongRole.Connect(attempt, assignment.Endpoint)
					finish()
					if err == nil {
						_ = unexpected.Close()
						t.Fatal("private SNI accepted publisher ALPN")
					}
				}
			}
			stopIngress()
			assertClosed := func(connection net.Conn) {
				t.Helper()
				_ = connection.SetReadDeadline(time.Now().Add(3 * time.Second))
				if _, err := connection.Read(make([]byte, 1)); err == nil {
					t.Fatal("failed path kept its stream open")
				} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
					t.Fatalf("path loss did not close visitor: %v", err)
				}
			}
			assertClosed(ingressLost.conn)
			fresh := open(100)
			_ = fresh.conn.Close()
			slotsMu.Lock()
			lost := slots[0]
			slotsMu.Unlock()
			_ = lost.Close()
			assertClosed(relayLost.conn)
			privateWait(t, 10*time.Second, func(ctx context.Context) (bool, error) {
				var n int
				err := f.inspect.QueryRowContext(ctx, `SELECT count(*) FROM control.service_connection_slots WHERE service_run_id=$1 AND state='ready' AND session_open`, selected.ServiceRunID).Scan(&n)
				if err != nil || n != 1 {
					return false, err
				}
				// the next cohort starts after the surviving ingress has prepared
				// the one-relay projection; it cannot refresh routing on arrival.
				for _, runtime := range ingressRuntimes {
					if runtime.controller.Lease().IngressId == ingressIDs[1] {
						route, ok := runtime.private.ServiceRoute(service.Id, selected.ServiceRunID, int64(selected.RunNumber), time.Now())
						return ok && len(*route.ConnectedRelays) == 1, nil
					}
				}
				return false, nil
			})
			fresh = open(101)
			_ = fresh.conn.Close()
			if _, err := io.WriteString(survivor.conn, "survived-both-failures\n"); err != nil {
				t.Fatal(err)
			}
			response := make([]byte, len("survived-both-failures\n"))
			if _, err := io.ReadFull(survivor.conn, response); err != nil {
				t.Fatalf("surviving live stream was interrupted: %v", err)
			}
			close(gate)
			privateWait(t, 10*time.Second, func(ctx context.Context) (bool, error) {
				var n int
				err := f.inspect.QueryRowContext(ctx, `SELECT count(*) FROM control.service_connection_slots WHERE service_run_id=$1 AND state='ready' AND session_open`, selected.ServiceRunID).Scan(&n)
				return n == 2, err
			})
			after, err := control.ResolveService(t.Context(), service.Id)
			if err != nil || after.ServiceRunID != selected.ServiceRunID || after.Endpoint == nil || selected.Endpoint == nil || *after.Endpoint != *selected.Endpoint {
				t.Fatalf("slot replacement restarted the run or rotated its pin: %v", err)
			}
			if err := f.identity.routes.RevokeVisitorDevice(t.Context(), device.Subject.DeviceID); err != nil {
				t.Fatal(err)
			}
			assertClosed(survivor.conn)
			select {
			case err := <-visitorDone:
				visitorStopped = true
				if !errors.Is(err, clientcontrol.ErrNotFound) {
					t.Fatalf("revocation did not stop prepared connector: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("revocation left prepared connector running")
			}
			if _, err := control.ResolveService(t.Context(), service.Id); err == nil {
				t.Fatal("revoked device selected another run")
			}
			var publicURLs int
			if err := f.inspect.QueryRowContext(t.Context(), `SELECT count(*) FROM control.public_urls`).Scan(&publicURLs); err != nil || publicURLs != 0 {
				t.Fatalf("private transport created public URL state: %d %v", publicURLs, err)
			}
			target.mu.Lock()
			defer target.mu.Unlock()
			for payload, count := range target.received {
				if count != 1 {
					t.Fatalf("live bytes replayed to target: %q count=%d", payload, count)
				}
			}
		})
	}
}
