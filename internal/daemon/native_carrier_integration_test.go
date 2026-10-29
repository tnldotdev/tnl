package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/stun/v4"
	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/peer"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type recordedNativeConnector struct {
	muxsession.Connector
	enabled atomic.Bool
	opened  chan muxsession.Session
}

func (c *recordedNativeConnector) Connect(ctx context.Context, endpoint muxsession.Endpoint) (muxsession.Session, error) {
	if !c.enabled.Load() {
		return nil, errors.New("carrier disabled by native runtime fixture")
	}
	session, err := c.Connector.Connect(ctx, endpoint)
	if err == nil {
		select {
		case c.opened <- session:
		case <-ctx.Done():
			_ = session.Close()
			return nil, context.Cause(ctx)
		}
	}
	return session, err
}

func TestIntegrationNativeCarrierSwitchRetainsApplicationAndTarget(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	for _, standalone := range []bool{false, true} {
		for _, tcpFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("standalone=%t/tcp-first=%t", standalone, tcpFirst), func(t *testing.T) {
				f := newServiceRuntimeFixture(t, standalone, nil)
				// discovery and native QUIC share the actual infrastructure socket;
				// the mapping is a hint, never admission or source authority.
				for _, address := range f.quicAddresses {
					checkNativeRelayDiscovery(t, address)
				}
				target := startPrivateEchoTarget(t)
				key, err := opaqueid.New(opaqueid.IdempotencyPrefix)
				if err != nil {
					t.Fatal(err)
				}
				service, err := f.identity.routes.CreateService(t.Context(), f.identity.teamID, "native", key)
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
				quic, tcp := f.connectors()
				a := &recordedNativeConnector{Connector: quic, opened: make(chan muxsession.Session, 8)}
				b := &recordedNativeConnector{Connector: tcp, opened: make(chan muxsession.Session, 8)}
				initial, replacement := a, b
				if tcpFirst {
					initial, replacement = b, a
				}
				initial.enabled.Store(true)
				listener := startNativeRuntimeConnector(t, f, service, connectorstream.Config{Control: control, IdentityID: person.Identity.Id, RelayQUIC: a, RelayTCP: b, Connectivity: peer.ConnectivityOptions{DisableDirect: true}})
				var originals [2]muxsession.Session
				for slot := range originals {
					select {
					case originals[slot] = <-initial.opened:
					case <-time.After(time.Second):
						t.Fatal("native readiness omitted a carrier")
					}
				}
				connection, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
				if err != nil {
					t.Fatal(err)
				}
				defer connection.Close()
				exchange := func(message string) {
					t.Helper()
					_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
					if _, err := io.WriteString(connection, message); err != nil {
						t.Fatal(err)
					}
					got := make([]byte, len(message))
					if _, err := io.ReadFull(connection, got); err != nil || string(got) != message {
						t.Fatal("carrier change interrupted the application", err)
					}
				}
				exchange("before-switch\n")
				replacement.enabled.Store(true)
				initial.enabled.Store(false)
				for _, original := range originals {
					_ = original.Close()
					select {
					case <-replacement.opened:
					case <-time.After(5 * time.Second):
						t.Fatal("native carrier did not switch transport")
					}
				}
				exchange("after-switch\n")
				target.mu.Lock()
				defer target.mu.Unlock()
				if target.received["before-switch\n"] != 1 || target.received["after-switch\n"] != 1 || target.receivedOn["before-switch\n"] != target.receivedOn["after-switch\n"] {
					t.Fatal("carrier replacement reopened the target or replayed application bytes")
				}
			})
		}
	}
}

func TestIntegrationNativePublisherAssignmentReplacementRetainsSession(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	for _, standalone := range []bool{false, true} {
		t.Run(fmt.Sprintf("standalone=%t", standalone), func(t *testing.T) {
			f := newServiceRuntimeFixture(t, standalone, nil)
			claimed := make(chan *publisherservice.Claimed, 8)
			f.publisherConnections = claimed
			target := startPrivateEchoTarget(t)
			key, err := opaqueid.New(opaqueid.IdempotencyPrefix)
			if err != nil {
				t.Fatal(err)
			}
			service, err := f.identity.routes.CreateService(t.Context(), f.identity.teamID, "native", key)
			if err != nil {
				t.Fatal(err)
			}
			startPrivateHTTPPublisher(t, f, service, target.address)
			var originals [2]*publisherservice.Claimed
			for slot := range originals {
				select {
				case originals[slot] = <-claimed:
				case <-time.After(time.Second):
					t.Fatal("publisher readiness omitted a claim")
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
			quic, tcp := f.connectors()
			listener := startNativeRuntimeConnector(t, f, service, connectorstream.Config{Control: control, IdentityID: person.Identity.Id, RelayQUIC: quic, RelayTCP: tcp, Connectivity: peer.ConnectivityOptions{DisableDirect: true}})
			connection, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			exchange := func(message string) {
				t.Helper()
				_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
				if _, err := io.WriteString(connection, message); err != nil {
					t.Fatal(err)
				}
				got := make([]byte, len(message))
				if _, err := io.ReadFull(connection, got); err != nil || string(got) != message {
					t.Fatal("publisher carrier replacement interrupted the retained stream", err)
				}
			}
			exchange("before-assignment\n")
			var pair string
			var generation int64
			if err := f.inspect.QueryRowContext(t.Context(), `SELECT id,delivery_generation FROM control.native_peer_pairs WHERE service_id=$1`, service.Id).Scan(&pair, &generation); err != nil {
				t.Fatal(err)
			}
			for index, original := range originals {
				_ = original.Close()
				select {
				case <-claimed:
				case <-time.After(8 * time.Second):
					t.Fatal("publisher did not replace its connection assignment")
				}
				privateWait(t, 8*time.Second, func(ctx context.Context) (bool, error) {
					var current bool
					err := f.inspect.QueryRowContext(ctx, `SELECT pair.publisher_prepared_until>now() AND pair.delivery_generation=$2
    AND NOT EXISTS(SELECT 1 FROM control.service_connection_slots slot WHERE slot.service_run_id=pair.service_run_id
        AND (pair.slots->slot.connection_slot::int->>'publisher_connection_id'<>slot.publisher_connection_id
            OR (pair.slots->slot.connection_slot::int->>'assignment_revision')::bigint<>slot.connection_assignment_revision))
    FROM control.native_peer_pairs pair WHERE pair.id=$1`, pair, generation).Scan(&current)
					return current, err
				})
				exchange(fmt.Sprintf("after-assignment-%d\n", index))
			}
			target.mu.Lock()
			defer target.mu.Unlock()
			for _, message := range []string{"before-assignment\n", "after-assignment-0\n", "after-assignment-1\n"} {
				if target.received[message] != 1 || target.receivedOn[message] != target.receivedOn["before-assignment\n"] {
					t.Fatal("assignment replacement reopened the target or replayed bytes")
				}
			}
		})
	}
}

func startNativeRuntimeConnector(t *testing.T, f *privateSeparatedFixture, service controlv1.Service, config connectorstream.Config, expectedStop ...error) net.Listener {
	t.Helper()
	listener := serviceRuntimeListener(t)
	ctx, cancel := context.WithCancel(t.Context())
	ready, done := make(chan struct{}), make(chan error, 1)
	config.ServiceID, config.Protocol, config.TrustRevision, config.Endpoint = service.Id, string(service.Protocol), service.TrustRevision, service.Endpoint
	config.ServiceTLS, config.TransportTLS = f.visitorRoots, f.roots
	config.Ready = func() error { close(ready); return nil }
	go func() { done <- connectorstream.Serve(ctx, listener, config) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			expected := false
			for _, allowed := range expectedStop {
				expected = expected || errors.Is(err, allowed)
			}
			if err != nil && !expected {
				t.Errorf("native connector cleanup: %v", err)
			}
		case <-time.After(8 * time.Second):
			t.Error("native connector did not join")
		}
	})
	select {
	case <-ready:
	case err := <-done:
		done <- err
		t.Fatal("native connector startup", err)
	case <-time.After(35 * time.Second):
		t.Fatal("native connector never became ready")
	}
	return listener
}

func checkNativeRelayDiscovery(t *testing.T, address string) {
	t.Helper()
	connection, err := net.DialTimeout("udp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(time.Second))
	request := stun.MustBuild(stun.TransactionID, stun.BindingRequest, stun.Fingerprint)
	if _, err := connection.Write(request.Raw); err != nil {
		t.Fatal(err)
	}
	var buffer [512]byte
	n, err := connection.Read(buffer[:])
	if err != nil {
		t.Fatal("relay discovery did not share the infrastructure socket", err)
	}
	response := &stun.Message{Raw: buffer[:n]}
	if response.Decode() != nil || response.Type != stun.BindingSuccess || response.TransactionID != request.TransactionID || stun.Fingerprint.Check(response) != nil {
		t.Fatal("relay returned invalid discovery evidence")
	}
}
