package daemon

import (
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
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type nativeOuter struct {
	session muxsession.Session
	address string
}
type recordedConnectorConnector struct {
	muxsession.Connector
	opened chan nativeOuter
}

func (c *recordedConnectorConnector) Connect(ctx context.Context, endpoint muxsession.Endpoint) (muxsession.Session, error) {
	session, err := c.Connector.Connect(ctx, endpoint)
	if err == nil {
		select {
		case c.opened <- nativeOuter{session, endpoint.Address}:
		case <-ctx.Done():
			_ = session.Close()
			return nil, context.Cause(ctx)
		}
	}
	return session, err
}

func TestIntegrationConnectorCarrierSwitchRetainsApplicationAndTarget(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	for _, standalone := range []bool{false, true} {
		for _, tcp := range []bool{false, true} {
			t.Run(fmt.Sprintf("standalone=%t/tcp=%t", standalone, tcp), func(t *testing.T) {
				f := newServiceRuntimeFixture(t, standalone, nil)
				target := startPrivateEchoTarget(t)
				key, _ := opaqueid.New(opaqueid.IdempotencyPrefix)
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
				quic, tls := f.connectors()
				selected := quic
				if tcp {
					selected = tls
				}
				recorded := &recordedConnectorConnector{Connector: selected, opened: make(chan nativeOuter, 8)}
				config := connectorstream.Config{Control: control, IdentityID: person.Identity.Id, RelayQUIC: recorded, RelayTCP: privateDisabledConnector()}
				if tcp {
					config.RelayQUIC, config.RelayTCP = privateDisabledConnector(), recorded
				}
				listener, stopConnector := startRuntimeConnector(t, f, service, config)
				defer stopConnector()
				var carriers [2]nativeOuter
				for i := range carriers {
					select {
					case carriers[i] = <-recorded.opened:
					case <-time.After(time.Second):
						t.Fatal("readiness omitted a carrier")
					}
				}
				var firstAddress string
				if err := f.inspect.QueryRowContext(t.Context(), `SELECT slots->0->>'relay_address' FROM control.connector_peer_pairs WHERE service_id=$1`, service.Id).Scan(&firstAddress); err != nil {
					t.Fatal(err)
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
						t.Fatal("carrier switch interrupted application", err)
					}
				}
				exchange("before-switch\n")
				closed := false
				for _, carrier := range carriers {
					if carrier.address == firstAddress {
						_ = carrier.session.Close()
						closed = true
						break
					}
				}
				if !closed {
					t.Fatal("active relay carrier was not found")
				}
				exchange("after-switch\n")
				select {
				case <-recorded.opened:
					t.Fatal("lost carrier reconnected")
				default:
				}
				target.mu.Lock()
				defer target.mu.Unlock()
				if target.received["before-switch\n"] != 1 || target.received["after-switch\n"] != 1 || target.receivedOn["before-switch\n"] != target.receivedOn["after-switch\n"] {
					t.Fatal("switch reopened target or replayed bytes")
				}
			})
		}
	}
}

// revocation can reach either the control worker or the publisher first.
// neither transport failure nor an arbitrary protocol error is an expected stop.
func revokedConnectorOwnerStop(err error) bool {
	var rejected *tunnel.ProtocolError
	return errors.Is(err, clientcontrol.ErrNotFound) || errors.Is(err, connectorstream.ErrServiceConnection) ||
		errors.As(err, &rejected) && rejected != nil && rejected.Code == tunnelv1.Unauthenticated
}

func TestRevokedConnectorOwnerStopClassification(t *testing.T) {
	for _, test := range []struct {
		err  error
		want bool
	}{
		{nil, false},
		{fmt.Errorf("control: %w", clientcontrol.ErrNotFound), true},
		{fmt.Errorf("owner: %w", connectorstream.ErrServiceConnection), true},
		{fmt.Errorf("publisher: %w", &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}), true},
		{context.DeadlineExceeded, false},
		{io.ErrUnexpectedEOF, false},
		{&tunnel.ProtocolError{Code: tunnelv1.Unavailable}, false},
	} {
		if got := revokedConnectorOwnerStop(test.err); got != test.want {
			t.Fatalf("revoked owner stop %v = %t, want %t", test.err, got, test.want)
		}
	}
}

func startRuntimeConnector(t *testing.T, f *privateSeparatedFixture, service controlv1.Service, config connectorstream.Config, expectedStop ...func(error) bool) (net.Listener, func()) {
	t.Helper()
	listener := serviceRuntimeListener(t)
	ctx, cancel := context.WithCancel(t.Context())
	ready, done := make(chan struct{}), make(chan error, 1)
	config.ServiceID, config.Protocol, config.TrustRevision, config.Endpoint = service.Id, string(service.Protocol), service.TrustRevision, service.Endpoint
	config.ServiceTLS, config.TransportTLS = f.visitorRoots, f.roots
	config.Ready = func() error { close(ready); return nil }
	go func() { done <- connectorstream.Serve(ctx, listener, config) }()
	// callers defer this join before testing cancels their publishers' contexts.
	// cleanup remains a fallback for a failed startup, not the lifetime owner.
	stop := sync.OnceFunc(func() {
		cancel()
		select {
		case err := <-done:
			expected := false
			for _, allowed := range expectedStop {
				expected = expected || allowed(err)
			}
			if err != nil && !expected {
				t.Errorf("connector cleanup: %v", err)
			}
		case <-time.After(8 * time.Second):
			t.Error("connector did not join")
		}
	})
	t.Cleanup(stop)
	select {
	case <-ready:
	case err := <-done:
		done <- err
		t.Fatal("connector startup", err)
	case <-time.After(35 * time.Second):
		t.Fatal("connector never became ready")
	}
	return listener, stop
}
