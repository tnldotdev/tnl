package daemon

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/testutil"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// hold background authority/signing after readiness. actual application arrival
// must consume installed state even while the next refresh/refill is stalled.
type heldConnectorControl struct {
	connectorstream.Control
	held    atomic.Bool
	release chan struct{}
}

func (c *heldConnectorControl) wait(ctx context.Context) error {
	if !c.held.Load() {
		return nil
	}
	select {
	case <-c.release:
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

func (c *heldConnectorControl) ConnectorSigner(ctx context.Context, identity string) (connectorstream.Signer, error) {
	signer, err := c.Control.ConnectorSigner(ctx, identity)
	if err != nil {
		return signer, err
	}
	sign := signer.Sign
	signer.Sign = func(message []byte) []byte {
		if c.held.Load() {
			<-c.release
		}
		return sign(message)
	}
	return signer, nil
}

func (c *heldConnectorControl) ResolveService(ctx context.Context, service string) (connectorstream.Run, error) {
	if err := c.wait(ctx); err != nil {
		return connectorstream.Run{}, err
	}
	return c.Control.ResolveService(ctx, service)
}

func (c *heldConnectorControl) PrepareConnectorPeerPair(ctx context.Context, service string, body controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPair, error) {
	if err := c.wait(ctx); err != nil {
		return controlv1.ConnectorPeerPair{}, err
	}
	return c.Control.PrepareConnectorPeerPair(ctx, service, body)
}

func (c *heldConnectorControl) VisitorPermission(ctx context.Context, service string) (controlv1.VisitorTokenResponse, error) {
	if err := c.wait(ctx); err != nil {
		return controlv1.VisitorTokenResponse{}, err
	}
	return c.Control.VisitorPermission(ctx, service)
}

func (c *heldConnectorControl) CloseContext(ctx context.Context) error {
	return c.Control.(interface{ CloseContext(context.Context) error }).CloseContext(ctx)
}

func TestIntegrationPreparedConnectorHasNoArrivalRPCOrSigning(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	for _, standalone := range []bool{false, true} {
		for _, tcp := range []bool{false, true} {
			t.Run(fmt.Sprintf("standalone=%t/tcp=%t", standalone, tcp), func(t *testing.T) {
				f := newServiceRuntimeFixture(t, standalone, nil)
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
				held := &heldConnectorControl{Control: control, release: make(chan struct{})}
				unblock := sync.OnceFunc(func() { close(held.release) })
				defer unblock()
				quic, tls := f.connectors()
				if tcp {
					quic = privateDisabledConnector()
				} else {
					tls = privateDisabledConnector()
				}
				listener, stopConnector := startRuntimeConnector(t, f, service, connectorstream.Config{Control: held, IdentityID: person.Identity.Id, RelayQUIC: quic, RelayTCP: tls})
				defer func() { unblock(); stopConnector() }()
				held.held.Store(true)
				for index := range 2 {
					connection, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
					if err != nil {
						t.Fatal(err)
					}
					payload := fmt.Sprintf("native-once-%d\n", index)
					_ = connection.SetDeadline(time.Now().Add(time.Second))
					if _, err := io.WriteString(connection, payload); err != nil {
						_ = connection.Close()
						t.Fatal(err)
					}
					response := make([]byte, len(payload))
					_, err = io.ReadFull(connection, response)
					_ = connection.Close()
					if err != nil || string(response) != payload {
						t.Fatalf("arrival waited for control/signing or lost bytes: %q %v", response, err)
					}
					target.mu.Lock()
					count := target.received[payload]
					target.mu.Unlock()
					if count != 1 {
						t.Fatalf("target replay count = %d", count)
					}
				}
				privateWait(t, 5*time.Second, func(ctx context.Context) (bool, error) {
					var opened, closed, foreign int
					err := f.inspect.QueryRowContext(ctx, `SELECT
						count(*) FILTER (WHERE event_type='connection.open' AND outcome='allowed'),
						count(*) FILTER (WHERE event_type='connection.close'),
						count(*) FILTER (WHERE actor_identity_id IS DISTINCT FROM $2 OR device_id IS NULL OR source_ip IS DISTINCT FROM '127.0.0.1'::inet)
						FROM control.service_audit_events WHERE service_id=$1 AND event_type IN ('connection.open','connection.close')`, service.Id, person.Identity.Id).
						Scan(&opened, &closed, &foreign)
					if foreign != 0 {
						return false, fmt.Errorf("native audit lost authenticated identity or source")
					}
					return opened >= 2 && closed >= 2, err
				})
			})
		}
	}
}
