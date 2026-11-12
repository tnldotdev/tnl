package relay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestConnectorClaimCancellationOnlyAndMixedErrors(t *testing.T) {
	denied := &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
	stale := &tunnel.ProtocolError{Code: tunnelv1.StaleNetworkBinding}
	operation := errors.New("independent operation failure")
	for _, test := range []struct {
		name string
		err  error
		want tunnelv1.ErrorCode
	}{
		{"canceled", context.Canceled, tunnelv1.Unavailable},
		{"deadline", context.DeadlineExceeded, tunnelv1.Unavailable},
		{"wrapped cancellation", fmt.Errorf("claim: %w", context.Canceled), tunnelv1.Unavailable},
		{"joined cancellation", errors.Join(context.Canceled, context.DeadlineExceeded), tunnelv1.Unavailable},
		{"denial", errors.Join(context.Canceled, denied), tunnelv1.Unauthenticated},
		{"stale source", errors.Join(context.Canceled, stale), tunnelv1.StaleNetworkBinding},
		{"operation failure", errors.Join(context.Canceled, operation), tunnelv1.Unauthenticated},
		{"retry and operation failure", errors.Join(&tunnel.ProtocolError{Code: tunnelv1.Unavailable}, context.Canceled, operation), tunnelv1.Unauthenticated},
		{"nested denial", errors.Join(stale, fmt.Errorf("claim: %w", errors.Join(context.Canceled, denied))), tunnelv1.Unauthenticated},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := connectorClaimError(test.err)
			var protocol *tunnel.ProtocolError
			if !errors.As(err, &protocol) || protocol.Code != test.want || !errors.Is(err, test.err) {
				t.Fatal("first wire classification lost a cause or precedence", err)
			}
		})
	}
}

func TestConnectorDeliveryRenewalCanceledControlErrorKeepsCauseTree(t *testing.T) {
	denied := &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
	stale := &tunnel.ProtocolError{Code: tunnelv1.StaleNetworkBinding}
	operation := errors.New("independent operation failure")
	for _, test := range []struct {
		name string
		err  error
		want tunnelv1.ErrorCode
	}{
		{"cancellation only", context.Canceled, tunnelv1.Unavailable},
		{"wrapped cancellation only", fmt.Errorf("direct claim: %w", context.Canceled), tunnelv1.Unavailable},
		{"denial", errors.Join(context.Canceled, denied), tunnelv1.Unauthenticated},
		{"stale source", errors.Join(context.Canceled, stale), tunnelv1.StaleNetworkBinding},
		{"operation failure", errors.Join(context.Canceled, operation), tunnelv1.Unauthenticated},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newConnectorBindingFixture(t)
			d, outer := f.candidate(t, 1, "192.0.2.1:12345")
			b, err := f.activate(t, d, tunnelv1.ConnectorHandoffID{})
			if err != nil {
				t.Fatal(err)
			}
			until, saved := b.until, d.claim.receipt
			f.acceptor.Claim = connectorClaimFunc(func(ctx context.Context, _ relayv1.RelayLease, _ netip.Addr, _ tunnelv1.ConnectorPairLegProof, _ []byte) (relayv1.ConnectorPeerPairLegClaim, error) {
				f.publisher.Close()
				if ctx.Err() != context.Canceled {
					t.Error("publisher teardown did not cancel the production claim context", ctx.Err())
				}
				if test.name == "cancellation only" {
					return relayv1.ConnectorPeerPairLegClaim{}, ctx.Err()
				}
				return relayv1.ConnectorPeerPairLegClaim{}, test.err
			})
			next, err := d.renew(d.ctx, f.acceptor, outer, d.proof)
			var protocol *tunnel.ProtocolError
			if !errors.As(err, &protocol) || protocol.Code != test.want || !errors.Is(err, test.err) {
				t.Fatal("canceled control operation lost its first wire code or cause", err)
			}
			if next != (tunnelv1.ConnectorPairLegAccepted{}) || b.until != until || d.claim.receipt != saved {
				t.Fatal("canceled control operation returned or changed authority")
			}
		})
	}
}

func TestConnectorClaimCancellationCauseIsPreservedOnRenewalWire(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want tunnelv1.ErrorCode
	}{
		{"denial", &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}, tunnelv1.Unauthenticated},
		{"stale source", &tunnel.ProtocolError{Code: tunnelv1.StaleNetworkBinding}, tunnelv1.StaleNetworkBinding},
		{"operation failure", errors.New("independent operation failure"), tunnelv1.Unauthenticated},
	} {
		for _, returnedError := range []bool{false, true} {
			name := fmt.Sprintf("%s/returned-error=%t", test.name, returnedError)
			t.Run(name, func(t *testing.T) {
				f := newConnectorBindingFixture(t)
				d, outer := f.candidate(t, 1, "192.0.2.1:12345")
				ctx, cancel := context.WithCancelCause(t.Context())
				defer cancel(context.Canceled)
				prior := f.acceptor.Claim
				cause := errors.Join(context.Canceled, test.err)
				f.acceptor.Claim = connectorClaimFunc(func(ctx context.Context, lease relayv1.RelayLease, source netip.Addr, proof tunnelv1.ConnectorPairLegProof, signature []byte) (relayv1.ConnectorPeerPairLegClaim, error) {
					claim, err := prior.ClaimConnectorPeerPairLegFromAcceptedSocket(ctx, lease, source, proof, signature)
					cancel(cause)
					if returnedError {
						return relayv1.ConnectorPeerPairLegClaim{}, ctx.Err()
					}
					return claim, err
				})
				server, client := net.Pipe()
				defer client.Close()
				defer server.Close()
				_ = client.SetDeadline(time.Now().Add(3 * time.Second))
				transport := newForwardingTestSession(&forwardingTestStream{Conn: server})
				defer transport.Close()
				joined := relayWorker(t, func() { _ = client.Close(); _ = transport.Close() }, func() error {
					session, _, err := tunnel.AcceptWithResult(t.Context(), transport, func(context.Context, tunnelv1.Message) (*tunnelv1.ConnectorPairLegAccepted, error) {
						return &d.claim.receipt, nil
					})
					if err != nil {
						return err
					}
					defer session.Close()
					// keep the wire open to observe the production serializer's code,
					// independently of the canceled claim's I/O deadline race.
					return session.HandleConnectorLegControl(t.Context(), nil, func(context.Context, tunnelv1.ConnectorPairLegProof) (tunnelv1.ConnectorPairLegAccepted, error) {
						claim, err := f.acceptor.claim(ctx, outer, d.proof)
						if claim != (connectorClaim{}) {
							t.Error("canceled claim returned authority")
						}
						return tunnelv1.ConnectorPairLegAccepted{}, err
					})
				})
				if err := tunnelv1.WriteControl(client, tunnelv1.Message{Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version, Role: tunnelv1.Connector, ConnectorPairLegProof: &d.proof}); err != nil {
					t.Fatal(err)
				}
				if response, err := tunnelv1.ReadControl(client); err != nil || response.Type != tunnelv1.HelloAccepted {
					t.Fatal("connector handshake failed", response.Type, err)
				}
				if err := tunnelv1.WriteControl(client, tunnelv1.Message{Type: tunnelv1.ConnectorLegRenew, ProtocolVersion: tunnelv1.Version, RequestID: "renew", Role: tunnelv1.Connector, ConnectorPairLegProof: &d.proof}); err != nil {
					t.Fatal(err)
				}
				response, err := tunnelv1.ReadControl(client)
				_ = client.Close()
				original := relayAwait(t, joined)
				if err != nil || response.Type != tunnelv1.Error || response.Code != test.want || response.RequestID != "renew" {
					t.Fatal("serialized renewal code hid the cancellation cause", response.Code, err)
				}
				if !errors.Is(original, test.err) || !errors.Is(original, context.Canceled) {
					t.Fatal("server discarded independent cancellation causes", original)
				}
			})
		}
	}
}

func TestConnectorDeliveryRenewalCancellationCauseUsesFirstProtocolCode(t *testing.T) {
	for _, stage := range []string{"before claim", "during claim", "bridge"} {
		for _, test := range []struct {
			name string
			err  error
			want tunnelv1.ErrorCode
		}{
			{"cancellation only", nil, tunnelv1.Unavailable},
			{"denial", &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}, tunnelv1.Unauthenticated},
			{"stale source", &tunnel.ProtocolError{Code: tunnelv1.StaleNetworkBinding}, tunnelv1.StaleNetworkBinding},
			{"operation failure", errors.New("independent operation failure"), tunnelv1.Unauthenticated},
		} {
			t.Run(stage+"/"+test.name, func(t *testing.T) {
				f := newConnectorBindingFixture(t)
				d, outer := f.candidate(t, 1, "192.0.2.1:12345")
				ctx, cancel := context.WithCancelCause(t.Context())
				defer cancel(context.Canceled)
				d.ctx = ctx
				bridge, cancelBridge := context.WithCancelCause(t.Context())
				defer cancelBridge(context.Canceled)
				b := isolatedConnectorBridge(t, d, bridge)
				until, saved := b.until, d.claim.receipt
				cause := errors.Join(context.Canceled, test.err)
				prior, calls := f.acceptor.Claim, 0
				f.acceptor.Claim = connectorClaimFunc(func(ctx context.Context, lease relayv1.RelayLease, source netip.Addr, proof tunnelv1.ConnectorPairLegProof, signature []byte) (relayv1.ConnectorPeerPairLegClaim, error) {
					calls++
					claim, err := prior.ClaimConnectorPeerPairLegFromAcceptedSocket(ctx, lease, source, proof, signature)
					if stage == "bridge" {
						cancelBridge(cause)
					} else {
						cancel(cause)
					}
					return claim, err
				})
				wantCalls := 1
				if stage == "before claim" {
					cancel(cause)
					wantCalls = 0
				}
				next, err := d.renew(d.ctx, f.acceptor, outer, d.proof)
				var protocol *tunnel.ProtocolError
				if !errors.As(err, &protocol) || protocol.Code != test.want || !errors.Is(err, context.Canceled) || test.err != nil && !errors.Is(err, test.err) {
					t.Fatal("renewal's first protocol code hid its cause tree", err)
				}
				if calls != wantCalls || next != (tunnelv1.ConnectorPairLegAccepted{}) || b.until != until || d.claim.receipt != saved {
					t.Fatal("canceled renewal called control or installed authority", calls, wantCalls)
				}
			})
		}
	}
}
