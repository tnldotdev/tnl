package relay

import (
	"context"
	"encoding/base64"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestConnectorDeliveryPublisherLossDuringRenewalIsNotAuthorizationDenial(t *testing.T) {
	for _, stage := range []string{"before claim", "during claim"} {
		t.Run(stage, func(t *testing.T) {
			f := newConnectorBindingFixture(t)
			d, outer := f.candidate(t, 1, "192.0.2.1:12345")
			b, err := f.activate(t, d, tunnelv1.ConnectorHandoffID{})
			if err != nil {
				t.Fatal(err)
			}
			until, bridgeUntil, receipt := d.until, b.until, d.claim.receipt
			prior, calls := f.acceptor.Claim, 0
			f.acceptor.Claim = connectorClaimFunc(func(ctx context.Context, lease relayv1.RelayLease, source netip.Addr, proof tunnelv1.ConnectorPairLegProof, signature []byte) (relayv1.ConnectorPeerPairLegClaim, error) {
				calls++
				claim, err := prior.ClaimConnectorPeerPairLegFromAcceptedSocket(ctx, lease, source, proof, signature)
				// join the actual publisher packet owner and its bridge before
				// returning the still-valid control claim to the renewal.
				f.publisher.Close()
				return claim, err
			})
			wantCalls := 1
			if stage == "before claim" {
				f.publisher.Close()
				wantCalls = 0
			}
			next, err := d.renew(d.ctx, f.acceptor, outer, d.proof)
			var protocol *tunnel.ProtocolError
			if !errors.As(err, &protocol) || protocol.Code != tunnelv1.Unavailable {
				t.Fatal("publisher transport loss became a terminal subject denial", err)
			}
			if !errors.Is(err, context.Canceled) {
				t.Fatal("delivery cancellation cause was lost", err)
			}
			if calls != wantCalls || next != (tunnelv1.ConnectorPairLegAccepted{}) || d.until != until || b.until != bridgeUntil || d.claim.receipt != receipt || d.ctx.Err() == nil {
				t.Fatal("retired delivery returned or changed authority", calls, wantCalls)
			}
		})
	}
}

func TestConnectorDeliveryRenewalDenialPrecedesConcurrentPublisherLoss(t *testing.T) {
	for _, boundary := range []string{"control denial", "changed key", "expired delivery", "delivery expires during claim", "bridge expires during claim", "binding state regresses"} {
		t.Run(boundary, func(t *testing.T) {
			f := newConnectorBindingFixture(t)
			d, outer := f.candidate(t, 1, "192.0.2.1:12345")
			b, err := f.activate(t, d, tunnelv1.ConnectorHandoffID{})
			if err != nil {
				t.Fatal(err)
			}
			denied := &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
			prior := f.acceptor.Claim
			var until, bridgeUntil time.Time
			f.acceptor.Claim = connectorClaimFunc(func(ctx context.Context, lease relayv1.RelayLease, source netip.Addr, proof tunnelv1.ConnectorPairLegProof, signature []byte) (relayv1.ConnectorPeerPairLegClaim, error) {
				claim, err := prior.ClaimConnectorPeerPairLegFromAcceptedSocket(ctx, lease, source, proof, signature)
				if boundary == "changed key" {
					key := [32]byte{9}
					claim.Key = base64.RawURLEncoding.EncodeToString(key[:])
				}
				if boundary == "delivery expires during claim" {
					d.mu.Lock()
					d.until = time.Now().Add(-time.Second)
					until = d.until
					d.mu.Unlock()
				}
				if boundary == "bridge expires during claim" {
					b.mu.Lock()
					b.until = time.Now().Add(-time.Second)
					bridgeUntil = b.until
					b.mu.Unlock()
				}
				if boundary == "binding state regresses" {
					claim.BindingState = relayv1.ConnectorPeerLegBindingPrepared
					claim.ExpiresAt = claim.ObservedAt.Add(time.Second)
				}
				f.publisher.Close()
				if boundary == "control denial" {
					return relayv1.ConnectorPeerPairLegClaim{}, denied
				}
				return claim, err
			})
			if boundary == "expired delivery" {
				d.until = time.Now().Add(-time.Second)
				f.publisher.Close()
			}
			until, bridgeUntil = d.until, b.until
			next, err := d.renew(d.ctx, f.acceptor, outer, d.proof)
			var protocol *tunnel.ProtocolError
			if !errors.As(err, &protocol) || protocol.Code != tunnelv1.Unauthenticated || next != (tunnelv1.ConnectorPairLegAccepted{}) || d.until != until || b.until != bridgeUntil {
				t.Fatal("teardown hid denial or revived expired authority", err)
			}
			if boundary == "control denial" && !errors.Is(err, denied) {
				t.Fatal("control denial cause was lost", err)
			}
		})
	}
}

func TestConnectorClaimCanceledResponseDoesNotReturnAuthorityOrDenial(t *testing.T) {
	for _, response := range []string{"valid claim", "denied claim", "invalid claim"} {
		t.Run(response, func(t *testing.T) {
			f := newConnectorBindingFixture(t)
			_, outer := f.candidate(t, 1, "192.0.2.1:12345")
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			prior := f.acceptor.Claim
			denied := &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
			f.acceptor.Claim = connectorClaimFunc(func(ctx context.Context, lease relayv1.RelayLease, source netip.Addr, proof tunnelv1.ConnectorPairLegProof, signature []byte) (relayv1.ConnectorPeerPairLegClaim, error) {
				claim, err := prior.ClaimConnectorPeerPairLegFromAcceptedSocket(ctx, lease, source, proof, signature)
				cancel()
				if response == "denied claim" {
					return relayv1.ConnectorPeerPairLegClaim{}, denied
				}
				if response == "invalid claim" {
					claim.Key = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
				}
				return claim, err
			})
			claim, err := f.acceptor.claim(ctx, outer, f.proof)
			var protocol *tunnel.ProtocolError
			want := tunnelv1.Unavailable
			if response != "valid claim" {
				want = tunnelv1.Unauthenticated
			}
			if !errors.As(err, &protocol) || protocol.Code != want || claim != (connectorClaim{}) {
				t.Fatal("canceled claim returned authority or lost classification", err)
			}
			if response == "denied claim" && !errors.Is(err, denied) || response == "valid claim" && !errors.Is(err, context.Canceled) {
				t.Fatal("claim cause was lost", err)
			}
		})
	}
}

func TestConnectorDeliveryRenewalRetiredBridgeReturnsNoAuthority(t *testing.T) {
	for _, boundary := range []string{"canceled", "expired", "superseded"} {
		t.Run(boundary, func(t *testing.T) {
			f := newConnectorBindingFixture(t)
			d, outer := f.candidate(t, 1, "192.0.2.1:12345")
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			// isolate the post-claim bridge check from its asynchronous worker's
			// delivery cancellation, covering either teardown ordering.
			b := &connectorBridge{ctx: ctx, active: d, until: d.until}
			d.bridge = b
			prior := f.acceptor.Claim
			f.acceptor.Claim = connectorClaimFunc(func(ctx context.Context, lease relayv1.RelayLease, source netip.Addr, proof tunnelv1.ConnectorPairLegProof, signature []byte) (relayv1.ConnectorPeerPairLegClaim, error) {
				claim, err := prior.ClaimConnectorPeerPairLegFromAcceptedSocket(ctx, lease, source, proof, signature)
				switch boundary {
				case "canceled":
					cancel()
				case "expired":
					b.until = time.Now().Add(-time.Second)
				case "superseded":
					b.active = nil
				}
				return claim, err
			})
			until := d.until
			next, err := d.renew(d.ctx, f.acceptor, outer, d.proof)
			want := tunnelv1.Unauthenticated
			if boundary == "canceled" {
				want = tunnelv1.Unavailable
			}
			var protocol *tunnel.ProtocolError
			if !errors.As(err, &protocol) || protocol.Code != want || next != (tunnelv1.ConnectorPairLegAccepted{}) || d.until != until {
				t.Fatal("retired bridge returned authority or lost classification", err)
			}
		})
	}
}
