package relay

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"testing/synctest"
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
			until, receipt := b.until, d.claim.receipt
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
			if calls != wantCalls || next != (tunnelv1.ConnectorPairLegAccepted{}) || b.until != until || d.claim.receipt != receipt || d.ctx.Err() == nil {
				t.Fatal("retired delivery returned or changed authority", calls, wantCalls)
			}
		})
	}
}

func TestConnectorDeliveryRenewalDenialPrecedesConcurrentPublisherLoss(t *testing.T) {
	for _, boundary := range []string{"control denial", "changed key", "expired binding", "binding expires during claim", "binding state regresses"} {
		t.Run(boundary, func(t *testing.T) {
			f := newConnectorBindingFixture(t)
			d, outer := f.candidate(t, 1, "192.0.2.1:12345")
			b, err := f.activate(t, d, tunnelv1.ConnectorHandoffID{})
			if err != nil {
				t.Fatal(err)
			}
			denied := &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
			prior := f.acceptor.Claim
			var until time.Time
			f.acceptor.Claim = connectorClaimFunc(func(ctx context.Context, lease relayv1.RelayLease, source netip.Addr, proof tunnelv1.ConnectorPairLegProof, signature []byte) (relayv1.ConnectorPeerPairLegClaim, error) {
				claim, err := prior.ClaimConnectorPeerPairLegFromAcceptedSocket(ctx, lease, source, proof, signature)
				if boundary == "changed key" {
					key := [32]byte{9}
					claim.Key = base64.RawURLEncoding.EncodeToString(key[:])
				}
				if boundary == "binding expires during claim" {
					b.mu.Lock()
					b.until = time.Now().Add(-time.Second)
					until = b.until
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
			if boundary == "expired binding" {
				b.mu.Lock()
				b.until = time.Now().Add(-time.Second)
				b.mu.Unlock()
				f.publisher.Close()
			}
			until = b.until
			next, err := d.renew(d.ctx, f.acceptor, outer, d.proof)
			var protocol *tunnel.ProtocolError
			if !errors.As(err, &protocol) || protocol.Code != tunnelv1.Unauthenticated || next != (tunnelv1.ConnectorPairLegAccepted{}) || b.until != until {
				t.Fatal("teardown hid denial or revived expired authority", err)
			}
			if boundary == "control denial" && !errors.Is(err, denied) {
				t.Fatal("control denial cause was lost", err)
			}
		})
	}
}

func TestConnectorClaimCanceledResponseDoesNotReturnAuthorityOrDenial(t *testing.T) {
	for _, response := range []string{"valid claim", "denied claim", "invalid claim", "missing binding state"} {
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
				if response == "missing binding state" {
					claim.BindingState = ""
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

func TestConnectorDeliveryRenewalSpentAuthorityPrecedesCancellation(t *testing.T) {
	for _, boundary := range []string{"candidate expiry", "binding expiry", "superseded carrier"} {
		for _, controlError := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/control-error=%t", boundary, controlError), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					f := newConnectorBindingFixture(t)
					if boundary == "candidate expiry" {
						f.duration = 5 * time.Second
					}
					d, outer := f.candidate(t, 1, "192.0.2.1:12345")
					// no asynchronous bridge worker: the control result and retained
					// authority change are ordered exactly, without a real-clock wait.
					b := &connectorBridge{ctx: d.ctx, active: d, until: d.claim.receipt.ExpiresAt, state: d.claim.receipt.BindingState}
					if boundary != "candidate expiry" {
						b = isolatedConnectorBridge(t, d, d.ctx)
					}
					prior := f.acceptor.Claim
					var until time.Time
					saved := d.claim.receipt
					f.acceptor.Claim = connectorClaimFunc(func(ctx context.Context, lease relayv1.RelayLease, source netip.Addr, proof tunnelv1.ConnectorPairLegProof, signature []byte) (relayv1.ConnectorPeerPairLegClaim, error) {
						claim, err := prior.ClaimConnectorPeerPairLegFromAcceptedSocket(ctx, lease, source, proof, signature)
						switch boundary {
						case "candidate expiry":
							time.Sleep(time.Until(d.claim.receipt.ExpiresAt))
							claim.ObservedAt = time.Now()
							claim.ExpiresAt = claim.ObservedAt.Add(5 * time.Second)
						case "binding expiry":
							b.until = time.Now().Add(-time.Second)
						case "superseded carrier":
							b.active = nil
						}
						until = b.until
						d.cancel()
						if controlError {
							return relayv1.ConnectorPeerPairLegClaim{}, ctx.Err()
						}
						return claim, err
					})
					receipt, err := d.renew(d.ctx, f.acceptor, outer, d.proof)
					var protocol *tunnel.ProtocolError
					want := tunnelv1.Unauthenticated
					if boundary == "superseded carrier" {
						want = tunnelv1.Unavailable
					}
					if !errors.As(err, &protocol) || protocol.Code != want || !errors.Is(err, context.Canceled) || receipt != (tunnelv1.ConnectorPairLegAccepted{}) {
						t.Fatal("canceled control result hid spent retained authority", err)
					}
					if b.until != until || d.claim.receipt != saved {
						t.Fatal("canceled renewal changed retained authority")
					}
				})
			})
		}
	}
}

func TestConnectorDeliveryRenewalKeepsIndependentCallerCancellationCause(t *testing.T) {
	f := newConnectorBindingFixture(t)
	d, outer := f.candidate(t, 1, "192.0.2.1:12345")
	denied := &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
	ctx, cancel := context.WithCancelCause(t.Context())
	cancel(denied)
	d.cancel()
	receipt, err := d.renew(ctx, f.acceptor, outer, d.proof)
	var protocol *tunnel.ProtocolError
	if !errors.As(err, &protocol) || protocol.Code != tunnelv1.Unauthenticated || !errors.Is(err, denied) || !errors.Is(err, context.Canceled) || receipt != (tunnelv1.ConnectorPairLegAccepted{}) {
		t.Fatal("publisher loss hid the caller's independent denial", err)
	}
}
