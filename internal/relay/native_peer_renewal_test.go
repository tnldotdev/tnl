package relay

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/peer"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestNativePeerDeliveryRenewalKeepsRegistrationsPastOriginalDeadline(t *testing.T) {
	for _, kind := range []string{"quic", "tls_yamux"} {
		t.Run(kind, func(t *testing.T) {
			var claims atomic.Int32
			claim := nativeClaimFunc(func(_ context.Context, _ relayv1.RelayLease, source netip.Addr, proof tunnelv1.NativePairLegProof, _ []byte) (relayv1.NativePeerPairLegClaim, error) {
				result := nativeTestClaim(source, proof)
				if claims.Add(1) == 1 {
					result.ExpiresAt = result.ObservedAt.Add(500 * time.Millisecond)
				} else {
					if proof.Nonce[0] != 1 {
						t.Error("claim renewal lost fresh proof")
					}
					result.ExpiresAt = result.ObservedAt.Add(2 * time.Second)
				}
				return result, nil
			})
			acceptor, owner, hello := nativeAdmissionFixture(t, 4, claim)
			publisherTransport, _, _ := nativeDeliveryPublisher(t, kind, acceptor, owner, hello)
			publisherPackets := nativeTestPacketOwner(t, publisherTransport)
			id, _ := tunnelv1.ParsePeerDeliveryIdentifier(nativeTestDeliveryID)
			binding := peer.PairBinding{Delivery: tunnelv1.PeerDelivery{Pair: id, Generation: 1}, Key: [32]byte{1}, Kind: peer.NativePeer, Role: 1}
			published := publisherPackets.register(t, binding, false)
			transport, exited := nativePacketTransport(t, kind, acceptor)
			session, receipt, err := tunnel.DialNative(t.Context(), transport, hello, nativeTestDeliveryID)
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			if err := session.ActivateNativeLeg(t.Context(), "activate"); err != nil {
				t.Fatal(err)
			}
			binding.Role = 0
			connected := nativeTestPacketOwner(t, transport).register(t, binding, true)
			exchange := func(sequence uint64) {
				t.Helper()
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				defer cancel()
				frame := nativeDeliveryFrame(t, binding, sequence, byte(sequence))
				if err := connected.carrier(t, ctx).Send(ctx, frame); err != nil {
					t.Fatal(err)
				}
				got, err := published.carrier(t, ctx).Receive(ctx)
				if err != nil || !bytes.Equal(got, frame) {
					t.Fatal("claim renewal replaced packet registration", err)
				}
			}
			exchange(1)
			proof := *hello.NativePairLegProof
			proof.RequestedAt, proof.Nonce = time.Now(), bytes.Repeat([]byte{1}, 32)
			renewed, err := session.RenewNativeLeg(t.Context(), "renew", proof, receipt)
			if err != nil || !renewed.ExpiresAt.After(receipt.ExpiresAt) {
				t.Fatal("checked relay renewal", err)
			}
			// the original claim has expired, but both existing registrations
			// remain usable under the fresh checked proof on this same session.
			time.Sleep(time.Until(receipt.ExpiresAt) + 20*time.Millisecond)
			exchange(2)
			owner.mu.Lock()
			live := owner.sessions
			owner.mu.Unlock()
			if live != 1 || claims.Load() != 2 {
				t.Fatal("renewal allocated another session or repeated admission", live, claims.Load())
			}
			_ = session.Close()
			if err := relayAwait(t, exited); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNativePeerDeliveryRenewalCannotReviveOrRebindOwner(t *testing.T) {
	for _, outcome := range []string{"accepted", "narrower", "expired", "stopped", "canceled", "late success", "different key", "different source", "temporary failure"} {
		t.Run(outcome, func(t *testing.T) {
			now := time.Now()
			active := false
			calls := 0
			claim := nativeClaimFunc(func(_ context.Context, _ relayv1.RelayLease, source netip.Addr, proof tunnelv1.NativePairLegProof, _ []byte) (relayv1.NativePeerPairLegClaim, error) {
				result := nativeTestClaim(source, proof)
				result.ObservedAt, result.ExpiresAt = now, now.Add(time.Minute)
				if active {
					calls++
					switch outcome {
					case "narrower":
						result.ExpiresAt = now.Add(10 * time.Second)
					case "late success":
						now = now.Add(31 * time.Second)
					case "different key":
						result.Key = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
					case "different source":
						result.SourceIp = "127.0.0.2"
					case "temporary failure":
						return relayv1.NativePeerPairLegClaim{}, &ControlProblemError{Status: 503}
					}
				}
				return result, nil
			})
			_, owner, hello := nativeAdmissionFixture(t, 1, claim)
			owner.Now = func() time.Time { return now }
			initial, err := owner.claim(t.Context(), socketIdentityOnly{}, *hello.NativePairLegProof)
			if err != nil {
				t.Fatal(err)
			}
			connection := &serviceConnection{ref: initial.ref, lease: owner.CurrentLease(), paths: &streamLifetime{}, packets: &nativePacketSession{}}
			owner.Publishers = NewServiceRegistry()
			owner.Publishers.connections[initial.ref.PublisherConnectionID] = connection
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			delivery := &nativePairDelivery{ctx: ctx, cancel: cancel, connection: connection, deadline: now.Add(30 * time.Second), changed: make(chan struct{})}
			switch outcome {
			case "expired":
				delivery.deadline = now
			case "stopped":
				delivery.closed = true
			case "canceled":
				cancel()
			}
			old := delivery.deadline
			active = true
			_, err = delivery.renewClaim(ctx, owner, socketIdentityOnly{}, *hello.NativePairLegProof, initial)
			allowed := outcome == "accepted" || outcome == "narrower"
			if (err == nil) != allowed {
				t.Fatal("unexpected renewal decision", outcome, err)
			}
			if !allowed && !delivery.deadline.Equal(old) {
				t.Fatal("denied or late renewal changed local authority")
			}
			if outcome == "narrower" && !delivery.deadline.Equal(now.Add(10*time.Second)) {
				t.Fatal("renewal did not narrow authority")
			}
			if (outcome == "expired" || outcome == "stopped" || outcome == "canceled") && calls != 0 {
				t.Fatal("stopped owner contacted control")
			}
		})
	}
}
