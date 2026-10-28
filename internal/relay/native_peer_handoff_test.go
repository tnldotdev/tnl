package relay

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/peer"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestNativePeerHandoffKeepsPublisherRegistrationAndReplay(t *testing.T) {
	for _, publisherKind := range []string{"quic", "tls_yamux"} {
		for _, firstKind := range []string{"quic", "tls_yamux"} {
			t.Run(publisherKind+"/"+firstKind, func(t *testing.T) {
				claim := nativeClaimFunc(func(_ context.Context, _ relayv1.RelayLease, source netip.Addr, proof tunnelv1.NativePairLegProof, _ []byte) (relayv1.NativePeerPairLegClaim, error) {
					return nativeTestClaim(source, proof), nil
				})
				acceptor, owner, hello := nativeAdmissionFixture(t, 4, claim)
				publisherTransport, _, _ := nativeDeliveryPublisher(t, publisherKind, acceptor, owner, hello)
				id, _ := tunnelv1.ParsePeerDeliveryIdentifier(nativeTestDeliveryID)
				binding := peer.PairBinding{Delivery: tunnelv1.PeerDelivery{Pair: id, Generation: 1}, Key: [32]byte{1}, Kind: peer.NativePeer, Role: 1}
				published := nativeTestPacketOwner(t, publisherTransport).register(t, binding, false)
				binding.Role = 0
				kind := firstKind
				previous := bytes.Clone(hello.NativePairLegProof.Nonce)
				var original *nativePairBridge
				var deadline time.Time
				var retained *tunnel.Session
				var retainedDone <-chan error
				for attempt := range 3 {
					transport, exited := nativePacketTransport(t, kind, acceptor)
					proof := *hello.NativePairLegProof
					proof.Nonce = bytes.Repeat([]byte{byte(attempt)}, 32)
					message := hello
					message.NativePairLegProof = &proof
					session, _, err := tunnel.DialNative(t.Context(), transport, message, nativeTestDeliveryID)
					if err != nil {
						t.Fatal(err)
					}
					if attempt == 0 {
						err = session.ActivateNativeLeg(t.Context(), "initial")
					} else {
						err = session.HandoffNativeLeg(t.Context(), "handoff", previous)
					}
					if err != nil {
						t.Fatal("selected carrier could not install", err)
					}
					if retained != nil {
						_ = relayAwait(t, retainedDone)
						select {
						case <-retained.Done():
						case <-time.After(time.Second):
							t.Fatal("handoff did not retire the old live candidate")
						}
						retained = nil
					}
					owner.Publishers.mu.Lock()
					for _, connection := range owner.Publishers.connections {
						connection.packets.mu.Lock()
						current := connection.packets.bridges[id]
						if current == nil {
							t.Fatal("selected carrier has no bridge")
						}
						current.mu.Lock()
						if attempt == 0 {
							original, deadline = current, current.deadline
						} else if current != original || current.deadline.After(deadline) {
							t.Error("handoff replaced registration or extended authority")
						}
						current.mu.Unlock()
						connection.packets.mu.Unlock()
					}
					owner.Publishers.mu.Unlock()
					connected := nativeTestPacketOwner(t, transport).register(t, binding, true)
					ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
					// replay a previous frame through a new outer session. the retained
					// publisher registration must discard it before delivering the next.
					if attempt > 0 {
						if err := connected.carrier(t, ctx).Send(ctx, nativeDeliveryFrame(t, binding, uint64(attempt), byte(attempt))); err != nil {
							t.Fatal(err)
						}
					}
					frame := nativeDeliveryFrame(t, binding, uint64(attempt+1), byte(attempt+1))
					if err := connected.carrier(t, ctx).Send(ctx, frame); err != nil {
						t.Fatal(err)
					}
					publishedCarrier := published.carrier(t, ctx)
					if got, err := publishedCarrier.Receive(ctx); err != nil || !bytes.Equal(got, frame) {
						t.Fatal("handoff lost delivery or publisher replay state", err)
					}
					reverse := binding
					reverse.Role = 1
					frame = nativeDeliveryFrame(t, reverse, uint64(attempt+1), byte(attempt+2))
					if err := publishedCarrier.Send(ctx, frame); err != nil {
						t.Fatal(err)
					}
					if got, err := connected.carrier(t, ctx).Receive(ctx); err != nil || !bytes.Equal(got, frame) {
						t.Fatal("handoff lost reverse delivery", err)
					}
					cancel()
					if attempt == 0 {
						retained, retainedDone = session, exited
					} else {
						if attempt == 1 && kind == "tls_yamux" {
							// a protocol failure on the packet stream must also retire
							// its control owner so the next handoff can recover it.
							ctx, finish := context.WithTimeout(t.Context(), time.Second)
							if err := connected.carrier(t, ctx).Send(ctx, nativeDeliveryFrame(t, binding, uint64(attempt+1), byte(attempt+1))); err != nil {
								t.Fatal(err)
							}
							select {
							case <-session.Done():
							case <-ctx.Done():
								t.Fatal("failed packet carrier left its control owner alive")
							}
							finish()
						}
						_ = session.Close()
						_ = relayAwait(t, exited)
					}
					previous = bytes.Clone(proof.Nonce)
					kind = map[string]string{"quic": "tls_yamux", "tls_yamux": "quic"}[kind]
				}
				for _, failure := range []string{"consumed predecessor", "reused candidate", "expired bridge"} {
					transport, exited := nativePacketTransport(t, firstKind, acceptor)
					proof := *hello.NativePairLegProof
					proof.Nonce = bytes.Repeat([]byte{9}, 32)
					predecessor := previous
					switch failure {
					case "consumed predecessor":
						predecessor = make([]byte, 32)
					case "reused candidate":
						proof.Nonce = make([]byte, 32)
					case "expired bridge":
						original.mu.Lock()
						original.deadline = time.Now()
						original.mu.Unlock()
					}
					message := hello
					message.NativePairLegProof = &proof
					session, _, err := tunnel.DialNative(t.Context(), transport, message, nativeTestDeliveryID)
					if err != nil {
						t.Fatal(err)
					}
					var rejected *tunnel.ProtocolError
					if err := session.HandoffNativeLeg(t.Context(), "stale", predecessor); !errors.As(err, &rejected) || (rejected.Code != tunnelv1.Unauthenticated && rejected.Code != tunnelv1.Unavailable) {
						t.Fatal("invalid handoff displaced current registration", failure, err)
					}
					_ = session.Close()
					// outer close can overtake the queued error frame. the server
					// must retain the exact denial even when the client sees ambiguity.
					if err := relayAwait(t, exited); !errors.As(err, &rejected) || rejected.Code != tunnelv1.Unauthenticated {
						t.Fatal("handoff lost its server-side rejection", failure, err)
					}
					original.mu.Lock()
					unchanged := bytes.Equal(original.nonce, previous) && !original.deadline.After(deadline)
					original.mu.Unlock()
					if !unchanged {
						t.Fatal("denied handoff changed the selected binding or deadline")
					}
				}
			})
		}
	}
}

func TestNativePeerHandoffBoundsAndFencesRetainedAuthority(t *testing.T) {
	for _, changed := range []string{"source", "key", "assignment", "expired", "canceled", "request canceled", "closed publisher", "candidate limit"} {
		t.Run(changed, func(t *testing.T) {
			claimClient := nativeClaimFunc(func(_ context.Context, _ relayv1.RelayLease, source netip.Addr, proof tunnelv1.NativePairLegProof, _ []byte) (relayv1.NativePeerPairLegClaim, error) {
				return nativeTestClaim(source, proof), nil
			})
			_, owner, hello := nativeAdmissionFixture(t, 2, claimClient)
			proof := *hello.NativePairLegProof
			claim, err := owner.claim(t.Context(), socketIdentityOnly{}, proof)
			if err != nil {
				t.Fatal(err)
			}
			life, stop := context.WithCancel(t.Context())
			defer stop()
			id, _ := tunnelv1.ParsePeerDeliveryIdentifier(nativeTestDeliveryID)
			oldNonce := bytes.Repeat([]byte{7}, 32)
			deadline := time.Now().Add(time.Minute)
			bridge := &nativePairBridge{ctx: life, cancel: stop, proof: proof, claim: claim, nonce: oldNonce,
				deadline: deadline, used: map[[32]byte]struct{}{[32]byte(oldNonce): {}}}
			packets := &nativePacketSession{ctx: t.Context(), bridges: map[[16]byte]*nativePairBridge{id: bridge}}
			delivery := &nativePairDelivery{deadline: deadline, changed: make(chan struct{})}
			request, cancel := context.WithCancel(t.Context())
			defer cancel()
			want := tunnelv1.Unauthenticated
			switch changed {
			case "source":
				claim.receipt.SourceIP = "127.0.0.2"
			case "key":
				claim.key[0]++
			case "assignment":
				proof.AssignmentRevision++
			case "expired":
				bridge.deadline = time.Now()
			case "canceled":
				stop()
			case "request canceled":
				cancel()
			case "closed publisher":
				packets.closed = true
			case "candidate limit":
				for n := byte(1); len(bridge.used) < maxNativeCarrierCandidates; n++ {
					bridge.used[[32]byte{n}] = struct{}{}
				}
				want = tunnelv1.CapacityExceeded
			}
			selection := tunnelv1.NativeLegBinding{Nonce: proof.Nonce, PreviousNonce: oldNonce}
			selected, err := packets.selectNativeBridge(request, owner, delivery, proof, claim, id, selection)
			var rejected *tunnel.ProtocolError
			if selected != nil || !errors.As(err, &rejected) || rejected.Code != want {
				t.Fatal("invalid handoff reached carrier installation", changed, err)
			}
			if bridge.active != nil || !bytes.Equal(bridge.nonce, oldNonce) || bridge.deadline.After(deadline) {
				t.Fatal("rejected handoff changed retained authority")
			}
		})
	}
}
