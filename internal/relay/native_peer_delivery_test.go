package relay

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/peer"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func nativePacketTransport(t *testing.T, kind string, acceptor *PublisherAcceptor) (muxsession.Session, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	t.Cleanup(cancel)
	root, cert := testutil.TLSCertificate(t, []string{"relay.test"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(root) {
		t.Fatal("invalid test root")
	}
	serverTLS := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	clientTLS := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}
	var client muxsession.Session
	var done <-chan error
	var err error
	if kind == "quic" {
		config := muxsession.QUICConfig{Config: &quic.Config{EnableDatagrams: true}}
		listener, listenErr := muxsession.ListenQUIC("127.0.0.1:0", serverTLS, config)
		if listenErr != nil {
			t.Fatal(listenErr)
		}
		t.Cleanup(func() { _ = listener.Close() })
		done = relayWorker(t, func() { cancel(); _ = listener.Close() }, func() error {
			accepted, err := listener.Accept(ctx)
			if err != nil {
				return err
			}
			return acceptor.Accept(ctx, accepted)
		})
		client, err = (muxsession.QUICConnector{TLSConfig: clientTLS, Config: config}).Connect(ctx,
			muxsession.Endpoint{Address: listener.Addr().String(), ServerName: "relay.test"})
	} else {
		listener, listenErr := net.Listen("tcp", "127.0.0.1:0")
		if listenErr != nil {
			t.Fatal(listenErr)
		}
		t.Cleanup(func() { _ = listener.Close() })
		done = relayWorker(t, func() { cancel(); _ = listener.Close() }, func() error {
			conn, err := listener.Accept()
			if err != nil {
				return err
			}
			defer conn.Close()
			accepted, err := muxsession.AcceptTLSYamux(ctx, conn, serverTLS, muxsession.TLSYamuxConfig{})
			if err != nil {
				return err
			}
			return acceptor.Accept(ctx, accepted)
		})
		client, err = (muxsession.TLSYamuxConnector{TLSConfig: clientTLS}).Connect(ctx,
			muxsession.Endpoint{Address: listener.Addr().String(), ServerName: "relay.test"})
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client, done
}

type nativePublisherControl struct {
	privateClaimControlStub
	ref tunnelv1.ServicePublisherConnectionRef
}

func (c *nativePublisherControl) ReadyServicePublisherConnection(_ context.Context, id string, body relayv1.ServicePublisherConnectionTransition) (relayv1.ServicePublisherConnection, error) {
	return relayv1.ServicePublisherConnection{ServiceId: c.ref.ServiceID, ServiceRunId: body.ServiceRunId, RunNumber: body.RunNumber,
		PublisherConnectionId: id, ConnectionAssignmentRevision: body.ConnectionAssignmentRevision, RelayServiceId: c.ref.RelayServiceID}, nil
}

func nativeDeliveryPublisher(t *testing.T, kind string, acceptor *PublisherAcceptor, owner *NativeConnectorAcceptor, hello tunnelv1.Message) (muxsession.Session, *tunnel.Session, <-chan struct{}) {
	t.Helper()
	registry := NewServiceRegistry()
	t.Cleanup(func() { _ = registry.Close() })
	owner.Publishers = registry
	client := new(nativePublisherControl)
	controller := &Controller{client: client, now: time.Now, lease: owner.CurrentLease()}
	acceptor.private = &ServicePublisherAcceptor{Select: func(string) (ServicePublisherTarget, bool) {
		return ServicePublisherTarget{Control: controller, Registry: registry}, true
	}}
	ready := make(chan struct{}, 1)
	acceptor.readyDelta = func(delta int) {
		if delta == 1 {
			ready <- struct{}{}
		}
	}
	proof := hello.NativePairLegProof
	ref := tunnelv1.ServicePublisherConnectionRef{ServiceID: proof.ServiceID, ServiceRunID: proof.ServiceRunID, RunNumber: uint64(proof.RunNumber),
		PublisherConnectionID: proof.PublisherConnectionID, ConnectionSlot: uint8(proof.ConnectionSlot),
		ConnectionAssignmentRevision: uint64(proof.AssignmentRevision), RelayServiceID: proof.RelayServiceID}
	client.ref = ref
	transport, done := nativePacketTransport(t, kind, acceptor)
	session, err := tunnel.Dial(t.Context(), transport, tunnelv1.Message{Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version,
		Role: tunnelv1.Publisher, ServiceConnection: &ref, Credential: "publisher-credential"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("publisher exited before readiness: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("publisher did not become ready")
	}
	return transport, session, ready
}

type nativeTestPackets struct {
	datagrams *peer.SharedDatagrams
	streams   *peer.SharedStreams
}

func nativeTestPacketOwner(t *testing.T, transport muxsession.Session) nativeTestPackets {
	t.Helper()
	var p nativeTestPackets
	var err error
	if datagrams, ok := transport.(muxsession.DatagramSession); ok {
		p.datagrams, err = peer.NewSharedDatagrams(t.Context(), datagrams)
		t.Cleanup(func() {
			if p.datagrams != nil {
				_ = p.datagrams.Close()
			}
		})
	} else {
		p.streams, err = peer.NewSharedStreams(t.Context(), transport)
		t.Cleanup(func() {
			if p.streams != nil {
				_ = p.streams.Close()
			}
		})
	}
	if err != nil {
		t.Fatal(err)
	}
	return p
}

type nativeTestRegistration struct {
	live peer.Carrier
	pair *peer.StreamPair
}

func (p nativeTestPackets) register(t *testing.T, binding peer.PairBinding, open bool) *nativeTestRegistration {
	t.Helper()
	r := new(nativeTestRegistration)
	var err error
	if p.datagrams != nil {
		r.live, err = p.datagrams.Register(binding)
	} else {
		r.pair, err = p.streams.Register(binding)
		if err == nil && open {
			r.live, err = r.pair.Open(t.Context())
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *nativeTestRegistration) carrier(t *testing.T, ctx context.Context) peer.Carrier {
	t.Helper()
	if r.live == nil {
		var err error
		r.live, err = r.pair.Accept(ctx)
		if err != nil {
			t.Fatal(err)
		}
	}
	return r.live
}

func nativeDeliveryFrame(t *testing.T, binding peer.PairBinding, sequence uint64, payload byte) []byte {
	t.Helper()
	p := tunnelv1.PeerPacket{Kind: tunnelv1.PeerData, Sender: binding.Role, Path: binding.Path,
		Sequence: sequence, Total: 1, Payload: []byte{payload}}
	unsigned, err := p.AuthenticatedBytes()
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, binding.Key[:])
	_, _ = mac.Write([]byte(binding.Kind))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(unsigned)
	copy(p.MAC[:], mac.Sum(nil))
	frame, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func TestNativePeerDeliveryCrossTransportAndPairIsolation(t *testing.T) {
	for _, publisherKind := range []string{"quic", "tls_yamux"} {
		for _, connectorKind := range []string{"quic", "tls_yamux"} {
			t.Run(publisherKind+"/"+connectorKind, func(t *testing.T) {
				claim := nativeClaimFunc(func(_ context.Context, _ relayv1.RelayLease, source netip.Addr, proof tunnelv1.NativePairLegProof, _ []byte) (relayv1.NativePeerPairLegClaim, error) {
					result := nativeTestClaim(source, proof)
					if proof.PairID != "npp_1234567890123456789012" {
						id := [16]byte{2}
						result.DeliveryId = base64.RawURLEncoding.EncodeToString(id[:])
					}
					return result, nil
				})
				acceptor, owner, hello := nativeAdmissionFixture(t, 4, claim)
				if publisherKind == "tls_yamux" {
					hello.NativePairLegProof.ConnectionSlot = 1
				}
				publisherTransport, publisher, _ := nativeDeliveryPublisher(t, publisherKind, acceptor, owner, hello)
				publisherPackets := nativeTestPacketOwner(t, publisherTransport)
				type path struct {
					session              *tunnel.Session
					done                 <-chan error
					connector, publisher *nativeTestRegistration
					binding              peer.PairBinding
				}
				start := func(message tunnelv1.Message, deliveryID string) path {
					t.Helper()
					id, err := tunnelv1.ParsePeerDeliveryIdentifier(deliveryID)
					if err != nil {
						t.Fatal(err)
					}
					binding := peer.PairBinding{Delivery: tunnelv1.PeerDelivery{Pair: id, Generation: 1}, Key: [32]byte{1}, Kind: peer.NativePeer,
						Role: 1, Path: uint8(message.NativePairLegProof.ConnectionSlot)}
					published := publisherPackets.register(t, binding, false)
					transport, done := nativePacketTransport(t, connectorKind, acceptor)
					session, _, err := tunnel.DialNative(t.Context(), transport, message, deliveryID)
					if err != nil {
						t.Fatal(err)
					}
					if err := session.ActivateNativeLeg(t.Context(), "activate"); err != nil {
						t.Fatal(err)
					}
					binding.Role = 0
					connected := nativeTestPacketOwner(t, transport).register(t, binding, true)
					return path{session: session, done: done, connector: connected, publisher: published, binding: binding}
				}
				first := start(hello, nativeTestDeliveryID)
				siblingProof := *hello.NativePairLegProof
				siblingProof.PairID = "npp_abcdefghijklmnopqrstuv"
				siblingHello := hello
				siblingHello.NativePairLegProof = &siblingProof
				id := [16]byte{2}
				sibling := start(siblingHello, base64.RawURLEncoding.EncodeToString(id[:]))
				exchange := func(p path, sequence uint64, value byte) {
					t.Helper()
					ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
					defer cancel()
					frame := nativeDeliveryFrame(t, p.binding, sequence, value)
					if err := p.connector.carrier(t, ctx).Send(ctx, frame); err != nil {
						t.Fatal(err)
					}
					published := p.publisher.carrier(t, ctx)
					if got, err := published.Receive(ctx); err != nil || !bytes.Equal(got, frame) {
						t.Fatalf("connector packet changed or crossed pairs: %v", err)
					}
					reverse := p.binding
					reverse.Role = 1
					frame = nativeDeliveryFrame(t, reverse, sequence, value+1)
					if err := published.Send(ctx, frame); err != nil {
						t.Fatal(err)
					}
					if got, err := p.connector.carrier(t, ctx).Receive(ctx); err != nil || !bytes.Equal(got, frame) {
						t.Fatalf("publisher packet changed or crossed pairs: %v", err)
					}
				}
				exchange(first, 1, 10)
				exchange(sibling, 1, 20)
				_ = first.session.Close()
				_ = relayAwait(t, first.done)
				exchange(sibling, 2, 30)
				select {
				case <-publisher.Done():
					t.Fatal("pair close retired the shared publisher")
				default:
				}
				// even a fresh control claim cannot reopen the retired generation
				// on this outer publisher session.
				retry, retryDone := nativePacketTransport(t, connectorKind, acceptor)
				retried, _, err := tunnel.DialNative(t.Context(), retry, hello, nativeTestDeliveryID)
				if err != nil {
					t.Fatal("retired candidate should remain passive until selection", err)
				}
				if err := retried.ActivateNativeLeg(t.Context(), "retired"); err == nil {
					t.Fatal("retired generation reopened")
				}
				_ = retried.Close()
				if err := relayAwait(t, retryDone); err == nil {
					t.Fatal("retired generation was not rejected")
				}
				exchange(sibling, 3, 40)
				// registry shutdown must join a live packet bridge before returning.
				if err := owner.Publishers.Close(); err != nil {
					t.Fatal(err)
				}
				_ = relayAwait(t, sibling.done)
				owner.mu.Lock()
				defer owner.mu.Unlock()
				if owner.sessions != 0 || len(owner.legs) != 0 {
					t.Fatal("shutdown retained native reservations")
				}
			})
		}
	}
}

func TestNativePeerDeliveryLateCrossTransportClaimKeepsCurrentRegistration(t *testing.T) {
	for _, publisherKind := range []string{"quic", "tls_yamux"} {
		for _, winnerKind := range []string{"quic", "tls_yamux"} {
			t.Run(publisherKind+"/"+winnerKind, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				released, release := context.WithCancel(ctx)
				defer release()
				lateStarted := make(chan struct{})
				claim := nativeClaimFunc(func(call context.Context, _ relayv1.RelayLease, source netip.Addr, proof tunnelv1.NativePairLegProof, _ []byte) (relayv1.NativePeerPairLegClaim, error) {
					if proof.Nonce[0] == 2 {
						close(lateStarted)
						select {
						case <-released.Done():
						case <-call.Done():
							return relayv1.NativePeerPairLegClaim{}, context.Cause(call)
						}
					}
					return nativeTestClaim(source, proof), nil
				})
				acceptor, owner, hello := nativeAdmissionFixture(t, 2, claim)
				if publisherKind == "tls_yamux" {
					hello.NativePairLegProof.ConnectionSlot = 1
				}
				publisherTransport, publisher, _ := nativeDeliveryPublisher(t, publisherKind, acceptor, owner, hello)
				id, err := tunnelv1.ParsePeerDeliveryIdentifier(nativeTestDeliveryID)
				if err != nil {
					t.Fatal(err)
				}
				binding := peer.PairBinding{Delivery: tunnelv1.PeerDelivery{Pair: id, Generation: 1}, Key: [32]byte{1}, Kind: peer.NativePeer,
					Role: 1, Path: uint8(hello.NativePairLegProof.ConnectionSlot)}
				published := nativeTestPacketOwner(t, publisherTransport).register(t, binding, false)
				winner, winnerDone := nativePacketTransport(t, winnerKind, acceptor)
				session, _, err := tunnel.DialNative(ctx, winner, hello, nativeTestDeliveryID)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = session.Close() })
				loserKind := map[string]string{"quic": "tls_yamux", "tls_yamux": "quic"}[winnerKind]
				passiveTransport, passiveDone := nativePacketTransport(t, loserKind, acceptor)
				passiveHello, passiveProof := hello, *hello.NativePairLegProof
				passiveProof.Nonce = bytes.Repeat([]byte{1}, 32)
				passiveHello.NativePairLegProof = &passiveProof
				passive, _, err := tunnel.DialNative(ctx, passiveTransport, passiveHello, nativeTestDeliveryID)
				if err != nil {
					t.Fatal("second authenticated hello could not remain passive", err)
				}
				// both hellos succeeded without spending publisher registration state.
				// closing an unselected candidate must leave the winner installable.
				owner.Publishers.mu.Lock()
				for _, connection := range owner.Publishers.connections {
					connection.packets.mu.Lock()
					for job := range connection.packets.jobs {
						job.mu.Lock()
						if job.activated || job.towardPublisher != nil {
							t.Error("passive hello installed publisher packet state")
						}
						job.mu.Unlock()
					}
					connection.packets.mu.Unlock()
				}
				owner.Publishers.mu.Unlock()
				_ = passive.Close()
				_ = relayAwait(t, passiveDone)
				if err := session.ActivateNativeLeg(ctx, "winner"); err != nil {
					t.Fatal("unselected cleanup retired the winner's generation", err)
				}
				binding.Role = 0
				connected := nativeTestPacketOwner(t, winner).register(t, binding, true)
				loser, loserDone := nativePacketTransport(t, loserKind, acceptor)
				lateHello, lateProof := hello, *hello.NativePairLegProof
				lateProof.Nonce = bytes.Repeat([]byte{2}, 32)
				lateHello.NativePairLegProof = &lateProof
				lateResult := relayWorker(t, func() { cancel(); release(); _ = loser.Close() }, func() error {
					late, _, err := tunnel.DialNative(ctx, loser, lateHello, nativeTestDeliveryID)
					if late != nil {
						defer late.Close()
					}
					if err != nil {
						t.Error("late authenticated candidate should remain passive", err)
						return err
					}
					return late.ActivateNativeLeg(ctx, "duplicate")
				})
				select {
				case <-lateStarted:
				case <-ctx.Done():
					t.Fatal("second transport did not reach its control claim")
				}
				exchange := func(sequence uint64) {
					t.Helper()
					frame := nativeDeliveryFrame(t, binding, sequence, 11)
					if err := connected.carrier(t, ctx).Send(ctx, frame); err != nil {
						t.Fatal(err)
					}
					current := published.carrier(t, ctx)
					if got, err := current.Receive(ctx); err != nil || !bytes.Equal(got, frame) {
						t.Fatal("current connector registration was displaced", err)
					}
					reverse := binding
					reverse.Role = 1
					frame = nativeDeliveryFrame(t, reverse, sequence, 22)
					if err := current.Send(ctx, frame); err != nil {
						t.Fatal(err)
					}
					if got, err := connected.carrier(t, ctx).Receive(ctx); err != nil || !bytes.Equal(got, frame) {
						t.Fatal("current publisher registration was displaced", err)
					}
				}
				exchange(1)
				// a late successful control claim is not permission to replace an
				// already installed registration or forget its packet replay state.
				release()
				if err := relayAwait(t, lateResult); err == nil {
					t.Fatal("late claim replaced the live delivery generation")
				}
				if err := relayAwait(t, loserDone); err == nil {
					t.Fatal("relay accepted the duplicate registration")
				}
				exchange(2)
				if publisher.Err() != nil || session.Err() != nil {
					t.Fatal("loser cleanup closed the winner or borrowed publisher")
				}
				owner.mu.Lock()
				remaining := owner.sessions
				owner.mu.Unlock()
				if remaining != 1 {
					t.Fatal("loser cleanup changed the live reservation count", remaining)
				}
				_ = session.Close()
				_ = relayAwait(t, winnerDone)
			})
		}
	}
}

func TestNativePeerDeliveryRequiresExactLocalAssignment(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*tunnelv1.NativePairLegProof)
	}{
		{"service", func(p *tunnelv1.NativePairLegProof) { p.ServiceID = "svc_abcdefghijklmnopqrstuv" }},
		{"run", func(p *tunnelv1.NativePairLegProof) { p.ServiceRunID = "srun_abcdefghijklmnopqrstuv" }},
		{"run number", func(p *tunnelv1.NativePairLegProof) { p.RunNumber++ }},
		{"connection", func(p *tunnelv1.NativePairLegProof) { p.PublisherConnectionID = "pc_abcdefghijklmnopqrstuv" }},
		{"assignment", func(p *tunnelv1.NativePairLegProof) { p.AssignmentRevision++ }},
		{"slot", func(p *tunnelv1.NativePairLegProof) { p.ConnectionSlot = 1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			claim := nativeClaimFunc(func(_ context.Context, _ relayv1.RelayLease, source netip.Addr, proof tunnelv1.NativePairLegProof, _ []byte) (relayv1.NativePeerPairLegClaim, error) {
				return nativeTestClaim(source, proof), nil
			})
			acceptor, owner, hello := nativeAdmissionFixture(t, 2, claim)
			_, publisher, _ := nativeDeliveryPublisher(t, "tls_yamux", acceptor, owner, hello)
			proof := *hello.NativePairLegProof
			test.change(&proof)
			hello.NativePairLegProof = &proof
			transport, done := nativePacketTransport(t, "tls_yamux", acceptor)
			if _, _, err := tunnel.DialNative(t.Context(), transport, hello, nativeTestDeliveryID); err == nil {
				t.Fatal("mismatched local assignment acknowledged")
			}
			var rejected *tunnel.ProtocolError
			if err := relayAwait(t, done); !errors.As(err, &rejected) || rejected.Code != tunnelv1.StaleConnectionAssignment {
				t.Fatalf("wrong local rejection: %v", err)
			}
			select {
			case <-publisher.Done():
				t.Fatal("rejection closed the publisher")
			default:
			}
		})
	}
}

func TestNativeConnectorDeadlineUsesRequestStart(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(map[bool]string{false: "shortened", true: "expired in transit"}[expired], func(t *testing.T) {
			now := time.Now()
			started := now
			claim := nativeClaimFunc(func(_ context.Context, _ relayv1.RelayLease, source netip.Addr, proof tunnelv1.NativePairLegProof, _ []byte) (relayv1.NativePeerPairLegClaim, error) {
				result := nativeTestClaim(source, proof)
				result.ObservedAt = started.Add(time.Hour)
				result.ExpiresAt = result.ObservedAt.Add(20 * time.Second)
				if expired {
					now = now.Add(21 * time.Second)
				} else {
					now = now.Add(5 * time.Second)
				}
				return result, nil
			})
			_, owner, hello := nativeAdmissionFixture(t, 1, claim)
			owner.Now = func() time.Time { return now }
			result, release, err := owner.admit(t.Context(), socketIdentityOnly{}, *hello.NativePairLegProof)
			if release != nil {
				defer release()
			}
			if expired {
				if err == nil {
					t.Fatal("response revived expired authority")
				}
			} else if err != nil || !result.receipt.ExpiresAt.Equal(started.Add(20*time.Second)) {
				t.Fatalf("deadline did not retain the original request start: %v", err)
			}
		})
	}
}

func TestNativePeerDeliveryJoinsPartialIntroductionOnAssignmentReplacement(t *testing.T) {
	claim := nativeClaimFunc(func(_ context.Context, _ relayv1.RelayLease, source netip.Addr, proof tunnelv1.NativePairLegProof, _ []byte) (relayv1.NativePeerPairLegClaim, error) {
		return nativeTestClaim(source, proof), nil
	})
	acceptor, owner, hello := nativeAdmissionFixture(t, 2, claim)
	_, _, ready := nativeDeliveryPublisher(t, "tls_yamux", acceptor, owner, hello)
	transport, done := nativePacketTransport(t, "tls_yamux", acceptor)
	if _, _, err := tunnel.DialNative(t.Context(), transport, hello, nativeTestDeliveryID); err != nil {
		t.Fatal(err)
	}
	// begin the native stream but omit its complete tagged first frame. shutdown
	// must interrupt this reader, not wait for another connector packet.
	partial, err := transport.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := partial.Write([]byte{tunnelv1.Version}); err != nil {
		t.Fatal(err)
	}
	ref := tunnelv1.ServicePublisherConnectionRef{ServiceID: hello.NativePairLegProof.ServiceID, ServiceRunID: hello.NativePairLegProof.ServiceRunID,
		RunNumber: 1, PublisherConnectionID: "pc_abcdefghijklmnopqrstuv", ConnectionSlot: 0, ConnectionAssignmentRevision: 2, RelayServiceID: "relay-a"}
	replacementTransport, _ := nativePacketTransport(t, "tls_yamux", acceptor)
	replacement, err := tunnel.Dial(t.Context(), replacementTransport, tunnelv1.Message{Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version,
		Role: tunnelv1.Publisher, ServiceConnection: &ref, Credential: "replacement-credential"})
	if err != nil {
		t.Fatal(err)
	}
	relayAwait(t, ready)
	_ = relayAwait(t, done)
	owner.mu.Lock()
	remaining := owner.sessions
	owner.mu.Unlock()
	if remaining != 0 {
		t.Fatal("assignment replacement retained the partial native session")
	}
	select {
	case <-replacement.Done():
		t.Fatal("old pair closed the replacement publisher")
	default:
	}
	// control may still return the old pair during a race; exact local lookup
	// must reject it before acknowledging or registering another carrier.
	stale, staleDone := nativePacketTransport(t, "tls_yamux", acceptor)
	if _, _, err := tunnel.DialNative(t.Context(), stale, hello, nativeTestDeliveryID); err == nil {
		t.Fatal("old pair selected a new assignment")
	}
	var rejected *tunnel.ProtocolError
	if err := relayAwait(t, staleDone); !errors.As(err, &rejected) || rejected.Code != tunnelv1.StaleConnectionAssignment {
		t.Fatalf("wrong stale assignment rejection: %v", err)
	}
}

func TestNativePeerDeliveryRetiresStreamRegistrationsAndFailedOpens(t *testing.T) {
	claim := nativeClaimFunc(func(_ context.Context, _ relayv1.RelayLease, source netip.Addr, proof tunnelv1.NativePairLegProof, _ []byte) (relayv1.NativePeerPairLegClaim, error) {
		return nativeTestClaim(source, proof), nil
	})
	acceptor, owner, hello := nativeAdmissionFixture(t, 2, claim)
	transport, publisher, _ := nativeDeliveryPublisher(t, "tls_yamux", acceptor, owner, hello)
	_ = nativeTestPacketOwner(t, transport)
	owner.Publishers.mu.Lock()
	packets := owner.Publishers.connections[hello.NativePairLegProof.PublisherConnectionID].packets
	owner.Publishers.mu.Unlock()
	for i := byte(1); i <= 65; i++ {
		binding := peer.PairBinding{Delivery: tunnelv1.PeerDelivery{Pair: [16]byte{i}, Generation: 1}, Key: [32]byte{1}, Kind: peer.NativePeer}
		carrier, err := packets.register(t.Context(), binding, true)
		if err != nil {
			t.Fatalf("closed registration spent a live pair slot at %d: %v", i, err)
		}
		if err := carrier.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := packets.register(t.Context(), binding, true); err == nil {
			t.Fatal("closed generation lost its tombstone")
		}
	}
	setup, cancel := context.WithCancel(t.Context())
	cancel()
	carrier, err := packets.register(setup, peer.PairBinding{Delivery: tunnelv1.PeerDelivery{Pair: [16]byte{66}, Generation: 1}, Key: [32]byte{1}, Kind: peer.NativePeer}, true)
	if err == nil || carrier != nil {
		t.Fatal("failed open returned a usable or typed-nil carrier")
	}
	binding := peer.PairBinding{Delivery: tunnelv1.PeerDelivery{Pair: [16]byte{67}, Generation: 1}, Key: [32]byte{1}, Kind: peer.NativePeer}
	carrier, err = packets.register(t.Context(), binding, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := carrier.Send(setup, nativeDeliveryFrame(t, binding, 1, 1)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled lazy open: %v", err)
	}
	if _, err := carrier.Receive(setup); !errors.Is(err, context.Canceled) {
		t.Fatalf("failed lazy open returned a usable carrier: %v", err)
	}
	if err := carrier.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-publisher.Done():
		t.Fatal("pair cleanup retired its borrowed session")
	default:
	}
}

func TestNativePeerDeliveryPublisherProbeWaitsForConnectorPreparation(t *testing.T) {
	for _, kind := range []string{"quic", "tls_yamux"} {
		t.Run(kind, func(t *testing.T) {
			claim := nativeClaimFunc(func(_ context.Context, _ relayv1.RelayLease, source netip.Addr, proof tunnelv1.NativePairLegProof, _ []byte) (relayv1.NativePeerPairLegClaim, error) {
				return nativeTestClaim(source, proof), nil
			})
			acceptor, owner, hello := nativeAdmissionFixture(t, 2, claim)
			transport, _, _ := nativeDeliveryPublisher(t, kind, acceptor, owner, hello)
			id, err := tunnelv1.ParsePeerDeliveryIdentifier(nativeTestDeliveryID)
			if err != nil {
				t.Fatal(err)
			}
			binding := peer.PairBinding{Delivery: tunnelv1.PeerDelivery{Pair: id, Generation: 1}, Key: [32]byte{1}, Kind: peer.NativePeer, Role: 1}
			published := nativeTestPacketOwner(t, transport).register(t, binding, false)
			native, done := nativePacketTransport(t, "tls_yamux", acceptor)
			session, _, err := tunnel.DialNative(t.Context(), native, hello, nativeTestDeliveryID)
			if err != nil {
				t.Fatal(err)
			}
			if err := session.ActivateNativeLeg(t.Context(), "activate"); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			probe := nativeDeliveryFrame(t, binding, 1, 11)
			// datagrams may arrive before the first connector frame. a TLS/yamux
			// publisher cannot accept the relay's stream until that tagged frame exists.
			if kind == "quic" {
				if err := published.carrier(t, ctx).Send(ctx, probe); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case <-session.Done():
				t.Fatal("publisher probe retired a connector still preparing")
			case <-time.After(1200 * time.Millisecond):
			}
			binding.Role = 0
			connected := nativeTestPacketOwner(t, native).register(t, binding, true)
			frame := nativeDeliveryFrame(t, binding, 1, 22)
			if err := connected.carrier(t, ctx).Send(ctx, frame); err != nil {
				t.Fatal(err)
			}
			if got, err := published.carrier(t, ctx).Receive(ctx); err != nil || !bytes.Equal(got, frame) {
				t.Fatalf("prepared connector lost its first packet: %v", err)
			}
			if kind == "tls_yamux" {
				if err := published.carrier(t, ctx).Send(ctx, probe); err != nil {
					t.Fatal(err)
				}
			}
			if got, err := connected.carrier(t, ctx).Receive(ctx); err != nil || !bytes.Equal(got, probe) {
				t.Fatalf("publisher probe did not resume: %v", err)
			}
			_ = session.Close()
			_ = relayAwait(t, done)
		})
	}
}
