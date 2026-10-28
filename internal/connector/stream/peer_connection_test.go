package stream

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type peerTestStream struct{ net.Conn }

func (s peerTestStream) CloseWrite() error  { return s.Close() }
func (s peerTestStream) Reset(uint32) error { return s.Close() }

// pipe sessions expose the consumer's real hello and opening frames while
// keeping clock, cancellation and late-connect races deterministic.
type peerTestSession struct {
	mu          sync.Mutex
	streams     []net.Conn
	done        chan struct{}
	workers     sync.WaitGroup
	open        func(muxsession.Stream)
	datagrams   bool
	opens       atomic.Int32
	packets     atomic.Int32
	activations atomic.Int32
	activate    func() error
	selection   func(tunnelv1.NativeLegBinding)
}

func newPeerTestSession(t *testing.T, datagrams bool, open func(muxsession.Stream)) *peerTestSession {
	t.Helper()
	s := &peerTestSession{done: make(chan struct{}), datagrams: datagrams, open: open}
	t.Cleanup(func() { _ = s.Close(); s.workers.Wait() })
	return s
}

func (s *peerTestSession) OpenStream(ctx context.Context) (muxsession.Stream, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.done:
		return nil, net.ErrClosed
	default:
	}
	if ctx.Err() != nil {
		return nil, context.Cause(ctx)
	}
	local, remote := net.Pipe()
	s.streams = append(s.streams, local, remote)
	s.opens.Add(1)
	s.workers.Go(func() { defer remote.Close(); s.open(peerTestStream{remote}) })
	return peerTestStream{local}, nil
}

func (s *peerTestSession) AcceptStream(ctx context.Context) (muxsession.Stream, error) {
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-s.done:
		return nil, net.ErrClosed
	}
}

func (s *peerTestSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.done:
		return nil
	default:
		close(s.done)
	}
	for _, stream := range s.streams {
		_ = stream.Close()
	}
	return nil
}

func (s *peerTestSession) Done() <-chan struct{}   { return s.done }
func (s *peerTestSession) Err() error              { return net.ErrClosed }
func (s *peerTestSession) SupportsDatagrams() bool { return s.datagrams }
func (s *peerTestSession) SendDatagram(context.Context, []byte) error {
	s.packets.Add(1)
	return nil
}
func (s *peerTestSession) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-s.done:
		return nil, net.ErrClosed
	}
}

func preparedPeerFixture(t *testing.T) (Config, *preparedSelection, *peerPreparation) {
	t.Helper()
	config, run, owner := peerUnitFixture(t)
	run.ServiceTLS = config.ServiceTLS
	pair := pairResponse(run, controlv1.NativePeerPairRequest{ExpectedRelays: run.PairReady.Relays})
	until := time.Now().Add(30 * time.Second)
	binding := &preparedPeer{pair: pair, runID: run.ServiceRunID, number: run.RunNumber, hint: clonePairHint(run.PairReady), until: until, expiresAt: until, publisherPreparedUntil: until}
	prepared := &preparedSelection{config: config, run: run, peer: binding, peerOwner: owner, until: until}
	return config, prepared, owner
}

func peerHelloSession(t *testing.T, binding preparedPeer, signer Signer, change func(*tunnelv1.NativePairLegAccepted), before func(), datagrams bool, renew ...func(tunnelv1.NativePairLegProof) (tunnelv1.NativePairLegAccepted, error)) *peerTestSession {
	t.Helper()
	var session *peerTestSession
	session = newPeerTestSession(t, datagrams, func(stream muxsession.Stream) {
		hello, err := tunnelv1.ReadControl(stream)
		if err != nil {
			return // cancellation can interrupt a late connected attempt.
		}
		if hello.Role != tunnelv1.NativeConnector || hello.NativePairLegProof == nil {
			t.Error("native leg used another hello role")
			return
		}
		proof := *hello.NativePairLegProof
		message, err := proof.Message()
		if err != nil || !ed25519.Verify(signer.PublicKey, message, proof.Signature) {
			t.Error("native leg did not sign its exact proof")
			return
		}
		receipt := tunnelv1.NativePairLegAccepted{PairID: binding.pair.PairId, DeliveryID: binding.pair.DeliveryId,
			DeliveryGeneration: binding.pair.DeliveryGeneration, ConnectionSlot: proof.ConnectionSlot, SourceIP: "127.0.0.1",
			ObservedAt: time.Now(), ExpiresAt: time.Now().Add(20 * time.Second)}
		if change != nil {
			change(&receipt)
		}
		if before != nil {
			before()
		}
		if err := tunnelv1.WriteControl(stream, tunnelv1.Message{Type: tunnelv1.HelloAccepted, ProtocolVersion: tunnelv1.Version, NativePairLegAccepted: &receipt}); err != nil {
			return
		}
		for {
			request, err := tunnelv1.ReadControl(stream)
			if err != nil {
				return
			}
			if (request.Type == tunnelv1.NativeLegActivate || request.Type == tunnelv1.NativeLegHandoff) && request.NativeLegBinding != nil && request.NativeLegBinding.Matches(proof) {
				session.activations.Add(1)
				if session.selection != nil {
					session.selection(*request.NativeLegBinding)
				}
				if session.activate != nil {
					if err := session.activate(); err != nil {
						_ = tunnelv1.WriteControl(stream, tunnelv1.Message{Type: tunnelv1.Error, ProtocolVersion: tunnelv1.Version,
							RequestID: request.RequestID, Code: tunnelv1.Unavailable})
						return
					}
				}
				accepted := tunnelv1.NativeLegActivated
				if request.Type == tunnelv1.NativeLegHandoff {
					accepted = tunnelv1.NativeLegHandedOff
				}
				if err := tunnelv1.WriteControl(stream, tunnelv1.Message{Type: accepted, ProtocolVersion: tunnelv1.Version,
					RequestID: request.RequestID, NativeLegBinding: request.NativeLegBinding}); err != nil {
					return
				}
				continue
			}
			if len(renew) == 0 {
				t.Error("unselected candidate attempted renewal or another control message")
				return
			}
			if request.Type != tunnelv1.NativeLegRenew || request.NativePairLegProof == nil || !proof.SameLeg(*request.NativePairLegProof) {
				t.Error("renewal changed its original leg")
				return
			}
			message, err := request.NativePairLegProof.Message()
			if err != nil || !ed25519.Verify(signer.PublicKey, message, request.NativePairLegProof.Signature) || bytes.Equal(proof.Nonce, request.NativePairLegProof.Nonce) {
				t.Error("renewal did not sign a fresh exact proof")
				return
			}
			receipt, err := renew[0](*request.NativePairLegProof)
			response := tunnelv1.Message{Type: tunnelv1.NativeLegRenewed, ProtocolVersion: tunnelv1.Version, RequestID: request.RequestID, NativePairLegAccepted: &receipt}
			if err != nil {
				response.Type, response.Code, response.NativePairLegAccepted = tunnelv1.Error, tunnelv1.Unavailable, nil
			}
			if err := tunnelv1.WriteControl(stream, response); err != nil {
				return
			}
		}
	})
	return session
}

func TestNativePeerRelayConsumerChecksReceiptCapabilityAndRequestDelay(t *testing.T) {
	for _, tc := range []struct {
		name      string
		change    func(*tunnelv1.NativePairLegAccepted)
		delay     time.Duration
		capable   bool
		wantError bool
	}{
		{name: "accepted", capable: true},
		{name: "clock skew", capable: true, change: func(r *tunnelv1.NativePairLegAccepted) {
			r.ObservedAt = r.ObservedAt.Add(time.Hour)
			r.ExpiresAt = r.ExpiresAt.Add(time.Hour)
		}},
		{name: "wrong delivery", capable: true, wantError: true, change: func(r *tunnelv1.NativePairLegAccepted) { r.DeliveryID = "AgICAgICAgICAgICAgICAg" }},
		{name: "wrong slot", capable: true, wantError: true, change: func(r *tunnelv1.NativePairLegAccepted) { r.ConnectionSlot = 1 }},
		{name: "no datagrams", wantError: true},
		{name: "expired in transit", capable: true, wantError: true, delay: time.Second, change: func(r *tunnelv1.NativePairLegAccepted) { r.ExpiresAt = r.ObservedAt.Add(time.Second) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				_, prepared, owner := preparedPeerFixture(t)
				binding := *prepared.peer
				session := peerHelloSession(t, binding, owner.signer, tc.change, func() { time.Sleep(tc.delay) }, tc.capable)
				connector := muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) { return session, nil })
				leg, err := dialPeerRelayLeg(t.Context(), t.Context(), connector, binding, owner.signer, 0, true)
				if (err != nil) != tc.wantError {
					t.Fatal("native receipt consumer", err)
				}
				if leg != nil {
					if session.packets.Load() != 0 {
						t.Error("leg setup sent packets before publisher confirmation")
					}
					leg.Close()
				}
				select {
				case <-session.Done():
				default:
					t.Fatal("native leg did not join transport cleanup")
				}
				if !tc.capable && session.opens.Load() != 0 {
					t.Fatal("ineligible QUIC consumed a leg proof")
				}
			})
		})
	}
}

func TestNativePeerRelayRaceJoinsCanceledLateConnect(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, prepared, owner := preparedPeerFixture(t)
		binding := *prepared.peer
		primary := peerHelloSession(t, binding, owner.signer, nil, nil, true)
		late := newPeerTestSession(t, false, func(muxsession.Stream) { t.Error("canceled loser wrote a hello") })
		started, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
		connectors := [2]muxsession.Connector{
			muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) { <-started; return primary, nil }),
			muxsession.ConnectorFunc(func(ctx context.Context, _ muxsession.Endpoint) (muxsession.Session, error) {
				close(started)
				<-ctx.Done()
				close(canceled)
				<-release
				return late, nil
			}),
		}
		done := make(chan *peerRelayLeg, 1)
		go func() {
			leg, err := racePeerRelayCandidates(t.Context(), t.Context(), connectors, binding, owner.signer, 0, nil)
			if err != nil {
				t.Error(err)
			}
			done <- leg
		}()
		<-canceled
		synctest.Wait()
		select {
		case <-done:
			t.Fatal("native race returned before its late loser joined")
		default:
		}
		if primary.activations.Load() != 0 {
			t.Fatal("winner activated before the losing attempt joined")
		}
		close(release)
		leg := <-done
		if leg == nil {
			t.Fatal("late loser displaced authenticated winner")
		}
		if primary.activations.Load() != 1 || late.activations.Load() != 0 {
			t.Fatal("race did not select exactly one candidate")
		}
		leg.Close()
		select {
		case <-late.Done():
		default:
			t.Fatal("late canceled transport leaked")
		}
	})
}

func TestNativePeerRelayActivationFailureClosesWinnerWithoutRetry(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(map[bool]string{false: "rejected", true: "startup deadline"}[expired], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				_, prepared, owner := preparedPeerFixture(t)
				binding := *prepared.peer
				primary := peerHelloSession(t, binding, owner.signer, nil, nil, true)
				primary.activate = func() error {
					if expired {
						time.Sleep(time.Second)
						return nil
					}
					return &tunnel.ProtocolError{Code: tunnelv1.Unavailable}
				}
				var connects, signatures atomic.Int32
				signer := owner.signer
				signer.Sign = func(message []byte) []byte { signatures.Add(1); return owner.signer.Sign(message) }
				connectors := [2]muxsession.Connector{
					muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
						connects.Add(1)
						return primary, nil
					}),
					muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
						connects.Add(1)
						t.Error("activation failure retried another candidate")
						return nil, ErrServiceConnection
					}),
				}
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				defer cancel()
				leg, err := racePeerRelayCandidates(ctx, t.Context(), connectors, binding, signer, 0, nil)
				if leg != nil || err == nil || primary.activations.Load() != 1 || connects.Load() != 1 || signatures.Load() != 1 {
					t.Fatal("activation failure retried setup or admitted a carrier", err)
				}
				if expired && !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("activation extended the original startup deadline", err)
				}
				select {
				case <-primary.Done():
				default:
					t.Fatal("failed winner was not closed and joined")
				}
			})
		})
	}
}

func TestNativePeerRelayOverlappingHellosActivateOnlySelectedCandidate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, prepared, owner := preparedPeerFixture(t)
		binding := *prepared.peer
		var hellos, signatures atomic.Int32
		both := make(chan struct{})
		before := func() {
			if hellos.Add(1) == 2 {
				close(both)
			}
			<-both
		}
		primary := peerHelloSession(t, binding, owner.signer, nil, before, true)
		fallback := peerHelloSession(t, binding, owner.signer, nil, before, false)
		signer := owner.signer
		signer.Sign = func(message []byte) []byte { signatures.Add(1); return owner.signer.Sign(message) }
		connectors := [2]muxsession.Connector{
			muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) { return primary, nil }),
			muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) { return fallback, nil }),
		}
		leg, err := racePeerRelayCandidates(t.Context(), t.Context(), connectors, binding, signer, 0, nil)
		if err != nil || leg == nil {
			t.Fatal("overlapping native hellos did not select a winner", err)
		}
		defer leg.Close()
		if hellos.Load() != 2 || signatures.Load() != 2 || primary.activations.Load()+fallback.activations.Load() != 1 {
			t.Fatal("selection signed again or activated more than one authenticated candidate")
		}
		winner, loser := primary, fallback
		if fallback.activations.Load() == 1 {
			winner, loser = fallback, primary
		}
		select {
		case <-loser.Done():
		default:
			t.Fatal("authenticated loser was not joined before activation")
		}
		select {
		case <-winner.Done():
			t.Fatal("loser cleanup retired the selected candidate")
		default:
		}
		if primary.packets.Load()+fallback.packets.Load() != 0 {
			t.Fatal("selection sent probes before publisher confirmation")
		}
	})
}

func TestNativePeerRelayWinnerExpiryWhileJoiningDoesNotActivate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, prepared, owner := preparedPeerFixture(t)
		binding := *prepared.peer
		primary := peerHelloSession(t, binding, owner.signer, nil, nil, true)
		late := newPeerTestSession(t, false, func(muxsession.Stream) { t.Error("canceled loser wrote a hello") })
		started, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
		connectors := [2]muxsession.Connector{
			muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) { <-started; return primary, nil }),
			muxsession.ConnectorFunc(func(ctx context.Context, _ muxsession.Endpoint) (muxsession.Session, error) {
				close(started)
				<-ctx.Done()
				close(canceled)
				<-release
				return late, nil
			}),
		}
		done := make(chan error, 1)
		go func() {
			leg, err := racePeerRelayCandidates(t.Context(), t.Context(), connectors, binding, owner.signer, 0, nil)
			if leg != nil {
				leg.Close()
				t.Error("expired winner was returned")
			}
			done <- err
		}()
		<-canceled
		time.Sleep(20 * time.Second)
		close(release)
		if err := <-done; !errors.Is(err, ErrSelectionExpired) || primary.activations.Load() != 0 {
			t.Fatal("joining a loser extended the winner's original claim", err)
		}
		select {
		case <-primary.Done():
		default:
			t.Fatal("expired winner retained its transport")
		}
	})
}

func TestNativePeerRelayDeadlineDoesNotFollowPairRenewal(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, prepared, owner := preparedPeerFixture(t)
		binding := *prepared.peer
		session := peerHelloSession(t, binding, owner.signer, nil, nil, true)
		connector := muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) { return session, nil })
		leg, err := dialPeerRelayLeg(t.Context(), t.Context(), connector, binding, owner.signer, 0, true)
		if err != nil {
			t.Fatal(err)
		}
		defer leg.Close()
		// a later pair response is not a checked renewal of this relay claim.
		prepared.peer.until, prepared.peer.expiresAt = time.Now().Add(time.Minute), time.Now().Add(time.Minute)
		time.Sleep(19 * time.Second)
		if leg.ctx.Err() != nil {
			t.Fatal("relay leg lost its confirmed deadline early")
		}
		time.Sleep(time.Second)
		synctest.Wait()
		if leg.ctx.Err() == nil {
			t.Fatal("pair renewal silently extended an existing relay claim")
		}
		select {
		case <-session.Done():
		default:
			t.Fatal("expired relay leg retained its transport")
		}
	})
}

func TestNativePeerRelayRenewalRequiresCheckedCurrentReceipt(t *testing.T) {
	for _, outcome := range []string{"accepted", "temporary denial", "changed source", "late success"} {
		t.Run(outcome, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				_, prepared, owner := preparedPeerFixture(t)
				initial := *prepared.peer
				var calls atomic.Int32
				session := peerHelloSession(t, initial, owner.signer, nil, nil, true, func(proof tunnelv1.NativePairLegProof) (tunnelv1.NativePairLegAccepted, error) {
					calls.Add(1)
					if outcome == "temporary denial" {
						return tunnelv1.NativePairLegAccepted{}, &tunnel.ProtocolError{Code: tunnelv1.Unavailable}
					}
					receipt := tunnelv1.NativePairLegAccepted{PairID: initial.pair.PairId, DeliveryID: initial.pair.DeliveryId,
						DeliveryGeneration: 1, ConnectionSlot: proof.ConnectionSlot, SourceIP: "127.0.0.1", ObservedAt: time.Now(), ExpiresAt: time.Now().Add(30 * time.Second)}
					if outcome == "changed source" {
						receipt.SourceIP = "127.0.0.2"
					}
					if outcome == "late success" {
						time.Sleep(16 * time.Second)
					}
					return receipt, nil
				})
				connector := muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) { return session, nil })
				leg, err := dialPeerRelayLeg(t.Context(), t.Context(), connector, initial, owner.signer, 0, true)
				if err != nil {
					t.Fatal(err)
				}
				prepared.peer.expiresAt, prepared.peer.until, prepared.until = time.Now().Add(40*time.Second), time.Now().Add(40*time.Second), time.Now().Add(40*time.Second)
				joined := make(chan struct{})
				go func() { defer close(joined); leg.renewPrepared(prepared, initial, owner.signer, 0) }()
				time.Sleep(21 * time.Second)
				synctest.Wait()
				if calls.Load() == 0 || (leg.ctx.Err() == nil) != (outcome == "accepted") {
					t.Fatal("relay renewal installed unchecked or expired authority", outcome, calls.Load(), leg.ctx.Err())
				}
				leg.Close()
				<-joined
			})
		})
	}
}

func TestNativePeerPacketStartupRequiresMatchingSourcesAndPublisherConfirmation(t *testing.T) {
	for _, mismatch := range []bool{false, true} {
		name := "missing publisher confirmation"
		if mismatch {
			name = "different accepted sources"
		}
		t.Run(name, func(t *testing.T) {
			config, prepared, owner := preparedPeerFixture(t)
			prepared.peer.publisherPreparedUntil = time.Time{}
			root, certificate := testCertificateForUses(t, []string{"relay.example.test"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(root) {
				t.Fatal("test root")
			}
			config.TransportTLS = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}
			serverTLS := &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			accepted, exited := make(chan struct{}, 2), make(chan struct{}, 2)
			var packetStreams atomic.Int32
			for slot := range 2 {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = listener.Close() })
				relay := &prepared.peer.pair.Relays[slot]
				relay.RelayAddress, relay.TlsServerName = listener.Addr().String(), "relay.example.test"
				prepared.peer.hint.Relays[slot] = *relay
				go func() {
					defer func() { exited <- struct{}{} }()
					connection, err := listener.Accept()
					if err != nil {
						return
					}
					defer connection.Close()
					outer, err := muxsession.AcceptTLSYamux(ctx, connection, serverTLS, muxsession.TLSYamuxConfig{})
					if err != nil {
						t.Error(err)
						return
					}
					defer outer.Close()
					session, _, err := tunnel.AcceptWithResult(ctx, outer, func(_ context.Context, hello tunnelv1.Message) (*tunnelv1.NativePairLegAccepted, error) {
						source := "127.0.0.1"
						if mismatch && slot == 1 {
							source = "127.0.0.2"
						}
						return &tunnelv1.NativePairLegAccepted{PairID: prepared.peer.pair.PairId, DeliveryID: prepared.peer.pair.DeliveryId,
							DeliveryGeneration: 1, ConnectionSlot: hello.NativePairLegProof.ConnectionSlot, SourceIP: source,
							ObservedAt: time.Now(), ExpiresAt: time.Now().Add(20 * time.Second)}, nil
					})
					if err != nil {
						t.Error(err)
						return
					}
					accepted <- struct{}{}
					controlDone := make(chan error, 1)
					go func() {
						controlDone <- session.HandleNativeLegControl(ctx, func(context.Context, tunnelv1.NativeLegBinding) error { return nil },
							func(context.Context, tunnelv1.NativePairLegProof) (tunnelv1.NativePairLegAccepted, error) {
								t.Error("startup unexpectedly renewed authority")
								return tunnelv1.NativePairLegAccepted{}, &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
							})
					}()
					if stream, err := outer.AcceptStream(ctx); err == nil {
						packetStreams.Add(1)
						_ = stream.Close()
					}
					_ = outer.Close()
					<-controlDone
				}()
			}
			prepared.run.PairReady = clonePairHint(prepared.peer.hint)
			done := make(chan error, 1)
			go func() {
				connection, err := preparePeerConnection(ctx, config, prepared, owner.signer)
				if connection != nil {
					connection.Close()
					t.Error("unprepared packet owner started")
				}
				done <- err
			}()
			for range 2 {
				select {
				case <-accepted:
				case <-time.After(3 * time.Second):
					t.Fatal("native claims did not finish")
				}
			}
			if !mismatch {
				cancel()
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("unprepared packet startup succeeded")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("native setup did not join")
			}
			for range 2 {
				select {
				case <-exited:
				case <-time.After(time.Second):
					t.Fatal("native setup left a relay session alive")
				}
			}
			if packetStreams.Load() != 0 {
				t.Fatal("unconfirmed publisher or differing sources admitted packet probes")
			}
		})
	}
}

func TestNativePeerApplicationArrivalUsesOnlyPreparedPermission(t *testing.T) {
	_, prepared, owner := preparedPeerFixture(t)
	prepared.run.Protocol = "http"
	var signatures atomic.Int32
	sign := owner.signer.Sign
	owner.signer.Sign = func(message []byte) []byte {
		if !bytes.HasPrefix(message, []byte("tnl native peer visitor opening v1\x00")) {
			t.Error("application arrival signed pair setup")
		}
		signatures.Add(1)
		return sign(message)
	}
	seen := make(chan string, 3)
	session := newPeerTestSession(t, false, func(stream muxsession.Stream) {
		entry, initial, err := tunnelv1.ReadNativePeerVisitorOpening(stream)
		if err != nil {
			t.Error(err)
			return
		}
		message, err := tunnelv1.NativePeerProofMessage(entry, initial)
		signature, _ := base64.RawURLEncoding.DecodeString(entry.Permission.Signature)
		if err != nil || !ed25519.Verify(owner.signer.PublicKey, message, signature) || len(initial) != 0 ||
			entry.SourceIP != "127.0.0.1" || entry.Permission.Token != prepared.run.Permission.VisitorToken || entry.Subject != owner.signer.Subject {
			t.Error("native application opening lost its independent permission or source binding")
		}
		seen <- entry.VisitorConnectionID
		_, _ = io.Copy(io.Discard, stream)
	})
	p := &peerConnection{prepared: prepared, initial: *prepared.peer, signer: owner.signer, source: "127.0.0.1", session: session, ctx: t.Context()}
	ids := make(map[string]bool)
	for range 3 {
		connection, err := p.open(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		id := <-seen
		if ids[id] {
			t.Fatal("application reused a visitor ID")
		}
		ids[id] = true
		_ = connection.Close()
	}
	if signatures.Load() != 3 || session.opens.Load() != 3 {
		t.Fatal("application arrival repeated an opening or signed pair setup")
	}
	// no control hooks exist on this snapshot: an attempted request would fail.
	for _, change := range []func(){
		func() { prepared.peerFenced = true },
		func() { prepared.peerFenced = false; prepared.peer.publisherPreparedUntil = time.Now() },
		func() { prepared.peer.publisherPreparedUntil = time.Now().Add(time.Minute); prepared.closed = true },
	} {
		change()
		if connection, err := p.open(t.Context()); err == nil || connection != nil {
			t.Fatal("unprepared application reached an inner stream")
		}
	}
	if signatures.Load() != 3 || session.opens.Load() != 3 {
		t.Fatal("unprepared application signed or opened a stream")
	}
}

func TestNativePeerExistingAuthoritySurvivesOnlyTemporaryPreparationFence(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, prepared, _ := preparedPeerFixture(t)
		initial := *prepared.peer
		prepared.peerFenced = true
		prepared.peer.publisherPreparedUntil = time.Now()
		if _, err := prepared.peerRunForRenewal(initial); err != nil {
			t.Fatal("temporary preparation outage canceled confirmed authority", err)
		}
		if _, _, err := prepared.peerPreparedRun(); err == nil {
			t.Fatal("temporary outage admitted a new application")
		}
		time.Sleep(30 * time.Second)
		if _, err := prepared.peerRunForRenewal(initial); !errors.Is(err, ErrSelectionExpired) {
			t.Fatal("temporary fence renewed expired authority", err)
		}
		prepared.until, prepared.peer.until = time.Now().Add(time.Minute), time.Now().Add(time.Minute)
		prepared.peer.hint = clonePairHint(prepared.peer.hint)
		prepared.peer.hint.Relays[0].AssignmentRevision++
		if _, err := prepared.peerRunForRenewal(initial); err == nil {
			t.Fatal("changed assignment retained old inner authority")
		}
	})
}

func TestNativePeerModeDoesNotRequestIngressAssignments(t *testing.T) {
	config, run, owner := peerUnitFixture(t)
	var assignments atomic.Int32
	control, err := NewControlWithConfig(ControlConfig{
		Signer:  func(context.Context, string) (Signer, error) { return owner.signer, nil },
		Resolve: func(context.Context, string) (Run, error) { return run, nil },
		Assignment: func(context.Context, string, tunnelv1.VisitorSubject, uint8) (Assignment, error) {
			assignments.Add(1)
			return Assignment{}, errors.New("ingress must not be used")
		},
		Release: func(context.Context, string) error { return nil }, Close: func() error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	config.Control, config.NativePeers, config.IdentityID = control, true, owner.signer.Subject.IdentityID
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := Serve(t.Context(), listener, config); !errors.Is(err, ErrServiceConnection) || assignments.Load() != 0 {
		t.Fatal("missing pair capability fell back to ingress", err, assignments.Load())
	}
}

var _ muxsession.DatagramSession = (*peerTestSession)(nil)
