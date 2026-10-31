package stream

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorsubject"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/peer"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func prepareNativePair(ctx context.Context, control Control, signer Signer, run Run, owner string, previous *controlv1.NativePeerPair) (controlv1.NativePeerPair, [32]byte, time.Time, controlv1.NativePeerPairRequest, error) {
	var key [32]byte
	var body controlv1.NativePeerPairRequest
	if run.PairReady == nil {
		return controlv1.NativePeerPair{}, key, time.Time{}, body, failure.Wrap("prepare native relay carriers", failure.ConnectionUnavailable, ErrServiceConnection)
	}
	if len(run.PairReady.Relays) != 2 || !opaqueid.Valid(run.PairReady.PublisherIdentityId, opaqueid.PublisherIdentityPrefix) || signer.Subject.Validate() != nil {
		return controlv1.NativePeerPair{}, key, time.Time{}, body, ErrServiceConnection
	}
	body = controlv1.NativePeerPairRequest{Action: "create", IdempotencyKey: owner, ServiceRunId: run.ServiceRunID, RunNumber: int64(run.RunNumber), PublisherIdentityId: run.PairReady.PublisherIdentityId,
		Subject: visitorsubject.Wire(signer.Subject), ExpectedRelays: run.PairReady.Relays, RequestedAt: time.Now().UTC().Truncate(time.Microsecond)}
	if previous != nil {
		body.Action, body.PreviousPairId, body.PreviousGeneration = "renew", &previous.PairId, &previous.DeliveryGeneration
	}
	message, err := controlv1.NativePeerPairProofMessage(run.ServiceID, body)
	if err != nil {
		return controlv1.NativePeerPair{}, key, time.Time{}, body, err
	}
	signature := signer.Sign(message)
	if !ed25519.Verify(signer.PublicKey, message, signature) {
		return controlv1.NativePeerPair{}, key, time.Time{}, body, ErrServiceConnection
	}
	body.Signature = base64.RawURLEncoding.EncodeToString(signature)
	started := time.Now()
	// an uncertain reply repeats this exact signed request, not a new owner or
	// timestamp. the caller's bounded preparation/renewal context is the ceiling.
	var pair controlv1.NativePeerPair
	for {
		pair, err = control.PrepareNativePeerPair(ctx, run.ServiceID, body)
		if err == nil || !nativeTemporary(err) {
			break
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return controlv1.NativePeerPair{}, key, time.Time{}, body, context.Cause(ctx)
		case <-timer.C:
		}
	}
	if err != nil {
		return controlv1.NativePeerPair{}, key, time.Time{}, body, err
	}
	secret, keyErr := base64.RawURLEncoding.Strict().DecodeString(pair.Key)
	defer clear(secret)
	_, idErr := tunnelv1.ParsePeerDeliveryIdentifier(pair.DeliveryId)
	duration := pair.ExpiresAt.Sub(pair.ObservedAt)
	until := started.Add(duration)
	if keyErr != nil || len(secret) != 32 || idErr != nil || !opaqueid.Valid(pair.PairId, "npp_") || pair.DeliveryGeneration < 1 || pair.ServiceId != run.ServiceID || pair.ServiceRunId != run.ServiceRunID || pair.RunNumber != int64(run.RunNumber) || pair.PublisherIdentityId != run.PairReady.PublisherIdentityId || !visitorsubject.Equal(pair.Subject, signer.Subject) ||
		pair.ObservedAt.IsZero() || duration <= 0 || duration > 5*time.Minute || !until.After(time.Now()) || ctx.Err() != nil || len(pair.Relays) != 2 {
		return controlv1.NativePeerPair{}, key, time.Time{}, body, ErrServiceConnection
	}
	for slot, relay := range pair.Relays {
		if relay != body.ExpectedRelays[slot] {
			return controlv1.NativePeerPair{}, key, time.Time{}, body, ErrServiceConnection
		}
	}
	copy(key[:], secret)
	if key == [32]byte{} || previous != nil && (pair.PairId != previous.PairId || pair.DeliveryId != previous.DeliveryId || pair.DeliveryGeneration != previous.DeliveryGeneration || pair.Key != previous.Key) {
		return controlv1.NativePeerPair{}, [32]byte{}, time.Time{}, body, ErrServiceConnection
	}
	return pair, key, until, body, nil
}

// awaitNativePublisher repeats the original signed create only to observe the
// installation barrier. it cannot renew authority or reset startup's deadline.
func awaitNativePublisher(ctx context.Context, control Control, service string, request controlv1.NativePeerPairRequest, expected controlv1.NativePeerPair) (time.Time, error) {
	for {
		if err := context.Cause(ctx); err != nil {
			return time.Time{}, err
		}
		started := time.Now()
		pair, err := control.PrepareNativePeerPair(ctx, service, request)
		if err == nil {
			if pair.PairId != expected.PairId || pair.DeliveryId != expected.DeliveryId || pair.DeliveryGeneration != expected.DeliveryGeneration || pair.Key != expected.Key ||
				pair.ServiceId != expected.ServiceId || pair.ServiceRunId != expected.ServiceRunId || pair.RunNumber != expected.RunNumber || pair.PublisherIdentityId != expected.PublisherIdentityId ||
				!visitorsubject.Same(pair.Subject, expected.Subject) || len(pair.Relays) != 2 || pair.Relays[0] != expected.Relays[0] || pair.Relays[1] != expected.Relays[1] ||
				pair.ObservedAt.IsZero() || !pair.ExpiresAt.After(pair.ObservedAt) || pair.ExpiresAt.Sub(pair.ObservedAt) > 5*time.Minute {
				return time.Time{}, ErrServiceConnection
			}
			if pair.PublisherPreparedUntil != nil {
				if pair.PublisherPreparedUntil.After(pair.ExpiresAt) {
					return time.Time{}, ErrServiceConnection
				}
				if remaining := pair.PublisherPreparedUntil.Sub(pair.ObservedAt); remaining > 0 && started.Add(remaining).After(time.Now()) {
					return started.Add(remaining), context.Cause(ctx)
				}
			}
		} else if !nativeTemporary(err) {
			return time.Time{}, err
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return time.Time{}, context.Cause(ctx)
		case <-timer.C:
		}
	}
}

type nativeRelayLeg struct {
	session   *tunnel.Session
	packets   *peer.SharedSession
	carrier   peer.Carrier
	proof     tunnelv1.NativePairLegProof
	receipt   tunnelv1.NativePairLegAccepted
	transport tunnel.Transport
	until     time.Time
	relay     controlv1.NativePeerPairRelay
}

func (l *nativeRelayLeg) Close() error {
	return errors.Join(l.carrier.Close(), l.packets.Close(), l.session.Close())
}

func nativeLegProof(signer Signer, pair controlv1.NativePeerPair, slot int) (tunnelv1.NativePairLegProof, error) {
	relay := pair.Relays[slot]
	proof := tunnelv1.NativePairLegProof{PairID: pair.PairId, DeliveryGeneration: pair.DeliveryGeneration, ServiceID: pair.ServiceId, ServiceRunID: pair.ServiceRunId, RunNumber: pair.RunNumber, PublisherIdentityID: pair.PublisherIdentityId,
		ConnectionSlot: slot, PublisherConnectionID: relay.PublisherConnectionId, AssignmentRevision: relay.AssignmentRevision, RelayServiceID: relay.RelayLease.RelayServiceId, RelayID: relay.RelayLease.RelayId, RelayRunID: relay.RelayLease.RelayRunId, RelayLeaseRevision: uint64(relay.RelayLease.RelayLeaseRevision), RequestedAt: time.Now().UTC().Truncate(time.Microsecond), Nonce: make([]byte, 32)}
	if _, err := rand.Read(proof.Nonce); err != nil {
		return proof, err
	}
	message, err := proof.Message()
	if err != nil {
		return proof, err
	}
	proof.Signature = signer.Sign(message)
	if !ed25519.Verify(signer.PublicKey, message, proof.Signature) {
		return proof, ErrServiceConnection
	}
	return proof, nil
}

// connectNativeLeg joins both raced candidates before selecting one. candidates
// are passive until activation, so a losing QUIC/TCP attempt cannot spend the
// publisher's registration or replace a sibling's replay state.
func connectNativeLeg(ctx, lifetime context.Context, config Config, signer Signer, pair controlv1.NativePeerPair, key [32]byte, slot int) (*nativeRelayLeg, error) {
	roots := config.TransportTLS
	if roots == nil {
		roots = &tls.Config{MinVersion: tls.VersionTLS13}
	}
	quicConnector, tcpConnector := config.RelayQUIC, config.RelayTCP
	if quicConnector == nil {
		quicConnector = muxsession.QUICConnector{TLSConfig: roots, Config: muxsession.QUICConfig{Config: &quic.Config{EnableDatagrams: true}}}
	}
	if tcpConnector == nil {
		tcpConnector = muxsession.TLSYamuxConnector{TLSConfig: roots}
	}
	type result struct {
		leg   *nativeRelayLeg
		outer muxsession.Session
		err   error
	}
	results := make(chan result, 2)
	race, cancel := context.WithCancel(ctx)
	defer cancel()
	start := func(connector muxsession.Connector, transport tunnel.Transport) {
		go func() {
			proof, err := nativeLegProof(signer, pair, slot)
			if err != nil {
				results <- result{err: err}
				return
			}
			outer, err := connector.Connect(race, muxsession.Endpoint{Address: pair.Relays[slot].RelayAddress, ServerName: pair.Relays[slot].TlsServerName})
			if err != nil {
				results <- result{err: err}
				return
			}
			if transport == tunnel.TransportQUIC {
				packets, ok := outer.(muxsession.DatagramSession)
				if !ok || !packets.SupportsDatagrams() {
					results <- result{err: errors.Join(peer.ErrConfiguration, outer.Close())}
					return
				}
			}
			started := time.Now()
			session, receipt, err := tunnel.DialNative(race, outer, tunnelv1.Message{Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version, Role: tunnelv1.NativeConnector, NativePairLegProof: &proof}, pair.DeliveryId)
			if err != nil {
				results <- result{err: err}
				return
			}
			results <- result{leg: &nativeRelayLeg{session: session, proof: proof, receipt: receipt, transport: transport, until: started.Add(receipt.ExpiresAt.Sub(receipt.ObservedAt)), relay: pair.Relays[slot]}, outer: outer}
		}()
	}
	primary, fallback := quicConnector, tcpConnector
	primaryKind, fallbackKind := tunnel.TransportQUIC, tunnel.TransportTLSTCP
	start(primary, primaryKind)
	remaining, fallbackStarted := 1, false
	timer := time.NewTimer(250 * time.Millisecond)
	defer timer.Stop()
	var winner result
	var failures error
	stopped := ctx.Done()
	for remaining > 0 {
		select {
		case <-stopped:
			stopped = nil
			cancel()
			failures = errors.Join(failures, context.Cause(ctx))
		case <-timer.C:
			if !fallbackStarted && winner.leg == nil {
				fallbackStarted = true
				remaining++
				start(fallback, fallbackKind)
			}
		case next := <-results:
			remaining--
			if next.leg != nil {
				if winner.leg == nil && ctx.Err() == nil {
					winner = next
					cancel()
				} else {
					_ = next.leg.session.Close()
				}
			} else {
				failures = errors.Join(failures, next.err)
				if !fallbackStarted && winner.leg == nil && ctx.Err() == nil {
					fallbackStarted = true
					remaining++
					start(fallback, fallbackKind)
				}
			}
		}
	}
	if winner.leg == nil {
		return nil, errors.Join(ErrServiceConnection, failures)
	}
	l := winner.leg
	owned := false
	defer func() {
		if !owned {
			if l.packets != nil {
				_ = l.packets.Close()
			}
			_ = l.session.Close()
		}
	}()
	if ctx.Err() != nil || !l.until.After(time.Now()) {
		return nil, errors.Join(ErrServiceConnection, context.Cause(ctx))
	}
	l.packets, failures = peer.NewSharedSession(lifetime, winner.outer)
	if failures != nil {
		return nil, failures
	}
	id, _ := tunnelv1.ParsePeerDeliveryIdentifier(pair.DeliveryId)
	l.carrier, failures = l.packets.Register(peer.PairBinding{Delivery: tunnelv1.PeerDelivery{Pair: id, Generation: uint64(pair.DeliveryGeneration)}, Key: key, Role: 0, Path: uint8(slot)}, true)
	if failures != nil {
		return nil, failures
	}
	request, err := opaqueid.New(opaqueid.IdempotencyPrefix)
	if err == nil {
		err = l.session.ActivateNativeLeg(ctx, request)
	}
	if err != nil {
		return nil, err
	}
	owned = true
	return l, nil
}
