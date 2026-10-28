package stream

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/peer"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// peerConnection owns one inner connection, not one application admission.
// outer leg loss never replaces its streams, visitor IDs, or target sockets.
type peerConnection struct {
	prepared  *preparedSelection
	signer    Signer
	initial   preparedPeer
	source    string
	socket    *peer.Socket
	legs      [2]*peerRelayLeg
	paths     [2]*peer.CarrierSlot
	packets   *peer.Endpoint
	transport *quic.Transport
	session   muxsession.Session
	ctx       context.Context
	cancel    context.CancelCauseFunc
	done      chan struct{}
	once      sync.Once
	renewals  sync.WaitGroup
}

type peerRelayLeg struct {
	session *tunnel.Session
	carrier peer.Carrier
	receipt tunnelv1.NativePairLegAccepted
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{}
	mu      sync.Mutex
	until   time.Time
	changed chan struct{}
	retired bool
	nonce   [32]byte
}

func (l *peerRelayLeg) Close() {
	l.cancel()
	_ = l.session.Close()
	<-l.done
}

func preparePeerConnection(ctx context.Context, config Config, prepared *preparedSelection, signer Signer) (_ *peerConnection, retErr error) {
	initial, err := prepared.peerCurrent()
	if err != nil {
		return nil, err
	}
	life, cancel := context.WithCancelCause(ctx)
	p := &peerConnection{prepared: prepared, signer: signer, initial: initial, ctx: life, cancel: cancel, done: make(chan struct{})}
	defer func() {
		if retErr != nil {
			p.closeResources()
		}
	}()
	p.socket, err = peer.ListenSocket(life, "udp", ":0")
	if err != nil {
		return nil, err
	}
	startup, done := context.WithTimeout(life, 30*time.Second)
	defer done()
	type result struct {
		slot int
		leg  *peerRelayLeg
		err  error
	}
	results := make(chan result, 2)
	for slot := range 2 {
		go func() {
			leg, err := racePeerRelayLeg(startup, life, config, p.socket, initial, signer, slot, nil)
			results <- result{slot, leg, err}
		}()
	}
	var failures []error
	for range 2 {
		r := <-results
		p.legs[r.slot] = r.leg
		if r.err != nil {
			failures = append(failures, r.err)
			done()
		}
	}
	if len(failures) > 0 {
		return nil, errors.Join(failures...)
	}
	if p.legs[0].receipt.SourceIP != p.legs[1].receipt.SourceIP {
		return nil, ErrServiceConnection
	}
	p.source = p.legs[0].receipt.SourceIP
	for slot, leg := range p.legs {
		p.paths[slot] = peer.NewCarrierSlot()
		_ = p.paths[slot].Install(leg.carrier)
		p.renewals.Go(func() { p.maintainRelayLeg(config, slot) })
	}
	// both relay claims can now be discovered by the publisher. do not start
	// even packet probes until it has installed its independent registrations.
	var run Run
	for {
		currentRun, current, ready := prepared.peerPreparedRun()
		if ready == nil {
			if !samePeerDelivery(initial, current) {
				return nil, ErrServiceConnection
			}
			run = currentRun
			break
		}
		select {
		case <-startup.Done():
			return nil, context.Cause(startup)
		case <-time.After(25 * time.Millisecond):
		}
	}
	key, _ := base64.RawURLEncoding.Strict().DecodeString(initial.pair.Key)
	var packetKey [32]byte
	copy(packetKey[:], key)
	clear(key)
	paths := [3]peer.Carrier{p.paths[0], p.paths[1]}
	p.packets, err = peer.New(life, peer.Config{Kind: peer.NativePeer, Role: 0, Key: packetKey, Paths: paths})
	clear(packetKey[:])
	if err != nil {
		return nil, err
	}
	p.transport = &quic.Transport{Conn: p.packets}
	verification := config.ServiceTLS.Clone()
	verification.ServerName, verification.MinVersion, verification.NextProtos = run.Endpoint.Hostname, tls.VersionTLS13, []string{tunnelv1.ALPN}
	connection, err := p.transport.Dial(startup, p.packets.RemoteAddr(), verification, &quic.Config{
		InitialPacketSize: tunnelv1.MaxPeerPacketBytes, DisablePathMTUDiscovery: true,
		MaxIdleTimeout: 30 * time.Second, KeepAlivePeriod: 10 * time.Second,
		MaxIncomingStreams: -1, MaxIncomingUniStreams: -1,
	})
	if err != nil {
		return nil, err
	}
	p.session, err = muxsession.AdoptQUIC(connection)
	if err != nil {
		return nil, err
	}
	go p.watch()
	return p, nil
}

func samePeerDelivery(a, b preparedPeer) bool {
	return a.pair.PairId == b.pair.PairId && a.pair.DeliveryId == b.pair.DeliveryId && a.pair.DeliveryGeneration == b.pair.DeliveryGeneration && a.pair.Key == b.pair.Key &&
		a.runID == b.runID && a.number == b.number && samePairHint(a.hint, b.hint)
}

func (p *peerConnection) watch() {
	defer close(p.done)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-p.session.Done():
			p.cancel(p.session.Err())
			return
		case <-ticker.C:
			_, err := p.prepared.peerRunForRenewal(p.initial)
			if err != nil {
				p.cancel(ErrSelectionExpired)
				return
			}
		}
	}
}

func (p *peerConnection) closeResources() {
	p.cancel(context.Canceled)
	if p.session != nil {
		_ = p.session.Close()
	}
	if p.transport != nil {
		_ = p.transport.Close()
	}
	if p.packets != nil {
		_ = p.packets.Close()
	}
	p.renewals.Wait()
	for _, leg := range p.legs {
		if leg != nil {
			leg.Close()
		}
	}
	for _, path := range p.paths {
		if path != nil {
			_ = path.Close()
		}
	}
	if p.socket != nil {
		_ = p.socket.Close()
	}
}

func (p *peerConnection) Close() {
	p.once.Do(func() { p.closeResources(); <-p.done })
}

// the race joins both attempts, including a late authenticated loser. each
// attempt gets its own signed nonce so it cannot replay a consumed leg proof.
func racePeerRelayLeg(ctx, life context.Context, config Config, socket *peer.Socket, binding preparedPeer, signer Signer, slot int, previous *peerLegPredecessor) (*peerRelayLeg, error) {
	quicConnector := muxsession.QUICConnector{TLSConfig: config.TransportTLS, Dialer: socket, Config: muxsession.QUICConfig{Config: &quic.Config{EnableDatagrams: true}}}
	tcpConnector := muxsession.TLSYamuxConnector{TLSConfig: config.TransportTLS}
	return racePeerRelayCandidates(ctx, life, [2]muxsession.Connector{quicConnector, tcpConnector}, binding, signer, slot, previous)
}

func racePeerRelayCandidates(ctx, life context.Context, connectors [2]muxsession.Connector, binding preparedPeer, signer Signer, slot int, previous *peerLegPredecessor) (*peerRelayLeg, error) {
	call, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		leg *peerRelayLeg
		err error
	}
	results := make(chan result, 2)
	go func() {
		leg, err := dialPeerRelayLeg(call, life, connectors[0], binding, signer, slot, true)
		results <- result{leg, err}
	}()
	remaining := 1
	timer := time.NewTimer(250 * time.Millisecond)
	defer timer.Stop()
	fallback := false
	startTCP := func() {
		fallback = true
		remaining++
		go func() {
			leg, err := dialPeerRelayLeg(call, life, connectors[1], binding, signer, slot, false)
			results <- result{leg, err}
		}()
	}
	var winner *peerRelayLeg
	var failures []error
	for remaining > 0 {
		select {
		case <-timer.C:
			if !fallback && winner == nil && ctx.Err() == nil {
				startTCP()
			}
		case r := <-results:
			remaining--
			if r.leg != nil {
				if winner == nil && ctx.Err() == nil {
					winner = r.leg
					cancel()
				} else {
					r.leg.Close()
				}
			} else {
				failures = append(failures, r.err)
				if !fallback && winner == nil && ctx.Err() == nil {
					startTCP()
				}
			}
		}
	}
	if winner != nil {
		winner.mu.Lock()
		until, retired := winner.until, winner.retired
		winner.mu.Unlock()
		if previous != nil {
			until = minSelectionTime(until, previous.until)
			if winner.receipt.SourceIP != previous.source {
				winner.Close()
				return nil, ErrServiceConnection
			}
		}
		if retired || ctx.Err() != nil || winner.ctx.Err() != nil || !until.After(time.Now()) {
			winner.Close()
			return nil, errors.Join(context.Cause(ctx), ErrSelectionExpired)
		}
		activation, finish := context.WithDeadline(ctx, until)
		var err error
		if previous == nil {
			err = winner.session.ActivateNativeLeg(activation, "activate")
		} else {
			err = winner.session.HandoffNativeLeg(activation, "handoff", previous.nonce[:])
		}
		finish()
		if err != nil {
			winner.Close()
			if previous != nil {
				err = errors.Join(errPeerHandoffConsumed, err)
			}
			return nil, err
		}
		if ctx.Err() != nil || winner.ctx.Err() != nil || !until.After(time.Now()) {
			winner.Close()
			return nil, errors.Join(errPeerHandoffConsumed, context.Cause(ctx), ErrSelectionExpired)
		}
		winner.mu.Lock()
		winner.until = until
		close(winner.changed)
		winner.changed = make(chan struct{})
		winner.mu.Unlock()
		return winner, nil
	}
	return nil, errors.Join(ErrServiceConnection, context.Cause(ctx), errors.Join(failures...))
}

func dialPeerRelayLeg(ctx, lifetime context.Context, connector muxsession.Connector, binding preparedPeer, signer Signer, slot int, datagrams bool) (_ *peerRelayLeg, retErr error) {
	relay := binding.pair.Relays[slot]
	proof, err := newPeerLegProof(binding, signer, slot)
	if err != nil {
		return nil, err
	}
	started := time.Now()
	outer, err := connector.Connect(ctx, muxsession.Endpoint{Address: relay.RelayAddress, ServerName: relay.TlsServerName})
	if err != nil {
		return nil, err
	}
	defer func() {
		if retErr != nil {
			_ = outer.Close()
		}
	}()
	if datagrams {
		packets, ok := outer.(muxsession.DatagramSession)
		if !ok || !packets.SupportsDatagrams() {
			return nil, peer.ErrConfiguration
		}
	}
	session, receipt, err := tunnel.DialNative(ctx, outer, tunnelv1.Message{Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version,
		Role: tunnelv1.NativeConnector, NativePairLegProof: &proof}, binding.pair.DeliveryId)
	if err != nil {
		return nil, err
	}
	until := minSelectionTime(binding.expiresAt, started.Add(receipt.ExpiresAt.Sub(receipt.ObservedAt)))
	if !until.After(time.Now()) || ctx.Err() != nil {
		return nil, ErrSelectionExpired
	}
	life, cancel := context.WithCancel(lifetime)
	defer func() {
		if retErr != nil {
			cancel()
		}
	}()
	id, _ := tunnelv1.ParsePeerDeliveryIdentifier(binding.pair.DeliveryId)
	key, _ := base64.RawURLEncoding.Strict().DecodeString(binding.pair.Key)
	registration := peer.PairBinding{Delivery: tunnelv1.PeerDelivery{Pair: id, Generation: uint64(binding.pair.DeliveryGeneration)}, Kind: peer.NativePeer, Role: 0, Path: uint8(slot)}
	copy(registration.Key[:], key)
	clear(key)
	var carrier peer.Carrier
	var closePackets func() error
	if datagrams {
		shared, sharedErr := peer.NewSharedDatagrams(life, outer.(muxsession.DatagramSession))
		if sharedErr != nil {
			return nil, sharedErr
		}
		closePackets = shared.Close
		carrier, err = shared.Register(registration)
	} else {
		shared, sharedErr := peer.NewSharedStreams(life, outer)
		if sharedErr != nil {
			return nil, sharedErr
		}
		closePackets = shared.Close
		var pair *peer.StreamPair
		pair, err = shared.Register(registration)
		if err == nil {
			carrier = pair.Carrier(true)
		}
	}
	if err != nil {
		_ = closePackets()
		return nil, err
	}
	leg := &peerRelayLeg{session: session, carrier: carrier, receipt: receipt, ctx: life, cancel: cancel, done: make(chan struct{}), until: until, changed: make(chan struct{})}
	leg.carrier = &peerRelayCarrier{Carrier: carrier, stop: cancel}
	copy(leg.nonce[:], proof.Nonce)
	go func() {
		defer close(leg.done)
		leg.watchAuthority()
		cancel()
		_ = session.Close()
		_ = closePackets()
	}()
	return leg, nil
}

func newPeerLegProof(binding preparedPeer, signer Signer, slot int) (tunnelv1.NativePairLegProof, error) {
	relay := binding.pair.Relays[slot]
	proof := tunnelv1.NativePairLegProof{PairID: binding.pair.PairId, DeliveryGeneration: binding.pair.DeliveryGeneration,
		ServiceID: binding.pair.ServiceId, ServiceRunID: binding.pair.ServiceRunId, RunNumber: binding.pair.RunNumber,
		PublisherIdentityID: binding.pair.PublisherIdentityId, ConnectionSlot: slot,
		PublisherConnectionID: relay.PublisherConnectionId, AssignmentRevision: relay.AssignmentRevision,
		RelayServiceID: relay.RelayLease.RelayServiceId, RelayID: relay.RelayLease.RelayId, RelayRunID: relay.RelayLease.RelayRunId,
		RelayLeaseRevision: uint64(relay.RelayLease.RelayLeaseRevision), RequestedAt: time.Now().UTC().Truncate(time.Microsecond), Nonce: make([]byte, 32)}
	if _, err := rand.Read(proof.Nonce); err != nil {
		return tunnelv1.NativePairLegProof{}, err
	}
	message, err := proof.Message()
	if err != nil {
		return tunnelv1.NativePairLegProof{}, err
	}
	if signer.Sign == nil {
		return tunnelv1.NativePairLegProof{}, ErrServiceConnection
	}
	proof.Signature = signer.Sign(message)
	if !ed25519.Verify(signer.PublicKey, message, proof.Signature) {
		return tunnelv1.NativePairLegProof{}, ErrServiceConnection
	}
	return proof, nil
}
