package service

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/peer"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// ServePackets consumes already-authorized carriers for this prepared pair.
// it owns exactly one inner QUIC connection; replacing a carrier cannot open
// another target socket or discard replay and capacity state. the relay role
// must register each shared carrier against the binding's exact delivery ID.
func (p *PeerSession) ServePackets(ctx context.Context, paths [3]peer.Carrier) error {
	defer closePeerCarriers(paths)
	return p.servePackets(ctx, func(PeerBinding) ([3]peer.Carrier, error) { return paths, nil })
}

// ServeRelayPackets registers the exact control-prepared binding on both current
// claimed publisher connections before accepting the one inner QUIC session.
func (p *PeerSession) ServeRelayPackets(ctx context.Context) error {
	return p.servePackets(ctx, p.bound.peerCarriers)
}

func (p *PeerSession) servePackets(ctx context.Context, prepare func(PeerBinding) ([3]peer.Carrier, error)) error {
	p.bound.mu.Lock()
	if p.closed || p.deliveryStarted || ctx.Err() != nil || !p.bound.peerBindingCurrentLocked(p.binding, time.Now()) {
		p.bound.mu.Unlock()
		return ErrPrivateStream
	}
	p.deliveryStarted = true
	p.delivery.Add(1)
	binding := p.binding
	p.bound.mu.Unlock()
	defer p.delivery.Done()
	defer p.stop()
	life, cancel := context.WithCancel(p.ctx)
	stopCaller := context.AfterFunc(ctx, cancel)
	defer func() { stopCaller(); cancel() }()
	paths, err := prepare(binding)
	if err != nil {
		return err
	}
	defer closePeerCarriers(paths)
	var direct *peer.CarrierSlot
	if p.bound.peerSocket != nil {
		direct = peer.NewCarrierSlot()
		paths[peer.Direct] = direct
		defer direct.Close()
	}
	packets, err := peer.New(life, peer.Config{Kind: peer.NativePeer, Key: binding.key, Role: 1, Paths: paths})
	if err != nil {
		return err
	}
	defer packets.Close()
	transport := &quic.Transport{Conn: packets}
	defer transport.Close()
	listener, err := transport.Listen(&tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{tunnelv1.ALPN},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello.ServerName != p.bound.prepared.managedHostname {
				return nil, ErrPrivateStream
			}
			return p.bound.prepared.currentCertificate()
		}}, &quic.Config{InitialPacketSize: tunnelv1.MaxPeerPacketBytes, DisablePathMTUDiscovery: true,
		MaxIncomingStreams: 64, MaxIncomingUniStreams: 1, MaxIdleTimeout: 30 * time.Second, KeepAlivePeriod: 10 * time.Second})
	if err != nil {
		return err
	}
	defer listener.Close()
	close(p.packetReady)
	connection, err := listener.Accept(life)
	if err != nil {
		if life.Err() != nil {
			return nil
		}
		return err
	}
	// one pair is one inner connection. subsequent handshakes cannot create
	// an independent stream/replay owner on these same carriers.
	_ = listener.Close()
	session, err := muxsession.AdoptQUIC(connection)
	if err != nil {
		return err
	}
	closed := make(chan struct{})
	stopSession := context.AfterFunc(life, func() { _ = session.Close(); close(closed) })
	var workers sync.WaitGroup
	if direct != nil {
		workers.Go(func() {
			_ = peer.ServeConnectivity(life, p.bound.peerSocket, connection, packets, direct, peer.ConnectivityBinding{
				PairID: binding.pairID, DeliveryID: base64.RawURLEncoding.EncodeToString(binding.deliveryID[:]), Generation: binding.generation,
				RelayAddresses: [2]string{binding.relays[0].RelayAddress, binding.relays[1].RelayAddress},
			}, false, p.bound.peerConnectivity)
		})
	}
	slots := make(chan struct{}, 64)
	defer func() {
		cancel()
		_ = session.Close()
		workers.Wait()
		if !stopSession() {
			<-closed
		}
	}()
	for {
		stream, err := session.AcceptStream(life)
		if err != nil {
			if life.Err() != nil || errors.Is(err, muxsession.ErrClosed) {
				return nil
			}
			return err
		}
		select {
		case slots <- struct{}{}:
			workers.Go(func() { defer func() { <-slots }(); _ = p.ServeStream(life, stream) })
		default:
			_ = stream.Reset(0)
		}
	}
}
