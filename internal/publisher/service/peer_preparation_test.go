package service

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/peer"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type publisherPeerControlFixture struct {
	binding   PeerBinding
	claims    atomic.Bool
	calls     atomic.Int64
	confirmed atomic.Int64
	confirm   func(context.Context, controlv1.NativePeerPairPrepared) error
}

func (f *publisherPeerControlFixture) ConfirmNativePeerPairPrepared(ctx context.Context, service, run, pair string, prepared controlv1.NativePeerPairPrepared, token credentials.ServiceRunToken) error {
	b := f.binding
	if service != b.serviceID || run != b.serviceRunID || pair != b.pairID || token != "run-token" ||
		prepared.DeliveryId != base64.RawURLEncoding.EncodeToString(b.deliveryID[:]) || prepared.DeliveryGeneration != b.generation || !prepared.BindingExpiresAt.Equal(b.expiresAt) {
		return ErrPrivateStream
	}
	f.confirmed.Add(1)
	if f.confirm != nil {
		return f.confirm(ctx, prepared)
	}
	return nil
}

func (f *publisherPeerControlFixture) ListNativePeerPairs(_ context.Context, service, run, after string, token credentials.ServiceRunToken) (controlv1.NativePeerPairCandidates, error) {
	if service != f.binding.serviceID || run != f.binding.serviceRunID || after != "" || token != "run-token" {
		return controlv1.NativePeerPairCandidates{}, ErrPrivateStream
	}
	return controlv1.NativePeerPairCandidates{Items: []controlv1.NativePeerPairCandidate{{PairId: f.binding.pairID, DeliveryGeneration: f.binding.generation}}}, nil
}

func (f *publisherPeerControlFixture) DeliverNativePeerPair(_ context.Context, service, run, pair string, generation int64, token credentials.ServiceRunToken) (controlv1.NativePeerPairDelivery, error) {
	f.calls.Add(1)
	if !f.claims.Load() || service != f.binding.serviceID || run != f.binding.serviceRunID || pair != f.binding.pairID || generation != f.binding.generation || token != "run-token" {
		return controlv1.NativePeerPairDelivery{}, ErrPrivateStream
	}
	b := f.binding
	return controlv1.NativePeerPairDelivery{PairId: b.pairID, DeliveryId: base64.RawURLEncoding.EncodeToString(b.deliveryID[:]),
		DeliveryGeneration: b.generation, ServiceId: b.serviceID, ServiceRunId: b.serviceRunID, RunNumber: b.runNumber,
		PublisherIdentityId: b.publisherIdentityID, Subject: b.Subject(), Key: base64.RawURLEncoding.EncodeToString(b.key[:]),
		SourceIp: b.sourceIP.String(), Relays: b.relays[:], ObservedAt: time.Now(), ExpiresAt: b.expiresAt}, nil
}

// connectPublisherPacketSlot uses the production claimed-session constructor
// and Serve method. the server is a checked relay-session fixture, not a proof
// of the control-backed relay bridge or connector's preparation ordering.
func connectPublisherPacketSlot(t *testing.T, ctx context.Context, b *Bound, slot uint8, kind string) (*Claimed, muxsession.Session) {
	t.Helper()
	serverTLS, roots := privateTransportTLS(t)
	var endpoint muxsession.Endpoint
	var listener interface{ Close() error }
	var accept func() (muxsession.Session, error)
	config := muxsession.QUICConfig{Config: &quic.Config{EnableDatagrams: true}}
	if kind == "quic" {
		udp, err := muxsession.ListenQUIC("127.0.0.1:0", serverTLS, config)
		if err != nil {
			t.Fatal(err)
		}
		listener, endpoint.Address = udp, udp.Addr().String()
		accept = func() (muxsession.Session, error) { return udp.Accept(ctx) }
	} else {
		tcp, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listener, endpoint.Address = tcp, tcp.Addr().String()
		accept = func() (muxsession.Session, error) {
			conn, err := tcp.Accept()
			if err != nil {
				return nil, err
			}
			return muxsession.AcceptTLSYamux(ctx, conn, serverTLS, muxsession.TLSYamuxConfig{})
		}
	}
	t.Cleanup(func() { _ = listener.Close() })
	endpoint.ServerName = "relay.test"
	b.connections[slot].RelayAddress, b.connections[slot].TlsServerName = endpoint.Address, endpoint.ServerName
	ref := b.assignments[b.connections[slot].PublisherConnectionId]
	accepted := make(chan muxsession.Session, 1)
	errors := make(chan error, 1)
	go func() {
		outer, err := accept()
		if err == nil {
			_, _, err = tunnel.Accept(ctx, outer, func(_ context.Context, hello tunnelv1.Message) error {
				if hello.ServiceConnection == nil || *hello.ServiceConnection != ref {
					return ErrPrivateStream
				}
				return nil
			})
			if err == nil {
				accepted <- outer
				return
			}
			_ = outer.Close()
		}
		errors <- err
	}()
	connector := muxsession.Connector(muxsession.TLSYamuxConnector{TLSConfig: roots})
	if kind == "quic" {
		connector = muxsession.QUICConnector{TLSConfig: roots, Config: config}
	}
	// both candidates use the chosen real transport so this proof controls the
	// complete two-slot matrix without waiting for an unrelated dial timeout.
	claimed, err := b.ConnectSlotWithTransports(ctx, slot, kind != "quic", connector, connector)
	if err != nil {
		t.Fatal(err)
	}
	serving := make(chan error, 1)
	go func() { serving <- claimed.Serve(ctx) }()
	t.Cleanup(func() {
		_ = claimed.Close()
		select {
		case <-serving:
		case <-time.After(3 * time.Second):
			t.Error("claimed publisher did not join")
		}
	})
	select {
	case outer := <-accepted:
		t.Cleanup(func() { _ = outer.Close() })
		return claimed, outer
	case err := <-errors:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	return nil, nil
}

func TestPeerPreparationDiscoversAndServesOnClaimedPublisherConnections(t *testing.T) {
	for _, first := range []string{"quic", "tls-yamux"} {
		for _, second := range []string{"quic", "tls-yamux"} {
			t.Run(first+"/"+second, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 12*time.Second)
				defer cancel()
				target, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				defer target.Close()
				_, b, _, verification := privateFixture(t, target.Addr().String())
				b.nativePeers = true
				var slots [2]*Claimed
				var relays [2]muxsession.Session
				for slot, kind := range []string{first, second} {
					slots[slot], relays[slot] = connectPublisherPacketSlot(t, ctx, b, uint8(slot), kind)
				}
				binding := peerAdmissionFixture(t, b)
				control := &publisherPeerControlFixture{binding: binding}
				reports := make(chan *PeerSession, 2)
				control.confirm = func(_ context.Context, _ controlv1.NativePeerPairPrepared) error {
					b.mu.Lock()
					p := b.peers[binding.pairID]
					installed := p != nil && p.deliveryStarted && b.peerPacketSlotsCurrentLocked(p.binding)
					b.mu.Unlock()
					if !installed {
						t.Error("publisher reported before installing both exact carrier registrations")
						return ErrPrivateStream
					}
					select {
					case <-p.packetReady:
					default:
						t.Error("publisher reported before installing the inner listener")
					}
					reports <- p
					if control.confirmed.Load() == 1 {
						return ErrPrivateStream // retry the report, not the inner session.
					}
					return nil
				}
				control.claims.Store(true)
				prepared := make(chan error, 1)
				go func() { prepared <- b.ServeNativePeers(ctx, control, "run-token") }()
				defer func() {
					cancel()
					select {
					case err := <-prepared:
						if err != nil {
							t.Error(err)
						}
					case <-time.After(3 * time.Second):
						t.Error("publisher pair preparation did not join")
					}
				}()
				var owner *PeerSession
				for owner == nil {
					b.mu.Lock()
					owner = b.peers[binding.pairID]
					b.mu.Unlock()
					if owner != nil {
						break
					}
					select {
					case err := <-prepared:
						t.Fatal("preparation exited", err)
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					case <-time.After(time.Millisecond):
					}
				}
				select {
				case <-owner.packetReady:
				case <-ctx.Done():
					t.Fatal("pair did not install both packet registrations", ctx.Err())
				}
				for range 2 {
					select {
					case reported := <-reports:
						if reported != owner {
							t.Fatal("retry replaced the installed inner listener")
						}
					case <-ctx.Done():
						t.Fatal("publisher did not retry its preparation report", ctx.Err())
					}
				}
				var outgoing [3]peer.Carrier
				for slot, relay := range relays {
					pair := peer.PairBinding{Delivery: tunnelv1.PeerDelivery{Pair: binding.deliveryID, Generation: uint64(binding.generation)},
						Key: binding.key, Kind: peer.NativePeer, Role: 0, Path: uint8(slot)}
					if datagrams, ok := relay.(muxsession.DatagramSession); ok {
						shared, err := peer.NewSharedDatagrams(ctx, datagrams)
						if err != nil {
							t.Fatal(err)
						}
						defer shared.Close()
						outgoing[slot], err = shared.Register(pair)
						if err != nil {
							t.Fatal(err)
						}
					} else {
						shared, err := peer.NewSharedStreams(ctx, relay)
						if err != nil {
							t.Fatal(err)
						}
						defer shared.Close()
						registration, err := shared.Register(pair)
						if err != nil {
							t.Fatal(err)
						}
						outgoing[slot] = registration.Carrier(true)
					}
				}
				packets, err := peer.New(ctx, peer.Config{Kind: peer.NativePeer, Role: 0, Key: binding.key, Paths: outgoing})
				if err != nil {
					t.Fatal(err)
				}
				defer packets.Close()
				transport := &quic.Transport{Conn: packets}
				defer transport.Close()
				trust := verification.Clone()
				trust.MinVersion, trust.NextProtos = tls.VersionTLS13, []string{tunnelv1.ALPN}
				connection, err := transport.Dial(ctx, packets.RemoteAddr(), trust, &quic.Config{InitialPacketSize: tunnelv1.MaxPeerPacketBytes, DisablePathMTUDiscovery: true})
				if err != nil {
					t.Fatal("prepared inner QUIC did not authenticate the service", err)
				}
				session, err := muxsession.AdoptQUIC(connection)
				if err != nil {
					t.Fatal(err)
				}
				defer session.Close()
				stream, err := session.OpenStream(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer stream.Close()
				_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
				entry := peerVisitorOpening(t, b, binding, "vc_"+strings.Repeat("v", 22), nil)
				if _, err := tunnelv1.WriteNativePeerVisitorOpening(stream, entry, nil); err != nil {
					t.Fatal(err)
				}
				visitor := tls.Client(tunnel.NewNativeRequestWriter(stream), verification)
				if err := visitor.HandshakeContext(ctx); err != nil {
					t.Fatal(err)
				}
				_ = target.SetDeadline(time.Now().Add(time.Second))
				backend, err := target.Accept()
				if err != nil {
					t.Fatal(err)
				}
				defer backend.Close()
				_ = backend.SetDeadline(time.Now().Add(5 * time.Second))
				echo := make(chan error, 1)
				go func() { _, err := io.Copy(backend, backend); echo <- err }()
				for _, value := range []byte{1, 2} {
					if _, err := visitor.Write([]byte{value}); err != nil {
						t.Fatal(err)
					}
					var reply [1]byte
					if _, err := io.ReadFull(visitor, reply[:]); err != nil || reply[0] != value {
						t.Fatal("claimed carrier change lost the application stream", err)
					}
					if value == 1 {
						_ = slots[0].Close()
					}
				}
				b.mu.Lock()
				admissions, visitors := b.reservedStreams, len(owner.seen)
				b.mu.Unlock()
				if admissions != 1 || visitors != 1 || connection.Context().Err() != nil || packets.ActivePath() != peer.RelayB {
					t.Fatal("carrier loss repeated admission or replaced the inner connection", admissions, visitors)
				}
				_ = target.SetDeadline(time.Now().Add(10 * time.Millisecond))
				if extra, err := target.Accept(); err == nil {
					_ = extra.Close()
					t.Fatal("carrier loss opened another target")
				}
				_ = backend.Close()
				<-echo
			})
		}
	}
}

func TestPeerPreparationRejectsMalformedPagesAndReapsOnlyExpiredReplayFences(t *testing.T) {
	for _, page := range []controlv1.NativePeerPairCandidates{
		{},
		{Items: []controlv1.NativePeerPairCandidate{{PairId: "invalid", DeliveryGeneration: 1}}},
		{Items: []controlv1.NativePeerPairCandidate{}, NextAfter: new("npp_" + strings.Repeat("a", 22))},
	} {
		if validPeerCandidates(page, "") {
			t.Fatal("malformed candidate page was accepted")
		}
	}
	synctest.Test(t, func(t *testing.T) {
		_, b, _, _ := privateFixture(t, "127.0.0.1:1")
		binding := peerAdmissionFixture(t, b)
		p, err := b.BindPeer(t.Context(), binding)
		if err != nil {
			t.Fatal(err)
		}
		p.Close()
		candidate := controlv1.NativePeerPairCandidate{PairId: binding.pairID, DeliveryGeneration: binding.generation}
		if b.peerNeedsPreparation(candidate) {
			t.Fatal("a stopped pair could be revived")
		}
		time.Sleep(5*time.Minute + time.Nanosecond)
		_ = b.peerNeedsPreparation(candidate)
		b.mu.Lock()
		defer b.mu.Unlock()
		if len(b.peers) != 0 {
			t.Fatal("expired replay fences blocked later pair preparation")
		}
	})
}

type blockedPeerDiscovery struct {
	NativePeerControl
	started chan struct{}
}

func (f blockedPeerDiscovery) ListNativePeerPairs(ctx context.Context, _, _, _ string, _ credentials.ServiceRunToken) (controlv1.NativePeerPairCandidates, error) {
	close(f.started)
	<-ctx.Done()
	return controlv1.NativePeerPairCandidates{}, ctx.Err()
}

func TestPeerPreparationCancellationJoinsBlockedDiscovery(t *testing.T) {
	_, b, _, _ := privateFixture(t, "127.0.0.1:1")
	b.nativePeers = true
	ctx, cancel := context.WithCancel(t.Context())
	control := blockedPeerDiscovery{started: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- b.ServeNativePeers(ctx, control, "run-token") }()
	<-control.started
	if err := b.ServeNativePeers(ctx, control, "run-token"); !errors.Is(err, ErrPrivateStream) {
		t.Fatal("a second preparation owner started for the same run", err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked discovery survived owner cancellation")
	}
}

func TestPeerPreparationCancellationJoinsConfirmationAndRejectsLateSuccess(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, b, _, _ := privateFixture(t, "127.0.0.1:1")
		b.nativePeers = true
		binding := peerAdmissionFixture(t, b)
		owner, err := b.BindPeer(t.Context(), binding)
		if err != nil {
			t.Fatal(err)
		}
		defer owner.Close()
		// this proof isolates confirmation ownership. the transport matrix above
		// proves the real registrations/listener precede this signal.
		close(owner.packetReady)
		for slot, assignment := range b.connections {
			b.packetSlots[slot] = &Claimed{ref: b.assignments[assignment.PublisherConnectionId], packets: &publisherPeerPackets{ctx: t.Context()}}
		}
		started, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
		control := &publisherPeerControlFixture{binding: binding, confirm: func(ctx context.Context, _ controlv1.NativePeerPairPrepared) error {
			close(started)
			<-ctx.Done()
			close(canceled)
			<-release
			return nil // a late successful response cannot confirm a stopped owner.
		}}
		control.claims.Store(true)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- b.ServeNativePeers(ctx, control, "run-token") }()
		<-started
		cancel()
		<-canceled
		synctest.Wait()
		select {
		case <-done:
			t.Fatal("shutdown returned before joining the confirmation worker")
		default:
		}
		owner.Close()
		close(release)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		if owner.publisherPrepared || !owner.closed || b.peers[binding.pairID] != owner {
			t.Fatal("late confirmation revived or replaced the stopped owner")
		}
	})
}

type blockedPeerBindings struct {
	NativePeerControl
	started chan struct{}
	active  atomic.Int64
	peak    atomic.Int64
}

func (f *blockedPeerBindings) ListNativePeerPairs(context.Context, string, string, string, credentials.ServiceRunToken) (controlv1.NativePeerPairCandidates, error) {
	page := controlv1.NativePeerPairCandidates{Items: make([]controlv1.NativePeerPairCandidate, maxPublisherPeerSessions)}
	for i := range page.Items {
		page.Items[i] = controlv1.NativePeerPairCandidate{PairId: fmt.Sprintf("npp_%022d", i), DeliveryGeneration: 1}
	}
	return page, nil
}

func (f *blockedPeerBindings) DeliverNativePeerPair(ctx context.Context, _, _, _ string, _ int64, _ credentials.ServiceRunToken) (controlv1.NativePeerPairDelivery, error) {
	active := f.active.Add(1)
	defer f.active.Add(-1)
	for old := f.peak.Load(); old < active; old = f.peak.Load() {
		if f.peak.CompareAndSwap(old, active) {
			break
		}
	}
	f.started <- struct{}{}
	<-ctx.Done()
	return controlv1.NativePeerPairDelivery{}, ctx.Err()
}

func TestPeerPreparationBoundsWorkersAndJoinsBlockedBindings(t *testing.T) {
	_, b, _, _ := privateFixture(t, "127.0.0.1:1")
	b.nativePeers = true
	// only the scheduling boundary is under test; the blocked control never
	// returns authority that could reach either packet slot.
	for slot, assignment := range b.connections {
		b.packetSlots[slot] = &Claimed{ref: b.assignments[assignment.PublisherConnectionId], packets: &publisherPeerPackets{ctx: t.Context()}}
	}
	control := &blockedPeerBindings{started: make(chan struct{}, maxPublisherPeerSessions)}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- b.ServeNativePeers(ctx, control, "run-token") }()
	for range peerPreparationWorkers {
		select {
		case <-control.started:
		case <-time.After(time.Second):
			t.Fatal("preparation workers did not start")
		}
	}
	if control.active.Load() != peerPreparationWorkers || control.peak.Load() != peerPreparationWorkers {
		t.Fatal("candidate page exceeded the preparation worker bound")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil || control.active.Load() != 0 || control.peak.Load() > peerPreparationWorkers {
			t.Fatal("binding preparation did not join", err)
		}
	case <-time.After(time.Second):
		t.Fatal("binding preparation survived cancellation")
	}
}

func TestPeerPreparationRenewalDoesNotReviveStoppedOrExtendDeniedAuthority(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, b, _, _ := privateFixture(t, "127.0.0.1:1")
		b.nativePeers = true
		binding := peerAdmissionFixture(t, b)
		binding.expiresAt = time.Now().Add(5 * time.Second)
		owner, err := b.BindPeer(t.Context(), binding)
		if err != nil {
			t.Fatal(err)
		}
		defer owner.Close()
		fresh := binding
		fresh.expiresAt = time.Now().Add(20 * time.Second)
		control := &publisherPeerControlFixture{binding: fresh}
		control.claims.Store(true)
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- b.ServeNativePeers(ctx, control, "run-token") }()
		synctest.Wait()
		b.mu.Lock()
		deadline := owner.binding.expiresAt
		b.mu.Unlock()
		if !deadline.Equal(fresh.expiresAt) {
			t.Fatal("fresh control authority did not renew the existing owner")
		}
		control.claims.Store(false)
		time.Sleep(10 * time.Second)
		synctest.Wait()
		b.mu.Lock()
		deadline, stopped := owner.binding.expiresAt, owner.closed
		b.mu.Unlock()
		if stopped || !deadline.Equal(fresh.expiresAt) || control.calls.Load() < 2 {
			t.Fatal("denied renewal changed the last confirmed authority")
		}
		time.Sleep(10 * time.Second)
		synctest.Wait()
		b.mu.Lock()
		stopped = owner.closed
		b.mu.Unlock()
		if !stopped {
			t.Fatal("the old owner survived its fixed deadline")
		}
		if err := owner.Renew(fresh); !errors.Is(err, ErrPrivateStream) {
			t.Fatal("a stopped owner was revived", err)
		}
		cancel()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	})
}

type nativePeerLifecycleControl struct {
	*lifecycleControl
	started chan struct{}
	stopped chan struct{}
}

func (f *nativePeerLifecycleControl) ListNativePeerPairs(ctx context.Context, service, run, after string, token credentials.ServiceRunToken) (controlv1.NativePeerPairCandidates, error) {
	if service != f.prep.ServiceId || run != f.prep.ServiceRunId || after != "" || token.String() != f.setup.RunToken {
		return controlv1.NativePeerPairCandidates{}, ErrPrivateStream
	}
	close(f.started)
	defer close(f.stopped)
	<-ctx.Done()
	return controlv1.NativePeerPairCandidates{}, ctx.Err()
}

func (f *nativePeerLifecycleControl) DeliverNativePeerPair(context.Context, string, string, string, int64, credentials.ServiceRunToken) (controlv1.NativePeerPairDelivery, error) {
	return controlv1.NativePeerPairDelivery{}, ErrPrivateStream
}

func (f *nativePeerLifecycleControl) ConfirmNativePeerPairPrepared(context.Context, string, string, string, controlv1.NativePeerPairPrepared, credentials.ServiceRunToken) error {
	return ErrPrivateStream
}

func TestPeerPreparationPublishOwnsAndJoinsDiscovery(t *testing.T) {
	config, base := lifecycleFixture(t)
	control := &nativePeerLifecycleControl{lifecycleControl: base, started: make(chan struct{}), stopped: make(chan struct{})}
	config.Control, config.NativePeers = control, true
	config.Connect = func(_ context.Context, bound *Bound, _ uint8) (SlotSession, error) {
		if !bound.nativePeers {
			t.Error("publication did not configure peer-capable slots")
		}
		return &heldSlot{stopped: make(chan struct{})}, nil
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Publish(ctx, config) }()
	select {
	case <-control.started:
	case err := <-done:
		t.Fatal("publication exited before starting discovery", err)
	case <-time.After(3 * time.Second):
		t.Fatal("publication never started native pair discovery")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("publication did not join native discovery")
	}
	select {
	case <-control.stopped:
	default:
		t.Fatal("publication returned with native discovery still running")
	}
}

func TestPeerPreparationRejectsDatagramlessQUICBeforePublisherClaim(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	serverTLS, roots := privateTransportTLS(t)
	listener, err := muxsession.ListenQUIC("127.0.0.1:0", serverTLS, muxsession.QUICConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	claim := make(chan bool, 1)
	accepted := make(chan struct{})
	go func() {
		session, err := listener.Accept(ctx)
		if err != nil {
			claim <- false
			return
		}
		defer session.Close()
		close(accepted)
		stream, err := session.AcceptStream(ctx)
		if err == nil {
			_ = stream.Close()
		}
		claim <- err == nil
	}()
	// synchronize the fixture's server acceptance before checking teardown;
	// a real client may close before the listener exposes the handshake at all.
	connector := requirePublisherPeerDatagrams(muxsession.ConnectorFunc(func(ctx context.Context, endpoint muxsession.Endpoint) (muxsession.Session, error) {
		session, err := (muxsession.QUICConnector{TLSConfig: roots, Config: muxsession.QUICConfig{Config: &quic.Config{EnableDatagrams: true}}}).Connect(ctx, endpoint)
		if err != nil {
			return nil, err
		}
		select {
		case <-accepted:
			return session, nil
		case <-ctx.Done():
			_ = session.Close()
			return nil, ctx.Err()
		}
	}))
	session, err := connector.Connect(ctx, muxsession.Endpoint{Address: listener.Addr().String(), ServerName: "relay.test"})
	if session != nil || !errors.Is(err, ErrPrivateStream) || !errors.Is(err, peer.ErrConfiguration) {
		t.Fatal("datagramless QUIC was allowed to consume a single-use claim", err)
	}
	select {
	case claimed := <-claim:
		if claimed {
			t.Fatal("datagramless QUIC opened a publisher hello stream")
		}
	case <-ctx.Done():
		t.Fatal("rejected QUIC transport was not closed")
	}
}

func TestPeerPreparationAssignmentReplacementRetiresOnlyTheOldPacketSlot(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, b, _, _ := privateFixture(t, "127.0.0.1:1")
	b.nativePeers = true
	old, oldOuter := connectPublisherPacketSlot(t, ctx, b, 0, "tls-yamux")
	sibling, siblingOuter := connectPublisherPacketSlot(t, ctx, b, 1, "tls-yamux")
	connections := []controlv1.ConnectionAssignment{b.connections[0], b.connections[1]}
	id, err := opaqueid.New(opaqueid.PublisherConnectionPrefix)
	if err != nil {
		t.Fatal(err)
	}
	connections[0].PublisherConnectionId = id
	connections[0].ConnectionAssignmentRevision++
	if err := b.ApplyHeartbeat(controlv1.ServiceRunState{ServiceId: b.prepared.Preparation.ServiceId,
		ServiceRunId: b.prepared.Preparation.ServiceRunId, RunNumber: b.prepared.Preparation.RunNumber,
		State: "ready", PublisherExpiresAt: time.Now().Add(time.Minute), PublisherConnections: connections}); err != nil {
		t.Fatal(err)
	}
	candidate := controlv1.NativePeerPairCandidate{PairId: "npp_" + strings.Repeat("x", 22), DeliveryGeneration: 2}
	if b.peerNeedsPreparation(candidate) {
		t.Fatal("stale packet slot was eligible for a new pair")
	}
	replacement, _ := connectPublisherPacketSlot(t, ctx, b, 0, "tls-yamux")
	_ = old.Close()
	b.mu.Lock()
	current := b.packetSlots == [2]*Claimed{replacement, sibling}
	b.mu.Unlock()
	if !current || !b.peerNeedsPreparation(candidate) {
		t.Fatal("late old-slot cleanup removed the replacement or sibling")
	}
	select {
	case <-oldOuter.Done():
	case <-ctx.Done():
		t.Fatal("replaced packet slot was not closed")
	}
	select {
	case <-siblingOuter.Done():
		t.Fatal("assignment replacement closed the healthy sibling")
	default:
	}
}
