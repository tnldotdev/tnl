package daemon

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/stun/v4"
	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/transport/peer"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type connectorDirectObservation struct {
	mu      sync.Mutex
	current peer.ConnectivityState
	history []peer.ConnectivityState
}

func (o *connectorDirectObservation) observe(state peer.ConnectivityState) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.current = state
	o.history = append(o.history, state)
}

func (o *connectorDirectObservation) state() peer.ConnectivityState {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.current
}

func (o *connectorDirectObservation) count(state peer.ConnectivityState) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	var count int
	for _, observed := range o.history {
		if observed == state {
			count++
		}
	}
	return count
}

func (o *connectorDirectObservation) relaying() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	// checks for the next attempt may already be running after fallback. they
	// do not replace the relay delivery proven by the last terminal state.
	for index := len(o.history) - 1; index >= 0; index-- {
		switch o.history[index] {
		case peer.ConnectivityDirect:
			return false
		case peer.ConnectivityRelay:
			return true
		}
	}
	return false
}

func connectorDirectObservations(t *testing.T) (observations [2]*connectorDirectObservation) {
	t.Helper()
	for side := range observations {
		observations[side] = new(connectorDirectObservation)
	}
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		for side, observation := range observations {
			observation.mu.Lock()
			t.Logf("connectivity side=%d history=%v", side, observation.history)
			observation.mu.Unlock()
		}
	})
	return observations
}

func waitConnectorDirectState(t *testing.T, observations [2]*connectorDirectObservation, state peer.ConnectivityState) {
	t.Helper()
	privateWait(t, 25*time.Second, func(context.Context) (bool, error) {
		if state == peer.ConnectivityRelay {
			return observations[0].relaying() && observations[1].relaying(), nil
		}
		return observations[0].state() == state && observations[1].state() == state, nil
	})
}

// physical UDP remains real. faults neither supply source metadata nor replace
// production relay connectors, signaling, ICE agents or packet authentication.
type connectorDirectPacketConn struct {
	net.PacketConn
	relays         map[string]bool
	blockDirect    atomic.Bool
	blockChecks    atomic.Bool
	blockRelays    atomic.Bool
	rejectThrough  atomic.Uint64
	latestAttempt  atomic.Uint64
	directDropped  atomic.Uint64
	directDataSent atomic.Uint64
	directDataRead atomic.Uint64
	relaySent      atomic.Uint64
	relayRead      atomic.Uint64
	stunSent       atomic.Uint64
	checksDropped  atomic.Uint64
}

func (p *connectorDirectPacketConn) inspect(packet []byte, address net.Addr) (drop, data, relay bool) {
	relay = p.relays[address.String()]
	if relay {
		return p.blockRelays.Load() && !stun.IsMessage(packet), false, true
	}
	drop = p.blockDirect.Load()
	if p.blockChecks.Load() && stun.IsMessage(packet) {
		drop = true
		p.checksDropped.Add(1)
	}
	// only inspect public framing for counters. production still authenticates
	// both envelopes; the fixture never reads or stores a packet key.
	const header, tag = tunnelv1.ConnectorPeerDirectHeaderBytes, tunnelv1.ConnectorPeerDirectTagBytes
	if len(packet) > header+tag+tunnelv1.PeerPacketOverhead && packet[0] == tunnelv1.Version {
		frame, err := tunnelv1.ParsePeerPacket(packet[header : len(packet)-tag])
		if err == nil && frame.Path == peer.Direct {
			attempt := binary.BigEndian.Uint64(packet[9:17])
			for previous := p.latestAttempt.Load(); attempt > previous; previous = p.latestAttempt.Load() {
				if p.latestAttempt.CompareAndSwap(previous, attempt) {
					break
				}
			}
			drop = drop || attempt <= p.rejectThrough.Load()
			data = frame.Kind == tunnelv1.PeerData
		}
	}
	if drop {
		p.directDropped.Add(1)
	}
	return drop, data, false
}

func (p *connectorDirectPacketConn) WriteTo(packet []byte, address net.Addr) (int, error) {
	drop, data, relay := p.inspect(packet, address)
	if drop {
		return len(packet), nil
	}
	n, err := p.PacketConn.WriteTo(packet, address)
	if err == nil {
		if data {
			p.directDataSent.Add(1)
		}
		if relay && !stun.IsMessage(packet) {
			p.relaySent.Add(1)
		}
		if stun.IsMessage(packet) {
			p.stunSent.Add(1)
		}
	}
	return n, err
}

func (p *connectorDirectPacketConn) ReadFrom(packet []byte) (int, net.Addr, error) {
	for {
		n, address, err := p.PacketConn.ReadFrom(packet)
		if err != nil {
			return n, address, err
		}
		drop, data, relay := p.inspect(packet[:n], address)
		if drop {
			continue
		}
		if data {
			p.directDataRead.Add(1)
		}
		if relay && !stun.IsMessage(packet[:n]) {
			p.relayRead.Add(1)
		}
		return n, address, nil
	}
}

func connectorDirectSockets(t *testing.T, f *privateSeparatedFixture, source *atomic.Uint32) (sockets [2]*peer.Socket, packets [2]*connectorDirectPacketConn) {
	t.Helper()
	for side := range sockets {
		var physical net.PacketConn
		var err error
		if side == 0 && source != nil {
			physical, err = newRebindingPacketConn(source)
		} else {
			physical, err = net.ListenPacket("udp4", "127.0.0.1:0")
		}
		if err != nil {
			t.Fatal(err)
		}
		packet := &connectorDirectPacketConn{PacketConn: physical, relays: make(map[string]bool)}
		for advertised, address := range f.quicAddresses {
			if advertised != address {
				t.Fatal("direct qualification requires real advertised relay UDP addresses")
			}
			packet.relays[address] = true
		}
		socket, err := peer.ListenSocketPacket(t.Context(), packet)
		if err != nil {
			_ = physical.Close()
			t.Fatal(err)
		}
		sockets[side], packets[side] = socket, packet
		t.Cleanup(func() { _ = socket.Close() })
	}
	t.Cleanup(func() {
		for side, packet := range packets {
			t.Logf("UDP side=%d relay sent/read=%d/%d direct data sent/read=%d/%d dropped=%d attempt=%d STUN=%d", side,
				packet.relaySent.Load(), packet.relayRead.Load(), packet.directDataSent.Load(), packet.directDataRead.Load(), packet.directDropped.Load(), packet.latestAttempt.Load(), packet.stunSent.Load())
		}
	})
	return sockets, packets
}

func startConnectorDirectPublisher(t *testing.T, f *privateSeparatedFixture, service controlv1.Service, target string, socket *peer.Socket, connectivity peer.ConnectivityOptions) {
	t.Helper()
	enrollment, err := f.identity.routes.CreatePublisherEnrollment(t.Context(), controlv1.CreatePublisherEnrollmentRequest{TeamId: service.TeamId, ServiceId: &service.Id, Kind: controlv1.CreatePublisherEnrollmentRequestKindInstalled, Name: "connector-direct"})
	if err != nil {
		t.Fatal(err)
	}
	native, identity, err := publisheridentity.EnrollNative(t.Context(), f.identity.state, f.identity.routes, f.identity.authority, enrollment.EnrollmentKey)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	ready, done := make(chan struct{}), make(chan error, 1)
	go func() {
		config := publisherservice.RunConfig{Control: f.identity.routes, State: f.identity.state, Access: native.Access, Identity: identity, ServiceID: service.Id, Target: target,
			Metadata:     controlv1.ServiceMetadata{Protocol: service.Protocol, TargetTls: service.TargetTls, TrustRevision: service.TrustRevision, PublisherPool: service.PublisherPool},
			TransportTLS: f.roots, HeartbeatInterval: 100 * time.Millisecond, PeerSocket: socket, Connectivity: connectivity,
			Ready: func() error { close(ready); return nil }}
		if socket != nil {
			// the physical UDP fence must cover every relay carrier in direct-only
			// exchanges. default composition separately exercises both transports.
			config.RelayTCP = privateDisabledConnector()
		}
		done <- publisherservice.Publish(ctx, config)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("direct publisher shutdown: %v", err)
			}
		case <-time.After(12 * time.Second):
			t.Error("direct publisher did not join")
		}
	})
	select {
	case <-ready:
	case err := <-done:
		done <- err
		t.Fatal("direct publisher startup", err)
	case <-time.After(20 * time.Second):
		t.Fatal("direct publisher never became ready")
	}
}

type connectorDirectRuntime struct {
	service  controlv1.Service
	listener net.Listener
	control  *rebindingControl
	stop     func()
}

func startConnectorDirectRuntime(t *testing.T, f *privateSeparatedFixture, target string, sockets [2]*peer.Socket, options [2]peer.ConnectivityOptions) connectorDirectRuntime {
	t.Helper()
	key, err := opaqueid.New(opaqueid.IdempotencyPrefix)
	if err != nil {
		t.Fatal(err)
	}
	service, err := f.identity.routes.CreateService(t.Context(), f.identity.teamID, "connector-direct", key)
	if err != nil {
		t.Fatal(err)
	}
	startConnectorDirectPublisher(t, f, service, target, sockets[1], options[1])
	person, err := f.identity.authority.IdentityContext(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	production, err := connectorstream.NewControl(f.identity.routes, f.identity.state, person.Identity.Id)
	if err != nil {
		t.Fatal(err)
	}
	control := &rebindingControl{Control: production, t: t}
	config := connectorstream.Config{Control: control, IdentityID: person.Identity.Id, PeerSocket: sockets[0], Connectivity: options[0]}
	if sockets[0] != nil {
		config.RelayTCP = privateDisabledConnector()
	}
	listener, stop := startRuntimeConnector(t, f, service, config)
	return connectorDirectRuntime{service: service, listener: listener, control: control, stop: stop}
}

func connectorDirectOptions(observations [2]*connectorDirectObservation) (options [2]peer.ConnectivityOptions) {
	for side := range options {
		options[side] = peer.ConnectivityOptions{IncludeLoopback: true, Observe: observations[side].observe}
	}
	return options
}

func connectorDirectExchange(t *testing.T, connection net.Conn, message string) {
	t.Helper()
	started := time.Now()
	_ = connection.SetDeadline(started.Add(15 * time.Second))
	if _, err := io.WriteString(connection, message); err != nil {
		t.Fatal("retained application write", err)
	}
	response := make([]byte, len(message))
	if _, err := io.ReadFull(connection, response); err != nil || string(response) != message {
		t.Fatalf("retained application response %q: %v", message, err)
	}
	t.Logf("application message=%q elapsed=%s", message, time.Since(started).Round(time.Millisecond))
}

func assertConnectorDirectTarget(t *testing.T, target *privateEchoTarget, messages []string) {
	t.Helper()
	target.mu.Lock()
	defer target.mu.Unlock()
	for _, message := range messages {
		if target.received[message] != 1 || target.receivedOn[message] != target.receivedOn[messages[0]] {
			t.Fatalf("path change replayed bytes or reopened target for %q", message)
		}
	}
}

func assertConnectorDirectOwner(t *testing.T, f *privateSeparatedFixture, runtime connectorDirectRuntime, before rebindingObservation, generationChanged bool) {
	t.Helper()
	after := readRebindingObservation(t, f, runtime.service.Id)
	if after.pairID != before.pairID || after.runID != before.runID || after.number != before.number || runtime.control.selections.Load() != 1 {
		t.Fatal("delivery change replaced the pair, service run or connector owner")
	}
	if !generationChanged && after.generation != before.generation {
		t.Fatal("direct delivery failure unnecessarily rebound relay authority")
	}
	var pairs, ingresses int
	if err := f.inspect.QueryRowContext(t.Context(), `SELECT count(*) FROM control.connector_peer_pairs WHERE service_id=$1`, runtime.service.Id).Scan(&pairs); err != nil {
		t.Fatal(err)
	}
	if err := f.inspect.QueryRowContext(t.Context(), `SELECT count(*) FROM control.ingress_leases`).Scan(&ingresses); err != nil {
		t.Fatal(err)
	}
	if pairs != 1 || ingresses != 0 {
		t.Fatal("connector delivery created a second pair or used ingress", pairs, ingresses)
	}
}

func connectorDirectOnly(t *testing.T, packets [2]*connectorDirectPacketConn, exchange func()) {
	t.Helper()
	var sent, read [2]uint64
	for side, packet := range packets {
		packet.blockRelays.Store(true)
		sent[side], read[side] = packet.directDataSent.Load(), packet.directDataRead.Load()
	}
	defer func() {
		for _, packet := range packets {
			packet.blockRelays.Store(false)
		}
	}()
	exchange()
	for side, packet := range packets {
		if packet.directDataSent.Load() <= sent[side] || packet.directDataRead.Load() <= read[side] {
			t.Fatalf("side %d did not carry retained application traffic over direct UDP", side)
		}
	}
}
