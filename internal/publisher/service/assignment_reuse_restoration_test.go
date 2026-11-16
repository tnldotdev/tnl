package service

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestServiceAssignmentStateOnlyUpdateRetainsSlots(t *testing.T) {
	_, bound, _, _ := privateFixture(t, "127.0.0.1:1")
	defer bound.Invalidate()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	var attempts [2]atomic.Int32
	slots, err := tunnel.NewSlots(ctx, tunnel.SlotsConfig{SingleUse: true,
		Connect: func(_ context.Context, slot uint8, _ bool) (tunnel.SlotSession, error) {
			attempts[slot].Add(1)
			return &heldSlot{stopped: make(chan struct{})}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		if err := slots.Close(); err != nil {
			t.Error("join assignment slots", err)
		}
	})
	set := func() {
		t.Helper()
		for slot := range uint8(2) {
			if err := slots.Set(slot, bound.assignmentKey(slot)); err != nil {
				t.Fatal(err)
			}
		}
	}
	wait := func() [2]tunnel.SlotSession {
		t.Helper()
		for {
			sessions, changed := slots.Snapshot()
			if sessions[0] != nil && sessions[1] != nil {
				return sessions
			}
			select {
			case <-changed:
			case <-ctx.Done():
				t.Fatal("assignment slots did not become ready", context.Cause(ctx))
			}
		}
	}
	initialKeys := [2]string{bound.assignmentKey(0), bound.assignmentKey(1)}
	state := controlv1.ServiceRunState{ServiceId: bound.prepared.Preparation.ServiceId,
		ServiceRunId: bound.prepared.Preparation.ServiceRunId, RunNumber: bound.prepared.Preparation.RunNumber,
		State: "ready", PublisherExpiresAt: time.Now().Add(time.Minute),
		PublisherConnections: append([]controlv1.ConnectionAssignment(nil), bound.connections[:]...)}
	for i := range state.PublisherConnections {
		state.PublisherConnections[i].State = controlv1.PublisherConnectionStateAssigned
	}
	if err := bound.ApplyHeartbeat(state); err != nil {
		t.Fatal(err)
	}
	set()
	original := wait()
	state.PublisherConnections[1].State = controlv1.PublisherConnectionStateReady
	if err := bound.ApplyHeartbeat(state); err != nil {
		t.Fatal(err)
	}
	set()
	current := wait()
	if current != original || bound.assignmentKey(0) != initialKeys[0] || bound.assignmentKey(1) != initialKeys[1] ||
		attempts[0].Load() != 1 || attempts[1].Load() != 1 {
		t.Fatal("assigned-to-ready state restarted an unchanged connection")
	}
	for _, session := range original {
		select {
		case <-session.(*heldSlot).stopped:
			t.Fatal("state-only update closed a retained slot")
		default:
		}
	}
	state.PublisherConnections[1].ConnectionAssignmentRevision++
	if err := bound.ApplyHeartbeat(state); !errors.Is(err, ErrPrivateStream) {
		t.Fatal("new revision reused the existing publisher connection identity", err)
	}
	set()
	if current := wait(); current != original || bound.assignmentKey(1) != initialKeys[1] {
		t.Fatal("rejected revision-only update changed the retained assignment")
	}
	replacement := state.PublisherConnections[1]
	replacement.PublisherConnectionId, err = opaqueid.New(opaqueid.PublisherConnectionPrefix)
	if err != nil {
		t.Fatal(err)
	}
	state.PublisherConnections[1] = replacement
	if err := bound.ApplyHeartbeat(state); err != nil {
		t.Fatal(err)
	}
	if bound.assignmentKey(0) != initialKeys[0] || bound.assignmentKey(1) == initialKeys[1] {
		t.Fatal("changed assignment revision retained the old slot identity")
	}
	set()
	current = wait()
	if current[0] != original[0] || current[1] == original[1] ||
		attempts[0].Load() != 1 || attempts[1].Load() != 2 {
		t.Fatal("changed revision did not replace only its own slot")
	}
	select {
	case <-original[1].(*heldSlot).stopped:
	case <-ctx.Done():
		t.Fatal("replaced assignment did not join", context.Cause(ctx))
	}
}

func TestServiceJoinedStopPhysicallyReleasesSharedUDP(t *testing.T) {
	cfg, control := lifecycleFixture(t)
	serverTLS, cfgTLS := privateTransportTLS(t)
	cfg.TransportTLS = cfgTLS
	listener, err := muxsession.ListenQUIC("127.0.0.1:0", serverTLS, muxsession.QUICConfig{})
	if err != nil {
		t.Fatal(err)
	}
	serverCtx, stopServer := context.WithCancel(t.Context())
	var servers sync.WaitGroup
	t.Cleanup(func() { stopServer(); _ = listener.Close(); servers.Wait() })
	servers.Add(2)
	for range 2 {
		go func() {
			defer servers.Done()
			session, err := listener.Accept(serverCtx)
			if err == nil {
				defer session.Close()
				select {
				case <-session.Done():
				case <-serverCtx.Done():
				}
			}
		}()
	}
	addresses := make(chan *net.UDPAddr, 2)
	draining := make(chan struct{}, 2)
	release := make(chan struct{})
	releaseDrain := sync.OnceFunc(func() { close(release) })
	cfg.Connect = func(ctx context.Context, bound *Bound, _ uint8, options ConnectOptions) (SlotSession, error) {
		connector, ok := options.QUIC.(muxsession.QUICConnector)
		if !ok || bound.peerSocket == nil || connector.Dialer != bound.peerSocket {
			return nil, errors.New("default relay connection did not borrow the run-owned UDP socket")
		}
		session, err := options.QUIC.Connect(ctx, muxsession.Endpoint{Address: listener.Addr().String(), ServerName: "relay.test"})
		if err != nil {
			return nil, err
		}
		address := *bound.peerSocket.LocalAddr().(*net.UDPAddr)
		address.IP = append(net.IP(nil), address.IP...)
		addresses <- &address
		return &lifecycleDrainingSlot{Session: session, draining: draining, release: release}, nil
	}
	ready := make(chan struct{})
	cfg.Ready = func() error { close(ready); return nil }
	ctx, cancel := context.WithCancel(t.Context())
	done, joined := make(chan error, 1), make(chan struct{})
	t.Cleanup(func() { cancel(); releaseDrain(); <-joined })
	go func() { defer close(joined); done <- Publish(ctx, cfg) }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatal("publisher stopped before its UDP ownership could be observed", err)
	case <-time.After(5 * time.Second):
		t.Fatal("publisher did not become ready")
	}
	first, second := <-addresses, <-addresses
	if first.String() != second.String() {
		t.Fatal("relay slots did not share one physical UDP socket", first, second)
	}
	assertHeld := func() {
		t.Helper()
		socket, err := net.ListenUDP("udp", first)
		if err == nil {
			_ = socket.Close()
			t.Fatal("live run released the shared UDP socket before joined stop")
		}
	}
	assertHeld()
	cancel()
	for range 2 {
		select {
		case <-draining:
		case <-time.After(3 * time.Second):
			t.Fatal("run did not enter both relay drains")
		}
	}
	assertHeld()
	select {
	case err := <-done:
		t.Fatal("publisher returned while shared-socket drain was held", err)
	default:
	}
	releaseDrain()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("joined publisher stop failed", err)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("publisher did not join its shared-socket owner")
	}
	<-joined
	socket, err := net.ListenUDP("udp", first)
	if err != nil {
		t.Fatal("joined stop did not physically release the shared UDP port", err)
	}
	if err := socket.Close(); err != nil {
		t.Fatal(err)
	}
	control.mu.Lock()
	defer control.mu.Unlock()
	if control.closes != 1 || control.bad != nil {
		t.Fatal("shared socket release lost exact run cleanup", control.closes, control.bad)
	}
}
