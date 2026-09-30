package publisher

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/tunnel"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func publisherTestAssignment(slot int, expiresAt time.Time) controlv1.ConnectionAssignment {
	return controlv1.ConnectionAssignment{
		ConnectionAssignmentRevision: 1, ConnectionSlot: slot,
		PublisherConnectionCredential: "credential", PublisherConnectionCredentialExpiresAt: expiresAt,
		PublisherConnectionId: "connection_" + string(rune('0'+slot)),
		RelayAddress:          "relay.example:443", RelayServiceId: "relay_service_" + string(rune('0'+slot)),
		State: controlv1.PublisherConnectionStateAssigned, TlsServerName: "relay.example",
	}
}

func TestSameConnectionAssignmentIgnoresLifecycleState(t *testing.T) {
	assigned := publisherTestAssignment(1, time.Now().Add(time.Minute))
	ready := assigned
	ready.State = controlv1.PublisherConnectionStateReady
	if !sameConnectionAssignment(assigned, ready) {
		t.Fatal("a lifecycle-state update replaced the same publisher connection assignment")
	}
	replaced := ready
	replaced.ConnectionAssignmentRevision++
	if sameConnectionAssignment(assigned, replaced) {
		t.Fatal("a new assignment revision reused the existing publisher connection")
	}
}

func TestConnectionLifecycleStateUpdateDoesNotRestartSlot(t *testing.T) {
	assigned := publisherTestAssignment(1, time.Now().Add(time.Minute))
	manager := &publisherConnectionManager{changed: make(chan struct{})}
	current := &managedPublisherConnection{assignment: assigned, phase: connectionAwaitingReplacement}
	manager.connections[1] = current
	other := publisherTestAssignment(0, assigned.PublisherConnectionCredentialExpiresAt)
	manager.connections[0] = &managedPublisherConnection{assignment: other}
	ready := assigned
	ready.State = controlv1.PublisherConnectionStateReady
	if err := manager.Update([]controlv1.ConnectionAssignment{other, ready}); err != nil {
		t.Fatal(err)
	}
	if manager.connections[1] != current {
		t.Fatal("a lifecycle-state update restarted the same publisher connection assignment")
	}
}

func TestPublisherConnectionUpdateValidatesBeforeMutation(t *testing.T) {
	now := time.Now()
	old := [publisherConnectionCount]*managedPublisherConnection{}
	canceled := [publisherConnectionCount]chan struct{}{make(chan struct{}), make(chan struct{})}
	for slot := range publisherConnectionCount {
		var once bool
		old[slot] = &managedPublisherConnection{assignment: publisherTestAssignment(slot, now.Add(time.Minute)), cancel: func() {
			if !once {
				once = true
				close(canceled[slot])
			}
		}}
	}
	connectError := errors.New("unexpected connection attempt")
	connector := muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
		return nil, connectError
	})
	manager := &publisherConnectionManager{
		ctx: t.Context(), config: publisherConnectionManagerConfig{
			QUICConnector: connector, TCPConnector: connector, ReconnectDelay: time.Second,
		},
		connections: old, changed: make(chan struct{}),
	}
	defer manager.Close()
	replacements := []controlv1.ConnectionAssignment{
		publisherTestAssignment(0, now.Add(time.Minute)), publisherTestAssignment(1, now.Add(-time.Second)),
	}
	replacements[0].PublisherConnectionId = "connection_new"
	replacements[0].ConnectionAssignmentRevision++
	if err := manager.Update(replacements); err == nil {
		t.Fatal("publisher connection update accepted an expired replacement")
	}
	for slot := range publisherConnectionCount {
		if manager.connections[slot] != old[slot] {
			t.Fatalf("publisher connection slot %d mutated before validation completed", slot)
		}
		select {
		case <-canceled[slot]:
			t.Fatalf("publisher connection slot %d was canceled before validation completed", slot)
		default:
		}
	}
}

func TestStaleTLSFallbackDoesNotPublishFallback(t *testing.T) {
	ctx, cancelTest := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancelTest()
	assignment := controlv1.ConnectionAssignment{
		ConnectionAssignmentRevision:           1,
		ConnectionSlot:                         0,
		PublisherConnectionCredential:          "credential",
		PublisherConnectionCredentialExpiresAt: time.Now().Add(time.Minute),
		PublisherConnectionId:                  "connection_1",
		RelayAddress:                           "relay.example:443",
		RelayServiceId:                         "relay_service_1",
		State:                                  controlv1.PublisherConnectionStateAssigned,
		TlsServerName:                          "relay.example",
	}
	transport := &certificateTestTransport{done: make(chan struct{})}
	fallbackStarted := make(chan struct{})
	releaseFallback := make(chan struct{})
	quic := muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
		return nil, errors.New("QUIC unavailable")
	})
	tcp := muxsession.ConnectorFunc(func(ctx context.Context, _ muxsession.Endpoint) (muxsession.Session, error) {
		close(fallbackStarted)
		select {
		case <-releaseFallback:
			return transport, nil
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		}
	})
	manager := &publisherConnectionManager{
		ctx: ctx, config: publisherConnectionManagerConfig{
			QUICConnector: quic, TCPConnector: tcp, ReconnectDelay: time.Second,
		},
		publishRunID: "publish_run_1", publicURLID: "public_url_1", publishRunNumber: 1,
		changed: make(chan struct{}), fallback: make(chan struct{}),
	}
	connectionCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	managed := &managedPublisherConnection{assignment: assignment, cancel: cancel}
	manager.connections[0] = managed
	manager.wg.Add(1)
	done := make(chan struct{})
	go func() {
		manager.run(connectionCtx, 0, managed)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		_ = transport.Close()
		select {
		case <-done:
			manager.Close()
		case <-time.After(5 * time.Second):
			t.Error("publisher connection did not join during cleanup")
		}
	})

	select {
	case <-fallbackStarted:
	case <-ctx.Done():
		t.Fatal("TLS/TCP fallback did not start")
	}
	replacement := &managedPublisherConnection{assignment: assignment, cancel: func() {}}
	manager.mu.Lock()
	manager.connections[0] = replacement
	manager.mu.Unlock()
	close(releaseFallback)
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("stale publisher connection did not stop")
	}

	select {
	case <-manager.Fallback():
		t.Fatal("stale TLS/TCP connection published a fallback event")
	default:
	}
	select {
	case <-transport.Done():
	default:
		t.Fatal("stale TLS/TCP session remained open")
	}
	if replacement.phase != connectionConnecting || replacement.session != nil {
		t.Fatal("stale TLS/TCP session mutated the replacement connection")
	}
}

func TestTLSFallbackIsPublishedBeforeConnectionReadiness(t *testing.T) {
	manager := &publisherConnectionManager{changed: make(chan struct{}), fallback: make(chan struct{})}
	managed := &managedPublisherConnection{}
	manager.connections[0] = managed
	if !manager.setSession(0, managed, new(tunnel.Session), tunnel.TransportTLSTCP) {
		t.Fatal("current TLS/TCP connection was rejected")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := manager.WaitReady(ctx, 1); err != nil {
		t.Fatal(err)
	}
	select {
	case <-manager.Fallback():
	default:
		t.Fatal("TLS/TCP connection became ready before publishing fallback")
	}
}

func TestQUICLossPrefersTCPOnNextAssignment(t *testing.T) {
	t.Run("publisher detects loss first", func(t *testing.T) { testQUICReplacement(t, false) })
	t.Run("control replaces assignment first", func(t *testing.T) { testQUICReplacement(t, true) })
}

func TestExpiredAssignmentWaitsForReplacement(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	route, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "route.example", Target: "http://127.0.0.1:8080",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer route.Close()
	connector := muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
		return nil, errors.New("relay unavailable")
	})
	manager, err := newPublisherConnectionManager(ctx, publisherConnectionManagerConfig{
		QUICConnector: connector, TCPConnector: connector, ReconnectDelay: 10 * time.Millisecond,
	}, route, "publish_run_1", "public_url_1", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	assignments := make([]controlv1.ConnectionAssignment, publisherConnectionCount)
	expiresAt := time.Now().Add(250 * time.Millisecond)
	for slot := range assignments {
		assignments[slot] = publisherTestAssignment(slot, expiresAt)
	}
	if err := manager.Update(assignments); err != nil {
		t.Fatal(err)
	}
	for {
		manager.mu.Lock()
		waiting := manager.connections[0].phase == connectionAwaitingReplacement &&
			manager.connections[1].phase == connectionAwaitingReplacement
		changed := manager.changed
		manager.mu.Unlock()
		if waiting {
			break
		}
		select {
		case <-changed:
		case <-ctx.Done():
			t.Fatal("expired assignments did not stop reconnecting")
		}
	}
	waitCtx, stop := context.WithTimeout(ctx, 20*time.Millisecond)
	defer stop()
	if err := manager.WaitReady(waitCtx, 1); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired assignments became ready: %v", err)
	}
}

func testQUICReplacement(t *testing.T, controlReplacedFirst bool) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	route, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "route.example", Target: "http://127.0.0.1:8080",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer route.Close()

	quicSlotZero := make(chan *certificateTestTransport, 3)
	quic := muxsession.ConnectorFunc(func(_ context.Context, endpoint muxsession.Endpoint) (muxsession.Session, error) {
		transport := &certificateTestTransport{done: make(chan struct{})}
		if endpoint.Address == "relay-0.example:443" {
			quicSlotZero <- transport
		}
		return transport, nil
	})
	tcp := muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
		return &certificateTestTransport{done: make(chan struct{})}, nil
	})
	manager, err := newPublisherConnectionManager(ctx, publisherConnectionManagerConfig{
		QUICConnector: quic, TCPConnector: tcp, FallbackDelay: time.Second, ReconnectDelay: time.Second,
	}, route, "publish_run_1", "public_url_1", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	assignments := make([]controlv1.ConnectionAssignment, publisherConnectionCount)
	for slot := range assignments {
		assignments[slot] = controlv1.ConnectionAssignment{
			ConnectionAssignmentRevision: 1, ConnectionSlot: slot,
			PublisherConnectionCredential: "credential", PublisherConnectionCredentialExpiresAt: time.Now().Add(time.Minute),
			PublisherConnectionId: "connection_" + string(rune('0'+slot)),
			RelayAddress:          "relay-" + string(rune('0'+slot)) + ".example:443",
			RelayServiceId:        "relay_service_" + string(rune('0'+slot)),
			State:                 controlv1.PublisherConnectionStateAssigned, TlsServerName: "relay.example",
		}
	}
	if err := manager.Update(assignments); err != nil {
		t.Fatal(err)
	}
	if err := manager.WaitReady(ctx, 2); err != nil {
		t.Fatal(err)
	}
	initialQUIC := <-quicSlotZero
	if !controlReplacedFirst {
		if err := initialQUIC.Close(); err != nil {
			t.Fatal(err)
		}
		for {
			manager.mu.Lock()
			failed := manager.connections[0].phase == connectionAwaitingReplacement && manager.connections[0].session == nil
			changed := manager.changed
			manager.mu.Unlock()
			if failed {
				break
			}
			select {
			case <-changed:
			case <-ctx.Done():
				t.Fatal("QUIC publisher connection did not report its mid-connection failure")
			}
		}
		select {
		case <-quicSlotZero:
			t.Fatal("failed publisher connection reconnected before a new assignment")
		default:
		}
	}
	assignments[0].ConnectionAssignmentRevision++
	assignments[0].PublisherConnectionId = "connection_replacement"
	if err := manager.Update(assignments); err != nil {
		t.Fatal(err)
	}
	if err := manager.WaitReady(ctx, 2); err != nil {
		t.Fatal(err)
	}
	select {
	case <-manager.Fallback():
	default:
		t.Fatal("TLS/TCP replacement did not report transport fallback")
	}
	select {
	case <-quicSlotZero:
		t.Fatal("replacement tried QUIC before TLS/TCP")
	default:
	}
	// A later replacement must return to the ordinary QUIC-first policy.
	assignments[0].ConnectionAssignmentRevision++
	assignments[0].PublisherConnectionId = "connection_after_recovery"
	if err := manager.Update(assignments); err != nil {
		t.Fatal(err)
	}
	if err := manager.WaitReady(ctx, 2); err != nil {
		t.Fatal(err)
	}
	select {
	case <-quicSlotZero:
	default:
		t.Fatal("publisher kept preferring TLS/TCP after recovery")
	}
}
