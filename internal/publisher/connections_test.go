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

func TestSameConnectionAssignmentIgnoresLifecycleState(t *testing.T) {
	assigned := controlv1.ConnectionAssignment{
		ConnectionAssignmentRevision:           1,
		ConnectionSlot:                         1,
		PublisherConnectionCredential:          "credential",
		PublisherConnectionCredentialExpiresAt: time.Now().Add(time.Minute),
		PublisherConnectionId:                  "connection_1",
		RelayAddress:                           "relay.example:443",
		RelayServiceId:                         "relay_service_1",
		State:                                  controlv1.PublisherConnectionStateAssigned,
		TlsServerName:                          "relay.example",
	}
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

func TestPublisherConnectionUpdateValidatesBeforeMutation(t *testing.T) {
	assignment := func(slot int, expiresAt time.Time) controlv1.ConnectionAssignment {
		return controlv1.ConnectionAssignment{
			ConnectionAssignmentRevision: 1, ConnectionSlot: slot,
			PublisherConnectionCredential: "credential", PublisherConnectionCredentialExpiresAt: expiresAt,
			PublisherConnectionId: "connection_" + string(rune('0'+slot)),
			RelayAddress:          "relay.example:443", RelayServiceId: "relay_service_" + string(rune('0'+slot)),
			State: controlv1.PublisherConnectionStateAssigned, TlsServerName: "relay.example",
		}
	}
	now := time.Now()
	old := [publisherConnectionCount]*managedPublisherConnection{}
	canceled := [publisherConnectionCount]chan struct{}{make(chan struct{}), make(chan struct{})}
	for slot := range publisherConnectionCount {
		var once bool
		old[slot] = &managedPublisherConnection{assignment: assignment(slot, now.Add(time.Minute)), cancel: func() {
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
		assignment(0, now.Add(time.Minute)), assignment(1, now.Add(-time.Second)),
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
		routeSessionID: "route_session_1", routeID: "route_1", routeVersion: 1,
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
	if replacement.ready || replacement.session != nil {
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
