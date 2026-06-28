package publisher

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestSamePublisherConnectionPlanIgnoresLifecycleState(t *testing.T) {
	assigned := controlv1.PublisherConnectionPlan{
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
	if !samePublisherConnectionPlan(assigned, ready) {
		t.Fatal("a lifecycle-state update replaced the same publisher connection assignment")
	}
	replaced := ready
	replaced.ConnectionAssignmentRevision++
	if samePublisherConnectionPlan(assigned, replaced) {
		t.Fatal("a new assignment revision reused the existing publisher connection")
	}
}

func TestPublisherConnectionUpdateValidatesBeforeMutation(t *testing.T) {
	plan := func(slot int, expiresAt time.Time) controlv1.PublisherConnectionPlan {
		return controlv1.PublisherConnectionPlan{
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
		old[slot] = &managedPublisherConnection{plan: plan(slot, now.Add(time.Minute)), cancel: func() {
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
	replacements := []controlv1.PublisherConnectionPlan{
		plan(0, now.Add(time.Minute)), plan(1, now.Add(-time.Second)),
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
