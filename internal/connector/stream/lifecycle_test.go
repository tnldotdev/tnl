package stream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type heldRebindControl struct {
	Control
	fixture *connectorFixture
	entered chan struct{}
	once    sync.Once
}

func (c *heldRebindControl) RebindConnectorPeerPair(ctx context.Context, service, pair string, body controlv1.ConnectorPeerPairRebindRequest) (controlv1.ConnectorPeerPairRebindState, error) {
	if body.Phase == controlv1.ConnectorPeerPairPrepare {
		c.once.Do(func() { close(c.entered) })
		<-ctx.Done()
		return controlv1.ConnectorPeerPairRebindState{}, context.Cause(ctx)
	}
	return c.Control.RebindConnectorPeerPair(ctx, service, pair, body)
}

func (c *heldRebindControl) RenewConnectorPeerPair(ctx context.Context, service string, body controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPairRenewal, error) {
	if c.fixture.denied.Load() {
		return controlv1.ConnectorPeerPairRenewal{}, &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
	}
	return c.Control.RenewConnectorPeerPair(ctx, service, body)
}

func TestConnectorAssignmentConflictRetainsApplicationWhileControlPreparesRebinding(t *testing.T) {
	entered := make(chan struct{})
	f := newConfiguredConnectorFixture(t, "tls-tcp", "", func(f *connectorFixture, config *Config) {
		f.drainRejections = true
		config.Control = &heldRebindControl{Control: f, fixture: f, entered: entered}
	})
	healthy := f.local(t)
	if _, err := healthy.Write([]byte("before")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(healthy, make([]byte, 6)); err != nil {
		t.Fatal(err)
	}
	f.activationConflict[0].Store(true)
	f.mu.Lock()
	lost := append([]muxsession.Session{}, f.sessions[0]...)
	siblings := len(f.sessions[1])
	f.mu.Unlock()
	for _, path := range lost {
		_ = path.Close()
	}
	until := time.Now().Add(3 * time.Second)
	for f.rejected[0].Load() == 0 {
		if time.Now().After(until) {
			t.Fatal("replacement did not reach the assignment fence")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("stale assignment did not request an authorized new binding")
	}
	if _, err := healthy.Write([]byte("after")); err != nil {
		t.Fatal(err)
	}
	_ = healthy.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, err := io.ReadFull(healthy, make([]byte, 5)); err == nil {
		t.Fatal("application crossed an unactivated replacement binding")
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatal("pending control ended the retained application", err)
	}
	select {
	case <-f.finished:
		t.Fatal("pending rebinding retired the session")
	default:
	}
	f.mu.Lock()
	left, right := len(f.sessions[0]), len(f.sessions[1])
	f.mu.Unlock()
	if left != 2 || right != siblings || f.opened.Load() != 1 || f.rejected[0].Load() != 1 {
		t.Fatalf("healthy stream was restarted or replayed: sessions=%d/%d sibling_before=%d opened=%d rejected=%d", left, right, siblings, f.opened.Load(), f.rejected[0].Load())
	}
	f.denied.Store(true)
	select {
	case <-f.finished:
	case <-time.After(4 * time.Second):
		t.Fatal("authority denial did not end the retained session")
	}
}

func TestMetadataReloadClassificationAndSafeFormatting(t *testing.T) {
	reload := &MetadataReloadError{ServiceID: "private-context-must-not-be-rendered", ApprovedRevision: 1, SelectedRevision: 2}
	wrapped := errors.Join(fmt.Errorf("connector stopped: %w", reload), io.ErrClosedPipe)
	if !IsMetadataReload(wrapped) || IsMetadataReload(io.ErrClosedPipe) || IsMetadataReload(nil) {
		t.Fatal("reload classification lost the lifecycle boundary")
	}
	var absent *MetadataReloadError
	if IsMetadataReload(absent) {
		t.Fatal("typed nil is not a reload signal")
	}
	var selected *MetadataReloadError
	if !errors.As(wrapped, &selected) || selected != reload {
		t.Fatal("reload metadata was not retained for its caller")
	}
	for _, value := range []any{reload, *reload} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if text := fmt.Sprintf(format, value); text != metadataReloadMessage {
				t.Fatalf("reload formatting included private context: %q", text)
			}
		}
	}
}
