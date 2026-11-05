package tunnel

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func permissionAccepted(stream muxsession.Stream, update tunnelv1.ConnectorPermissionUpdate) error {
	return tunnelv1.WriteConnectorPermissionResult(stream, tunnelv1.ConnectorPermissionResult{VisitorConnectionID: update.VisitorConnectionID, UpdateNumber: update.UpdateNumber, DeliveryGeneration: update.DeliveryGeneration, Kind: tunnelv1.ConnectorPermissionAccepted})
}

func TestConnectorPermissionSuspensionGatesQueuedFramesAndAcceptedACK(t *testing.T) {
	client, server := newMemoryPair(t)
	writer, control := permissionControlPair(t, client, server)
	if err := writer.Suspend(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	first := tunnelWorker(t, writer.Close, func() error { return writer.Renew(tunnelContext(t), connectorPermissionFixture()) })
	read := tunnelWorker(t, writer.Close, func() tunnelv1.ConnectorPermissionUpdate {
		update, err := tunnelv1.ReadConnectorPermissionUpdate(control)
		if err != nil {
			t.Error(err)
		}
		return update
	})
	select {
	case <-read:
		t.Fatal("suspended writer started a new inner exchange")
	case <-time.After(20 * time.Millisecond):
	}
	if err := writer.Resume(); err != nil {
		t.Fatal(err)
	}
	update := await(t, read)
	if err := writer.Suspend(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := permissionAccepted(control, update); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-first:
		t.Fatal("accepted ACK escaped the staged binding fence", err)
	case <-time.After(20 * time.Millisecond):
	}
	if err := writer.Resume(); err != nil {
		t.Fatal(err)
	}
	if err := await(t, first); err != nil {
		t.Fatal("activation did not release the exact ACK", err)
	}
}

func TestConnectorPermissionSuspensionPreservesEnteredFrame(t *testing.T) {
	client, server := newMemoryPair(t)
	tracked := &permissionDeadlineSession{Session: client}
	writer, control := permissionControlPair(t, tracked, server)
	for len(tracked.stream.writes) > 0 {
		<-tracked.stream.writes
	}
	done := tunnelWorker(t, writer.Close, func() error { return writer.Renew(tunnelContext(t), connectorPermissionFixture()) })
	before := await(t, tracked.stream.deadlines)
	await(t, tracked.stream.writes)
	if err := writer.Suspend(time.Now().Add(4 * time.Second)); err != nil {
		t.Fatal(err)
	}
	after := await(t, tracked.stream.deadlines)
	if !after.After(before) {
		t.Fatal("suspension did not protect the entered frame's short write deadline")
	}
	timer := time.NewTimer(time.Until(before.Add(20 * time.Millisecond)))
	defer timer.Stop()
	select {
	case err := <-done:
		t.Fatal("entered frame failed on its pre-suspension deadline", err)
	case <-timer.C:
	}
	update, err := tunnelv1.ReadConnectorPermissionUpdate(control)
	if err != nil {
		t.Fatal("entered frame was reset or replayed", err)
	}
	if err := permissionAccepted(control, update); err != nil {
		t.Fatal(err)
	}
	if err := writer.Resume(); err != nil {
		t.Fatal(err)
	}
	if err := await(t, done); err != nil {
		t.Fatal(err)
	}
	if len(tracked.stream.writes) != 1 {
		// the opening frame writes its header and body separately. exactly the
		// body's write remains after observing the entered header above.
		t.Fatal("suspension retried a partial permission frame")
	}
}

func TestConnectorPermissionSuspensionDoesNotExtendAuthority(t *testing.T) {
	writer, tracked := permissionDeadlinePair(t)
	if err := writer.Suspend(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	if err := writer.Renew(ctx, connectorPermissionFixture()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("suspended renewal escaped its original authority", err)
	}
	if len(tracked.writes) != 0 || len(tracked.deadlines) != 0 || len(writer.pending) != 0 {
		t.Fatal("expired suspended work changed framing or retained a pending request")
	}
}

func TestConnectorPermissionSuspensionPreservesEnteredACKWaitPastShortBudget(t *testing.T) {
	client, server := realTunnelPair(t, "quic")
	setup := tunnelContext(t)
	accepted := tunnelWorker(t, func() { _ = server.Close() }, func() muxsession.Stream {
		stream, err := AcceptConnectorPermissionControl(setup, server.transport)
		if err != nil {
			t.Error(err)
		}
		return stream
	})
	writer, err := OpenConnectorPermissionControl(t.Context(), setup, client.transport)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(writer.Close)
	control := await(t, accepted)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	done := tunnelWorker(t, writer.Close, func() error { return writer.Renew(ctx, connectorPermissionFixture()) })
	update, err := tunnelv1.ReadConnectorPermissionUpdate(control)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Suspend(time.Now().Add(12 * time.Second)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		t.Fatal("staged ACK wait expired on its short exchange budget", err)
	case <-time.After(10*time.Second + 20*time.Millisecond):
	}
	if err := permissionAccepted(control, update); err != nil {
		t.Fatal(err)
	}
	if err := writer.Resume(); err != nil {
		t.Fatal(err)
	}
	if err := await(t, done); err != nil {
		t.Fatal("entered ACK wait did not survive bounded suspension", err)
	}
}

func TestConnectorPermissionSuspensionRepeatedRequestsCannotExtendOrRevive(t *testing.T) {
	gate := &ConnectorPermissionGate{}
	if err := gate.Suspend(time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	first := gate.until
	if time.Until(first) > connectorPermissionSuspensionLimit {
		t.Fatal("suspension exceeded the real inner QUIC idle limit")
	}
	if err := gate.Suspend(time.Now().Add(time.Hour)); err != nil || !gate.until.Equal(first) {
		t.Fatal("repeated suspension extended the original bound", err)
	}
	if err := gate.Suspend(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if err := gate.wait(tunnelContext(t)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("suspension did not end at its fixed deadline", err)
	}
	if err := gate.Resume(); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("late activation revived an expired suspension", err)
	}
	if err := gate.Suspend(time.Now().Add(time.Hour)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("a new pause revived expired control delivery", err)
	}
}

func TestConnectorPermissionSuspensionKeepsDenialAndSessionCloseTerminal(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(map[bool]string{false: "session close", true: "denied"}[reject], func(t *testing.T) {
			client, server := newMemoryPair(t)
			writer, control := permissionControlPair(t, client, server)
			done := tunnelWorker(t, writer.Close, func() error { return writer.Renew(tunnelContext(t), connectorPermissionFixture()) })
			update, err := tunnelv1.ReadConnectorPermissionUpdate(control)
			if err != nil {
				t.Fatal(err)
			}
			if err := writer.Suspend(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if reject {
				err = tunnelv1.WriteConnectorPermissionResult(control, tunnelv1.ConnectorPermissionResult{VisitorConnectionID: update.VisitorConnectionID, UpdateNumber: update.UpdateNumber, DeliveryGeneration: update.DeliveryGeneration, Kind: tunnelv1.ConnectorPermissionRejected})
			} else {
				err = server.Close()
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := await(t, done); err == nil || reject && !errors.Is(err, ErrConnectorPermissionRejected) {
				t.Fatal("suspension hid a terminal decision", err)
			}
		})
	}
}

func TestConnectorPermissionResponderSuspensionProtectsEnteredACK(t *testing.T) {
	client, server := newMemoryPair(t)
	control, err := server.OpenStream(tunnelContext(t))
	if err != nil {
		t.Fatal(err)
	}
	remote, err := client.AcceptStream(tunnelContext(t))
	if err != nil {
		t.Fatal(err)
	}
	tracked := &permissionDeadlineStream{Stream: control, deadlines: make(chan time.Time, 8), writes: make(chan struct{}, 8)}
	gate := &ConnectorPermissionGate{}
	update := connectorPermissionFixture()
	var failures atomic.Int32
	responder := &ConnectorPermissionResponder{ctx: tunnelContext(t), stream: tracked, gate: make(chan struct{}, 1), suspension: gate, fail: func(error) { failures.Add(1) }}
	done := tunnelWorker(t, func() { _ = server.Close() }, func() error { return responder.Respond(update, true) })
	before := await(t, tracked.deadlines)
	await(t, tracked.writes)
	if err := gate.Suspend(time.Now().Add(4 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if after := await(t, tracked.deadlines); !after.After(before) {
		t.Fatal("publisher suspension did not protect the entered ACK")
	}
	timer := time.NewTimer(time.Until(before.Add(20 * time.Millisecond)))
	defer timer.Stop()
	select {
	case err := <-done:
		t.Fatal("entered ACK failed on its pre-suspension deadline", err)
	case <-timer.C:
	}
	result, err := tunnelv1.ReadConnectorPermissionResult(remote)
	if err != nil || result.VisitorConnectionID != update.VisitorConnectionID || result.UpdateNumber != update.UpdateNumber {
		t.Fatal("suspension reset or replayed the entered ACK", err)
	}
	if err := await(t, done); err != nil {
		t.Fatal(err)
	}
	if failures.Load() != 0 {
		t.Fatal("publisher treated a staged ACK as a terminal framing failure")
	}
}
