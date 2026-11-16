package tunnel

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestConnectorCompletionCannotExtendItsCallerOrReviveControl(t *testing.T) {
	client, server := newMemoryPair(t)
	writer, _ := permissionControlPair(t, client, server)
	update := connectorPermissionFixture()
	cancelled, cancel := context.WithTimeout(t.Context(), time.Second)
	cancel()
	expired, stop := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer stop()
	for _, test := range []struct {
		ctx  context.Context
		want error
	}{
		{context.Background(), context.DeadlineExceeded},
		{cancelled, context.Canceled},
		{expired, context.DeadlineExceeded},
	} {
		if _, err := writer.Complete(test.ctx, tunnelv1.ConnectorVisitorTerminalKey{VisitorConnectionID: update.VisitorConnectionID, DeliveryGeneration: update.DeliveryGeneration}); !errors.Is(err, test.want) {
			t.Fatal("completion changed its caller's deadline or cancellation", err)
		}
	}
	if writer.Err() != nil || writer.next != 0 {
		t.Fatal("invalid completion ended control or spent a permission update number")
	}
	writer.Close()
	if _, err := writer.Complete(tunnelContext(t), tunnelv1.ConnectorVisitorTerminalKey{VisitorConnectionID: update.VisitorConnectionID, DeliveryGeneration: update.DeliveryGeneration}); !errors.Is(err, context.Canceled) {
		t.Fatal("completion revived closed control", err)
	}
}

func TestConnectorCompletionUsesExistingControlWithoutRenewingPermission(t *testing.T) {
	for _, transport := range []string{"quic", "tls-yamux"} {
		t.Run(transport, func(t *testing.T) {
			client, server := realTunnelPair(t, transport)
			writer, control := permissionControlPair(t, client.transport, server.transport)
			ctx, cancel := context.WithCancel(tunnelContext(t))
			defer cancel()
			completed := make(chan tunnelv1.ConnectorVisitorCompletion, 1)
			updates := make(chan tunnelv1.ConnectorPermissionUpdate, 1)
			var permissionGate ConnectorPermissionGate
			done := tunnelWorker(t, cancel, func() error {
				return servePermissionTestControl(ctx, control, func(update tunnelv1.ConnectorPermissionUpdate, responder *ConnectorPermissionResponder) {
					updates <- update
					_ = responder.Respond(ctx, update, true)
				}, func(receipt tunnelv1.ConnectorVisitorCompletion) { completed <- receipt }, func() {}, &permissionGate)
			})
			if err := writer.Suspend(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			update := connectorPermissionFixture()
			if _, err := writer.Complete(tunnelContext(t), tunnelv1.ConnectorVisitorTerminalKey{VisitorConnectionID: update.VisitorConnectionID, DeliveryGeneration: update.DeliveryGeneration}); err != nil {
				t.Fatal("completion waited for permission renewal", err)
			}
			receipt := await(t, completed)
			if receipt.Kind != tunnelv1.ConnectorVisitorCompleted || receipt.VisitorConnectionID != update.VisitorConnectionID ||
				receipt.DeliveryGeneration != update.DeliveryGeneration || len(updates) != 0 {
				t.Fatal("completion acquired or changed visitor permission")
			}
			if err := writer.Resume(); err != nil {
				t.Fatal(err)
			}
			if err := writer.Renew(tunnelContext(t), update); err != nil || await(t, updates) != update {
				t.Fatal("completion consumed a permission update number", err)
			}
			cancel()
			_ = await(t, done)
		})
	}
}
