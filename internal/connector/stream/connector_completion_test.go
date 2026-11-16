package stream

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestConnectorCompletionFollowsReturnDeliveryNotRequestFIN(t *testing.T) {
	for _, protocol := range []string{"http", "tcp", "postgres", "mysql", "kubernetes"} {
		for _, transport := range []string{"quic", "tls-tcp"} {
			for _, failure := range []string{"completed", "reset", "cleanup"} {
				t.Run(protocol+"/"+transport+"/"+failure, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
					defer cancel()
					client, server := stdioTransportSessions(t, transport)
					controlReady := make(chan struct{})
					completed := make(chan tunnelv1.ConnectorVisitorCompletion, 1)
					controlDone := make(chan error, 1)
					go func() {
						control, err := tunnel.AcceptConnectorPermissionControl(ctx, server)
						if err != nil {
							controlDone <- err
							return
						}
						close(controlReady)
						var gate tunnel.ConnectorPermissionGate
						controlDone <- tunnel.ServeConnectorPermissionControl(ctx, control,
							func(tunnelv1.ConnectorPermissionUpdate, *tunnel.ConnectorPermissionResponder) {
								t.Error("completion renewed visitor authority")
							}, func(receipt tunnelv1.ConnectorVisitorCompletion) { completed <- receipt }, func() {}, &gate)
					}()
					defer func() { cancel(); <-controlDone }()
					writer, err := tunnel.OpenConnectorPermissionControl(ctx, ctx, client)
					if err != nil {
						t.Fatal(err)
					}
					defer writer.Close()
					<-controlReady
					application, remote := stdioTransportPair(t, transport)
					local, input := stdioTransportPair(t, transport)
					until, _ := ctx.Deadline()
					prepared := &PreparedConnector{ctx: ctx, conn: application, stream: streamPrepared{},
						permission: permissionUsable{}, permissionUntil: until, stop: func() bool { return true }}
					cleanup := errors.New("independent joined permission cleanup failure")
					if failure == "cleanup" {
						prepared.permissionErr = cleanup
					}
					defer prepared.Close()
					entry := tunnelv1.ConnectorPeerVisitorEntry{VisitorConnectionID: "vc_aaaaaaaaaaaaaaaaaaaaaa", DeliveryGeneration: 7}
					use := &connectorUse{entry: entry, prepared: prepared, until: until}
					p := &connectorConnection{ctx: ctx, permissions: writer, until: until, preparedUntil: until,
						run: Run{ValidUntil: until}, permission: controlv1.VisitorTokenResponse{ExpiresAt: until},
						config: Config{Protocol: protocol, MaxConnections: 1}, warm: use,
						active: make(map[*connectorUse]struct{}), refill: make(chan struct{}, 1)}
					done := make(chan struct{})
					var copyErr error
					go func() { defer close(done); copyErr = p.Forward(ctx, local) }()
					defer func() { cancel(); _ = input.Close(); _ = remote.Close(); <-done }()
					if _, err := io.WriteString(input, "request"); err != nil {
						t.Fatal(err)
					}
					if err := input.CloseWrite(); err != nil {
						t.Fatal(err)
					}
					request, err := io.ReadAll(remote)
					if err != nil || string(request) != "request" {
						t.Fatal("request FIN did not reach the publisher", string(request), err)
					}
					select {
					case receipt := <-completed:
						t.Fatal("request FIN acknowledged an unfinished response", receipt)
					case <-done:
						t.Fatal("request FIN ended return delivery", copyErr)
					default:
					}
					if failure == "reset" {
						if err := remote.Reset(1); err != nil {
							t.Fatal(err)
						}
					} else {
						if _, err := io.WriteString(remote, "final response"); err != nil {
							t.Fatal(err)
						}
						data := make([]byte, len("final response"))
						if _, err := io.ReadFull(input, data); err != nil || string(data) != "final response" {
							t.Fatal("response did not reach the local client", string(data), err)
						}
						if err := remote.CloseWrite(); err != nil {
							t.Fatal(err)
						}
					}
					select {
					case <-done:
						if (copyErr != nil) != (failure != "completed") || failure == "cleanup" && !errors.Is(copyErr, cleanup) {
							t.Fatal("completion hid a copy failure or failed clean delivery", copyErr)
						}
					case <-ctx.Done():
						t.Fatal("raw forwarding did not join", ctx.Err())
					}
					if failure != "completed" {
						select {
						case receipt := <-completed:
							t.Fatal("failed return delivery sent a completion receipt", receipt)
						default:
						}
					} else {
						select {
						case receipt := <-completed:
							if receipt.Kind != tunnelv1.ConnectorVisitorCompleted || receipt.VisitorConnectionID != entry.VisitorConnectionID ||
								receipt.DeliveryGeneration != entry.DeliveryGeneration {
								t.Fatal("completion lost its original visitor/delivery identity", receipt)
							}
						case <-ctx.Done():
							t.Fatal("joined return delivery did not report completion", ctx.Err())
						}
					}
					if err := writer.Err(); err != nil && !errors.Is(err, context.Canceled) {
						t.Fatal("one visitor's completion ended shared permission control", err)
					}
				})
			}
		}
	}
}
