package stream

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/testutil/connectorfixture"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestConnectorCompletionFollowsReturnDeliveryNotRequestFIN(t *testing.T) {
	for _, protocol := range []string{"http", "tcp", "postgres", "mysql", "kubernetes"} {
		for _, transport := range []string{"quic", "tls-tcp"} {
			for _, failure := range []string{"completed", "reset", "cleanup", "remote-cleanup"} {
				t.Run(protocol+"/"+transport+"/"+failure, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
					defer cancel()
					serving, stopServing := context.WithCancelCause(ctx)
					defer stopServing(nil)
					client, server := stdioTransportSessions(t, transport)
					controlReady := make(chan struct{})
					completed := make(chan tunnelv1.ConnectorVisitorCompletion, 1)
					controlDone := make(chan error, 1)
					entry := tunnelv1.ConnectorPeerVisitorEntry{VisitorConnectionID: "vc_aaaaaaaaaaaaaaaaaaaaaa", DeliveryGeneration: 7}
					until, _ := ctx.Deadline()
					var fixtureMu sync.Mutex
					var visitor *connectorfixture.JoinedVisitor
					terminalEntered := make(chan struct{})
					enter := sync.OnceFunc(func() { close(terminalEntered) })
					controlOwner := connectorfixture.NewJoinedControl(ctx, connectorTestControlScope(), func(key tunnelv1.ConnectorVisitorTerminalKey) *connectorfixture.JoinedVisitor {
						fixtureMu.Lock()
						defer fixtureMu.Unlock()
						return visitor
					})
					controlOwner.Permission = func(tunnelv1.ConnectorPermissionUpdate, *tunnel.ConnectorPermissionResponder) {
						t.Error("completion renewed visitor authority")
					}
					controlOwner.Entered = func(request tunnelv1.ConnectorVisitorTerminalRequest) {
						if request.Purpose == tunnelv1.ConnectorTerminalCompletion {
							completed <- tunnelv1.ConnectorVisitorCompletion{Kind: tunnelv1.ConnectorVisitorCompleted, VisitorConnectionID: request.Key.VisitorConnectionID,
								DeliveryGeneration: request.Key.DeliveryGeneration, TerminalNumber: request.TerminalNumber}
						}
						if failure == "remote-cleanup" {
							stopServing(context.Canceled)
						}
						enter()
					}
					go func() {
						control, err := tunnel.AcceptConnectorPermissionControl(ctx, server)
						if err != nil {
							controlDone <- err
							return
						}
						close(controlReady)
						var gate tunnel.ConnectorPermissionGate
						controlDone <- controlOwner.Serve(control, &gate)
					}()
					defer func() { cancel(); <-controlDone }()
					writer, err := tunnel.OpenConnectorPermissionControl(ctx, ctx, client, connectorTestControlScope())
					if err != nil {
						t.Fatal(err)
					}
					defer writer.Close()
					<-controlReady
					application, remote := stdioTransportPair(t, transport)
					local, input := stdioTransportPair(t, transport)
					fixtureMu.Lock()
					visitor = connectorfixture.NewJoinedVisitor(ctx, entry, until, remote.Close)
					fixtureMu.Unlock()
					producerDone := make(chan struct{})
					finishProducer := sync.OnceFunc(func() { close(producerDone) })
					defer finishProducer()
					remoteJoined := make(chan struct{})
					go func() {
						defer close(remoteJoined)
						select {
						case <-terminalEntered:
						case <-ctx.Done():
						}
						select {
						case <-producerDone:
						case <-ctx.Done():
						}
						if failure == "remote-cleanup" {
							fault := &failingStdioClose{Conn: remote, err: errors.New("independent remote physical close failure")}
							visitor.Join(fault.Close())
						} else {
							visitor.Join(remote.Close())
						}
					}()
					defer func() { cancel(); finishProducer(); <-remoteJoined }()
					prepared := &PreparedConnector{ctx: serving, conn: application, stream: streamPrepared{},
						permission: permissionUsable{}, permissionUntil: until, stop: func() bool { return true }}
					cleanup := errors.New("independent joined permission cleanup failure")
					if failure == "cleanup" {
						prepared.permissionErr = cleanup
					}
					defer prepared.Close()
					use := &connectorUse{entry: entry, prepared: prepared, until: until, terminalKey: connectorTerminalKey(entry), admitted: true}
					p := &connectorConnection{ctx: serving, cancel: stopServing, packetCtx: ctx, cleanup: newConnectorCleanup(ctx, nil), permissions: writer, until: until, preparedUntil: until,
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
					finishProducer()
					select {
					case <-done:
						if (copyErr != nil) != (failure != "completed") || failure == "cleanup" && !errors.Is(copyErr, cleanup) {
							t.Fatal("completion hid a copy failure or failed clean delivery", copyErr)
						}
					case <-ctx.Done():
						t.Fatal("raw forwarding did not join", ctx.Err())
					}
					if failure == "remote-cleanup" {
						if !errors.Is(copyErr, tunnel.ErrConnectorTerminalFailed) {
							t.Fatal("remote joined failure was hidden from the visitor", copyErr)
						}
						p.mu.Lock()
						ownerErr := p.useErr
						p.mu.Unlock()
						if ownerErr != nil {
							t.Fatal("observed visitor result was charged to owner cleanup", ownerErr)
						}
					}
					if failure != "completed" && failure != "remote-cleanup" {
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
