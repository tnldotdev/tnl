package tunnel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func connectorPermissionFixture() tunnelv1.ConnectorPermissionUpdate {
	return tunnelv1.ConnectorPermissionUpdate{VisitorConnectionID: "vc_aaaaaaaaaaaaaaaaaaaaaa", UpdateNumber: 1, DeliveryGeneration: 7, Permission: tunnelv1.ConnectorVisitorPermission{Token: "signed-visitor-token", PublicKey: strings.Repeat("A", 43), Signature: strings.Repeat("A", 86)}}
}

func permissionControlPair(t *testing.T, client, server muxsession.Session) (*ConnectorPermissionWriter, muxsession.Stream) {
	t.Helper()
	ctx := tunnelContext(t)
	accepted := tunnelWorker(t, func() { _ = server.Close() }, func() muxsession.Stream {
		stream, err := AcceptConnectorPermissionControl(ctx, server)
		if err != nil {
			t.Error(err)
		}
		return stream
	})
	writer, err := OpenConnectorPermissionControl(ctx, ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(writer.Close)
	return writer, await(t, accepted)
}

func TestConnectorPermissionControlRequiresRoleOwnedSuspensionGate(t *testing.T) {
	if err := ServeConnectorPermissionControl(t.Context(), nil, func(tunnelv1.ConnectorPermissionUpdate, *ConnectorPermissionResponder) {
		t.Error("missing gate dispatched a permission update")
	}, func() { t.Error("invalid configuration fenced a running owner") }, nil); err == nil {
		t.Fatal("permission control accepted a missing suspension gate")
	}
}

func TestConnectorPermissionControlRejectsOldPeersBeforeApplicationBytes(t *testing.T) {
	for _, newServer := range []bool{false, true} {
		t.Run(map[bool]string{false: "old publisher", true: "old connector"}[newServer], func(t *testing.T) {
			client, server := newMemoryPair(t)
			ctx := tunnelContext(t)
			if newServer {
				accepted := tunnelWorker(t, func() { _ = server.Close() }, func() error {
					_, err := AcceptConnectorPermissionControl(ctx, server)
					return err
				})
				old, err := client.OpenStream(ctx)
				if err != nil {
					t.Fatal(err)
				}
				// an old publisher/application opening is too large and has a
				// different shape. reject its header, before reading visitor bytes.
				_, _ = old.Write([]byte{0, 0, 4, 0})
				if err := await(t, accepted); err == nil {
					t.Fatal("old connector bypassed the control handshake")
				}
			} else {
				var targetCalls atomic.Int32
				old := tunnelWorker(t, func() { _ = server.Close() }, func() error {
					stream, err := server.AcceptStream(ctx)
					if err != nil {
						return err
					}
					defer stream.Close()
					_, _, err = tunnelv1.ReadConnectorPeerVisitorOpening(stream)
					if err == nil {
						targetCalls.Add(1) // the old target boundary follows this decoder.
					}
					return err
				})
				if _, err := OpenConnectorPermissionControl(ctx, ctx, client); err == nil {
					t.Fatal("old publisher acknowledged the new protocol")
				}
				if err := await(t, old); err == nil {
					t.Fatal("new control bytes became an old application opening")
				}
				if targetCalls.Load() != 0 {
					t.Fatal("new connector reached an old publisher's target boundary")
				}
			}
		})
	}
}

func TestConnectorPermissionControlIndependentOfRawDataDeadlinesAndHalfClose(t *testing.T) {
	client, server := realTunnelPair(t, "quic")
	writer, control := permissionControlPair(t, client.transport, server.transport)
	ctx, cancel := context.WithCancel(tunnelContext(t))
	defer cancel()
	updates := make(chan tunnelv1.ConnectorPermissionUpdate, 4)
	var permissionGate ConnectorPermissionGate
	done := tunnelWorker(t, func() { cancel() }, func() error {
		return ServeConnectorPermissionControl(ctx, control, func(u tunnelv1.ConnectorPermissionUpdate, responder *ConnectorPermissionResponder) {
			updates <- u
			_ = responder.Respond(u, true)
		}, func() {}, &permissionGate)
	})
	raw, err := client.transport.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// make this stream visible without relying on an application read.
	data := bytes.Repeat([]byte{0x16}, 128<<10)
	written := tunnelWorker(t, func() { _ = raw.Reset(0) }, func() error {
		_, err := raw.Write(data)
		return err
	})
	application, err := server.transport.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = application.SetReadDeadline(time.Now().Add(-time.Second))
	u := connectorPermissionFixture()
	if err := writer.Renew(tunnelContext(t), u); err != nil {
		t.Fatal("application backpressure blocked permission", err)
	}
	if got := await(t, updates); got != u {
		t.Fatal("control proof entered application bytes")
	}
	if _, err := application.Read(make([]byte, 1)); err == nil {
		t.Fatal("control renewal reset application deadline")
	}
	_ = application.SetReadDeadline(time.Time{})
	got := make([]byte, len(data))
	if _, err := io.ReadFull(application, got); err != nil || !bytes.Equal(got, data) {
		t.Fatal("control changed raw visitor data", err)
	}
	if err := await(t, written); err != nil {
		t.Fatal(err)
	}
	if err := raw.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := application.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatal("raw half-close did not end the request", err)
	}
	u.UpdateNumber++
	if err := writer.Renew(tunnelContext(t), u); err != nil || await(t, updates) != u {
		t.Fatal("half-close ended permission control", err)
	}
	if _, err := application.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	var response [8]byte
	if _, err := io.ReadFull(raw, response[:]); err != nil || string(response[:]) != "response" {
		t.Fatal("raw half-close truncated the response", err)
	}
	cancel()
	_ = await(t, done)
}

func TestConnectorPermissionWriteGateKeepsOriginalDeadline(t *testing.T) {
	client, server := newMemoryPair(t)
	writer, control := permissionControlPair(t, client, server)
	defer control.Close()
	writer.gate <- struct{}{}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if err := writer.Renew(ctx, connectorPermissionFixture()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("contended control write escaped its fixed budget", err)
	}
	<-writer.gate
	read := tunnelWorker(t, func() { _ = control.Close() }, func() error {
		update, err := tunnelv1.ReadConnectorPermissionUpdate(control)
		if err != nil {
			return err
		}
		return tunnelv1.WriteConnectorPermissionResult(control, tunnelv1.ConnectorPermissionResult{VisitorConnectionID: update.VisitorConnectionID, UpdateNumber: update.UpdateNumber, DeliveryGeneration: update.DeliveryGeneration, Kind: tunnelv1.ConnectorPermissionAccepted})
	})
	if err := writer.Renew(tunnelContext(t), connectorPermissionFixture()); err != nil {
		t.Fatal("expired waiter poisoned a sibling control write", err)
	}
	if err := await(t, read); err != nil {
		t.Fatal(err)
	}
}

func TestConnectorPermissionControlSkipsMalformedBoundedUpdate(t *testing.T) {
	client, server := newMemoryPair(t)
	writer, control := permissionControlPair(t, client, server)
	ctx, cancel := context.WithCancel(tunnelContext(t))
	defer cancel()
	updates := make(chan tunnelv1.ConnectorPermissionUpdate, 1)
	var permissionGate ConnectorPermissionGate
	done := tunnelWorker(t, cancel, func() error {
		return ServeConnectorPermissionControl(ctx, control, func(update tunnelv1.ConnectorPermissionUpdate, responder *ConnectorPermissionResponder) {
			updates <- update
			_ = responder.Respond(update, true)
		}, func() {}, &permissionGate)
	})
	if _, err := writer.stream.Write([]byte{0, 0, 0, 1, '{'}); err != nil {
		t.Fatal(err)
	}
	want := connectorPermissionFixture()
	if err := writer.Renew(tunnelContext(t), want); err != nil || await(t, updates) != want {
		t.Fatal("malformed bounded update stopped a sibling control frame", err)
	}
	cancel()
	_ = await(t, done)
}

func TestConnectorPermissionACKCannotReleaseAnotherVisitorOrFutureRequest(t *testing.T) {
	for _, boundary := range []string{"visitor", "request", "binding"} {
		t.Run(boundary, func(t *testing.T) {
			client, server := newMemoryPair(t)
			writer, control := permissionControlPair(t, client, server)
			done := tunnelWorker(t, writer.Close, func() error { return writer.Renew(tunnelContext(t), connectorPermissionFixture()) })
			update, err := tunnelv1.ReadConnectorPermissionUpdate(control)
			if err != nil {
				t.Fatal(err)
			}
			result := tunnelv1.ConnectorPermissionResult{VisitorConnectionID: update.VisitorConnectionID, UpdateNumber: update.UpdateNumber, DeliveryGeneration: update.DeliveryGeneration, Kind: tunnelv1.ConnectorPermissionAccepted}
			if boundary == "visitor" {
				result.VisitorConnectionID = "vc_bbbbbbbbbbbbbbbbbbbbbb"
			} else if boundary == "request" {
				result.UpdateNumber++
			} else {
				result.DeliveryGeneration++
			}
			_ = tunnelv1.WriteConnectorPermissionResult(control, result)
			if err := await(t, done); !errors.Is(err, tunnelv1.ErrConnectorPermissionUpdate) {
				t.Fatal("foreign ACK released renewal or lost its protocol failure", err)
			}
			if err := writer.Renew(tunnelContext(t), connectorPermissionFixture()); err == nil {
				t.Fatal("invalid ACK left control reusable")
			}
		})
	}
}

func TestConnectorPermissionStaleGrantsNothingAndKeepsControlReusable(t *testing.T) {
	client, server := newMemoryPair(t)
	writer, control := permissionControlPair(t, client, server)
	ctx, cancel := context.WithCancel(tunnelContext(t))
	defer cancel()
	var stale atomic.Bool
	stale.Store(true)
	var permissionGate ConnectorPermissionGate
	done := tunnelWorker(t, cancel, func() error {
		return ServeConnectorPermissionControl(ctx, control, func(update tunnelv1.ConnectorPermissionUpdate, responder *ConnectorPermissionResponder) {
			if responder.suspension != &permissionGate {
				t.Error("permission replies lost the role-owned suspension gate")
			}
			if stale.Swap(false) {
				_ = responder.RespondStale(update)
			} else {
				_ = responder.Respond(update, true)
			}
		}, func() {}, &permissionGate)
	})
	update := connectorPermissionFixture()
	if err := writer.Renew(tunnelContext(t), update); !errors.Is(err, ErrConnectorPermissionStale) || writer.Err() != nil {
		t.Fatal("stale proof granted authority or ended shared control", err)
	}
	update.DeliveryGeneration++
	if err := writer.Renew(tunnelContext(t), update); err != nil {
		t.Fatal("current revision could not follow a stale proof", err)
	}
	cancel()
	_ = await(t, done)
}

func TestConnectorPermissionLateDuplicateACKCannotReleaseNextRenewal(t *testing.T) {
	client, server := newMemoryPair(t)
	writer, control := permissionControlPair(t, client, server)
	firstCtx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	first := tunnelWorker(t, writer.Close, func() error { return writer.Renew(firstCtx, connectorPermissionFixture()) })
	old, err := tunnelv1.ReadConnectorPermissionUpdate(control)
	if err != nil {
		t.Fatal(err)
	}
	if err := await(t, first); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("ACK wait escaped its original caller deadline", err)
	}
	next := tunnelWorker(t, writer.Close, func() error { return writer.Renew(tunnelContext(t), connectorPermissionFixture()) })
	current, err := tunnelv1.ReadConnectorPermissionUpdate(control)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := tunnelv1.WriteConnectorPermissionResult(control, tunnelv1.ConnectorPermissionResult{VisitorConnectionID: old.VisitorConnectionID, UpdateNumber: old.UpdateNumber, DeliveryGeneration: old.DeliveryGeneration, Kind: tunnelv1.ConnectorPermissionAccepted}); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case err := <-next:
		t.Fatal("late/duplicate ACK released the next request", err)
	case <-time.After(20 * time.Millisecond):
	}
	if err := tunnelv1.WriteConnectorPermissionResult(control, tunnelv1.ConnectorPermissionResult{VisitorConnectionID: current.VisitorConnectionID, UpdateNumber: current.UpdateNumber, DeliveryGeneration: current.DeliveryGeneration, Kind: tunnelv1.ConnectorPermissionAccepted}); err != nil {
		t.Fatal(err)
	}
	if err := await(t, next); err != nil {
		t.Fatal("current ACK did not release its exact renewal", err)
	}
}

type heldPermissionReset struct {
	muxsession.Stream
	entered, release chan struct{}
	writeEntered     chan struct{}
	once             sync.Once
}

func (s *heldPermissionReset) Write(p []byte) (int, error) {
	if s.writeEntered != nil {
		close(s.writeEntered)
	}
	return s.Stream.Write(p)
}

func (s *heldPermissionReset) Reset(code uint32) error {
	err := s.Stream.Reset(code)
	s.once.Do(func() { close(s.entered) })
	<-s.release
	return err
}

func TestConnectorPermissionCancellationJoinsPhysicalCallback(t *testing.T) {
	for _, writing := range []bool{false, true} {
		t.Run(map[bool]string{false: "reader", true: "writer"}[writing], func(t *testing.T) {
			client, server := newMemoryPair(t)
			writer, control := permissionControlPair(t, client, server)
			held := &heldPermissionReset{Stream: control, entered: make(chan struct{}), release: make(chan struct{})}
			release := sync.OnceFunc(func() { close(held.release) })
			defer release()
			ctx, cancel := context.WithCancel(tunnelContext(t))
			defer cancel()
			var done <-chan error
			if writing {
				held.Stream = writer.stream
				held.writeEntered = make(chan struct{})
				done = tunnelWorker(t, release, func() error {
					var gate ConnectorPermissionGate
					_, err := gate.write(ctx, held, make(chan struct{}, 1), func(w io.Writer) error {
						return tunnelv1.WriteConnectorPermissionUpdate(w, connectorPermissionFixture())
					})
					return err
				})
				await(t, held.writeEntered)
			} else {
				var permissionGate ConnectorPermissionGate
				done = tunnelWorker(t, release, func() error {
					return ServeConnectorPermissionControl(ctx, held, func(tunnelv1.ConnectorPermissionUpdate, *ConnectorPermissionResponder) {}, func() {}, &permissionGate)
				})
			}
			cancel()
			await(t, held.entered)
			select {
			case <-done:
				t.Fatal("control returned before its callback joined")
			default:
			}
			release()
			_ = await(t, done)
		})
	}
}
