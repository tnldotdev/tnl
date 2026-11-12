package stream

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type preparedRenewalFunc func(context.Context, tunnelv1.ConnectorPermissionUpdate) error

func (f preparedRenewalFunc) Renew(ctx context.Context, update tunnelv1.ConnectorPermissionUpdate) error {
	return f(ctx, update)
}

func TestPreparedConnectorCloseJoinsRenewalDecision(t *testing.T) {
	denied := tunnel.ErrConnectorPermissionRejected
	for _, test := range []struct {
		name    string
		failure error
		joined  bool
	}{
		{name: "owned stop"},
		{name: "joined owned stop", joined: true},
		{name: "denial", failure: denied},
		{name: "denial joined with stop", failure: denied, joined: true},
		{name: "stale decision joined with denial", failure: errors.Join(tunnel.ErrConnectorPermissionStale, denied)},
		{name: "stale decision joined with denial and stop", failure: errors.Join(tunnel.ErrConnectorPermissionStale, denied), joined: true},
		{name: "stale decision joined with independent cancellation", failure: errors.Join(tunnel.ErrConnectorPermissionStale, context.Canceled)},
		{name: "independent cancellation", failure: context.Canceled},
		{name: "cancellation joined with stop", failure: context.Canceled, joined: true},
		{name: "deadline", failure: context.DeadlineExceeded},
		{name: "deadline joined with stop", failure: context.DeadlineExceeded, joined: true},
		{name: "another stream stopped", failure: &preparedPermissionStop{owner: &PreparedConnector{}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			local, remote := net.Pipe()
			defer remote.Close()
			p := &PreparedConnector{ctx: t.Context(), conn: local, stream: streamPrepared{}, permission: permissionUsable{}, permissionUntil: time.Now().Add(time.Minute), stop: func() bool { return true }}
			entered, stopped, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })
			defer func() { unblock(); _ = p.Close() }()
			writer := preparedRenewalFunc(func(ctx context.Context, _ tunnelv1.ConnectorPermissionUpdate) error {
				close(entered)
				<-ctx.Done()
				close(stopped)
				<-release
				if test.joined {
					return errors.Join(context.Cause(ctx), test.failure)
				}
				if test.failure == nil {
					return context.Cause(ctx)
				}
				return test.failure
			})
			if err := p.queuePermission(preparedPermissionRenewal{writer: writer, until: time.Now().Add(time.Minute)}); err != nil {
				t.Fatal(err)
			}
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("renewal did not start")
			}
			done := make(chan error, 1)
			go func() { done <- p.Close() }()
			select {
			case <-stopped:
			case <-time.After(time.Second):
				t.Fatal("close did not stop renewal")
			}
			select {
			case err := <-done:
				t.Fatal("close returned before the renewal result", err)
			default:
			}
			unblock()
			select {
			case err := <-done:
				if test.failure == nil && err != nil || test.failure != nil && !errors.Is(err, test.failure) {
					t.Fatal("close misclassified the joined renewal result", err)
				}
			case <-time.After(time.Second):
				t.Fatal("close did not join renewal")
			}
		})
	}
}

func TestPreparedConnectorEOFCancelsPendingPermission(t *testing.T) {
	for _, transport := range []string{"quic", "tls-tcp"} {
		t.Run(transport, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			client, server := stdioTransportSessions(t, transport)
			accepted := make(chan muxsession.Stream, 1)
			failed := make(chan error, 1)
			go func() {
				control, err := tunnel.AcceptConnectorPermissionControl(ctx, server)
				if err != nil {
					failed <- err
					return
				}
				accepted <- control
			}()
			writer, err := tunnel.OpenConnectorPermissionControl(ctx, ctx, client)
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Close()
			var control muxsession.Stream
			select {
			case control = <-accepted:
			case err := <-failed:
				t.Fatal(err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			defer control.Close()
			if err := control.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			application, remote := stdioTransportPair(t, transport)
			local, input := net.Pipe()
			defer local.Close()
			defer input.Close()
			p := &PreparedConnector{ctx: ctx, conn: application, stream: streamPrepared{}, permission: permissionUsable{}, permissionUntil: time.Now().Add(time.Minute), stop: func() bool { return true }}
			defer p.Close()
			done := make(chan error, 1)
			go func() { done <- p.Forward(ctx, local) }()
			// finish the request half before starting renewal, then keep the
			// response half open until the publisher has received the proof.
			_ = input.Close()
			_ = remote.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := remote.Read(make([]byte, 1)); err != io.EOF {
				t.Fatal("request did not half-close", err)
			}
			update := tunnelv1.ConnectorPermissionUpdate{VisitorConnectionID: "vc_aaaaaaaaaaaaaaaaaaaaaa", DeliveryGeneration: 1, Permission: tunnelv1.ConnectorVisitorPermission{Token: "signed-visitor-token", PublicKey: strings.Repeat("A", 43), Signature: strings.Repeat("A", 86)}}
			if err := p.queuePermission(preparedPermissionRenewal{writer: writer, update: update, until: time.Now().Add(time.Minute)}); err != nil {
				t.Fatal(err)
			}
			if _, err := tunnelv1.ReadConnectorPermissionUpdate(control); err != nil {
				t.Fatal(err)
			}
			// no ACK is sent: clean response EOF must join the pending renewal.
			if err := remote.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal("clean copy failed", err)
				}
			case <-ctx.Done():
				t.Fatal("clean copy did not join", ctx.Err())
			}
			if err := p.Close(); err != nil {
				t.Fatal("clean EOF retained its own permission shutdown", err)
			}
			if err := writer.Err(); err != nil {
				t.Fatal("one application's EOF ended permission control", err)
			}
			if err := context.Cause(ctx); err != nil {
				t.Fatal("EOF required caller cancellation", err)
			}
		})
	}
}
