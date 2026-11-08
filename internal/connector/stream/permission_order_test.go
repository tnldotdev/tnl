package stream

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestConnectorPermissionAcknowledgementFencesFollowingApplicationBytes(t *testing.T) {
	for _, accepted := range []bool{false, true} {
		t.Run(map[bool]string{false: "rejected", true: "accepted"}[accepted], func(t *testing.T) {
			f := newConnectorFixture(t, "quic")
			setup, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			p, err := prepareConnectorConnection(t.Context(), setup, f.config, f.device)
			cancel()
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			use := p.warm
			application := &preparedConnectorUse{owner: use.prepared, ctx: p.ctx}
			if _, err := application.Write([]byte("before")); err != nil {
				t.Fatal(err)
			}
			var before [6]byte
			if _, err := io.ReadFull(application, before[:]); err != nil || string(before[:]) != "before" {
				t.Fatal(err)
			}
			count := f.application.Load()
			entered, release := make(chan struct{}), make(chan struct{})
			resume := sync.OnceFunc(func() { close(release) })
			defer resume()
			f.mu.Lock()
			f.peers[p.pair.PairId].permissionReply = func(update tunnelv1.ConnectorPermissionUpdate, responder *tunnel.ConnectorPermissionResponder) {
				close(entered)
				select {
				case <-release:
					_ = responder.Respond(update, accepted)
				case <-p.ctx.Done():
				}
			}
			f.mu.Unlock()
			p.renewActive([]*connectorUse{use}, p.permission, time.Now().Add(time.Minute))
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("renewal did not reach actual control stream")
			}
			type result struct {
				n   int
				err error
			}
			following := make(chan result, 1)
			go func() { n, err := application.Write([]byte("following")); following <- result{n, err} }()
			select {
			case result := <-following:
				t.Fatal("following write crossed an unacknowledged renewal", result.n, result.err)
			case <-time.After(20 * time.Millisecond):
			}
			if f.application.Load() != count {
				t.Fatal("unacknowledged renewal forwarded following bytes")
			}
			resume()
			select {
			case result := <-following:
				if accepted {
					if result.n != len("following") || result.err != nil {
						t.Fatal("accepted renewal did not release its exact write", result.n, result.err)
					}
					var data [9]byte
					if _, err := io.ReadFull(application, data[:]); err != nil || string(data[:]) != "following" {
						t.Fatal("following raw transcript changed", err)
					}
				} else if result.n != 0 || result.err == nil || f.application.Load() != count {
					t.Fatal("rejected renewal admitted following application bytes", result.n, result.err, f.application.Load())
				}
			case <-time.After(time.Second):
				t.Fatal("permission ACK did not release or reject its waiting writer")
			}
		})
	}
}

func TestConnectorTerminalPermissionControlRetiresOwnerBeforeAnotherArrival(t *testing.T) {
	for _, mode := range []string{"eof", "reset", "truncated", "oversize", "transport closed"} {
		t.Run(mode, func(t *testing.T) {
			f := newConnectorFixture(t, "quic")
			setup, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			p, err := prepareConnectorConnection(t.Context(), setup, f.config, f.device)
			cancel()
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			f.mu.Lock()
			control := f.peers[p.pair.PairId].control
			f.mu.Unlock()
			switch mode {
			case "reset":
				_ = control.Reset(0)
			case "truncated":
				_, _ = control.Write([]byte{0, 0, 0, 16, '{'})
				_ = control.CloseWrite()
			case "oversize":
				_, _ = control.Write(binary.BigEndian.AppendUint32(nil, 257))
			case "transport closed":
				_ = p.transport.Close()
			default:
				_ = control.CloseWrite()
			}
			select {
			case <-p.ctx.Done():
			case <-time.After(time.Second):
				t.Fatal("terminal ACK channel left its owner reusable")
			}
			cause := context.Cause(p.ctx)
			if !errors.Is(cause, ErrServiceConnection) {
				t.Fatal("terminal control owner lost its obsolete connection classification", cause)
			}
			if mode == "eof" && !errors.Is(cause, io.EOF) {
				t.Fatal("terminal control owner discarded the underlying control cause", cause)
			}
			local, app := net.Pipe()
			defer app.Close()
			defer local.Close()
			if err := p.Forward(t.Context(), local); err == nil {
				t.Fatal("arrival entered an owner with a terminal control channel")
			}
			joined := make(chan struct{})
			go func() { p.Close(); close(joined) }()
			select {
			case <-joined:
			case <-time.After(time.Second):
				t.Fatal("terminal control owner did not join its physical children")
			}
		})
	}
}

func TestConnectorTerminalPermissionControlPreservesEarlierAuthorizationCause(t *testing.T) {
	f := newConnectorFixture(t, "quic")
	setup, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	p, err := prepareConnectorConnection(t.Context(), setup, f.config, f.device)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	denied := failure.Wrap("renew connector permission", failure.ServerDenied, io.ErrClosedPipe)
	p.cancel(denied)
	_ = p.transport.Close()
	p.Close()
	if cause := context.Cause(p.ctx); cause != denied || !errors.Is(cause, io.ErrClosedPipe) {
		t.Fatal("terminal control cleanup replaced the first authorization cause", cause)
	}
}

func TestConnectorTerminalPermissionControlWatchWinsRetirement(t *testing.T) {
	for _, transport := range []string{"quic", "tls-tcp"} {
		for _, mode := range []string{"eof", "session closed"} {
			t.Run(transport+"/"+mode, func(t *testing.T) {
				client, server := stdioTransportSessions(t, transport)
				ctx, cancel := context.WithCancelCause(t.Context())
				defer cancel(nil)
				setup, stop := context.WithTimeout(ctx, 3*time.Second)
				defer stop()
				accepted := make(chan muxsession.Stream, 1)
				failed := make(chan error, 1)
				var workers sync.WaitGroup
				workers.Go(func() {
					control, err := tunnel.AcceptConnectorPermissionControl(setup, server)
					if err != nil {
						failed <- err
						return
					}
					accepted <- control
				})
				defer func() { stop(); workers.Wait() }()
				writer, err := tunnel.OpenConnectorPermissionControl(ctx, setup, client)
				if err != nil {
					t.Fatal(err)
				}
				defer writer.Close()
				var control muxsession.Stream
				select {
				case control = <-accepted:
				case err := <-failed:
					t.Fatal(err)
				case <-setup.Done():
					t.Fatal(context.Cause(setup))
				}
				defer control.Close()
				until := time.Now().Add(time.Minute)
				p := &connectorConnection{ctx: ctx, cancel: cancel, session: client, permissions: writer, until: until, preparedUntil: until, changed: make(chan struct{})}
				p.run.ValidUntil, p.permission.ExpiresAt = until, until
				defer p.Close()
				if mode == "eof" {
					err = control.CloseWrite()
				} else {
					err = client.Close()
				}
				if err != nil {
					t.Fatal(err)
				}
				select {
				case <-writer.Done():
				case <-setup.Done():
					t.Fatal("permission reader did not observe terminal control", context.Cause(setup))
				}
				underlying := writer.Err()
				if underlying == nil || errors.Is(underlying, ErrServiceConnection) || context.Cause(ctx) != nil {
					t.Fatal("fixture did not isolate an unclassified permission failure", underlying, context.Cause(ctx))
				}
				// the permission notification worker has not run. force watch to
				// observe the terminal reader first, with every authority still current.
				watched := make(chan struct{})
				p.workers.Go(func() { defer close(watched); p.watch() })
				select {
				case <-watched:
				case <-time.After(time.Second):
					t.Fatal("watch did not retire terminal permission control")
				}
				cause := context.Cause(ctx)
				if !errors.Is(cause, ErrServiceConnection) || !errors.Is(cause, underlying) {
					t.Fatal("watch lost terminal control classification or its underlying cause", cause)
				}
				if mode == "eof" && !errors.Is(cause, io.EOF) {
					t.Fatal("watch discarded control EOF", cause)
				}
			})
		}
	}
}
