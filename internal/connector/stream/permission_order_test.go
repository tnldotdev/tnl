package stream

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

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
	for _, mode := range []string{"eof", "reset", "truncated", "oversize"} {
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
			default:
				_ = control.CloseWrite()
			}
			select {
			case <-p.ctx.Done():
			case <-time.After(time.Second):
				t.Fatal("terminal ACK channel left its owner reusable")
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
