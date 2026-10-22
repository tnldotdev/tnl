package muxsession

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func muxAwait[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatal("transport worker did not finish")
		var zero T
		return zero
	}
}

func streamPair(t *testing.T, client, server Session) (Stream, Stream) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	a, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	_ = a.SetDeadline(time.Now().Add(5 * time.Second))
	// QUIC announces a stream to the peer only when it sends bytes.
	if _, err := a.Write([]byte("!")); err != nil {
		t.Fatal(err)
	}
	b, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	_ = b.SetDeadline(time.Now().Add(5 * time.Second))
	var marker [1]byte
	if _, err := io.ReadFull(b, marker[:]); err != nil || marker[0] != '!' {
		t.Fatalf("stream marker: %q, %v", marker, err)
	}
	return a, b
}

func TestSessionContract(t *testing.T) {
	for _, test := range []struct {
		name string
		pair pairFactory
	}{{"quic", newQUICPair}, {"tls_yamux", newTLSYamuxPair}} {
		t.Run(test.name, func(t *testing.T) {
			t.Run("accepted peer identity", func(t *testing.T) {
				client, server := test.pair(t)
				local, ok := client.(AcceptedPeer)
				if !ok {
					t.Fatal("network client has no accepted-peer capability")
				}
				remote, ok := server.(AcceptedPeer)
				if !ok {
					t.Fatal("network server has no accepted-peer capability")
				}
				for _, addresses := range [][2]net.Addr{{local.LocalAddr(), remote.RemoteAddr()}, {remote.LocalAddr(), local.RemoteAddr()}} {
					bound, boundErr := netip.ParseAddrPort(addresses[0].String())
					observed, observedErr := netip.ParseAddrPort(addresses[1].String())
					// a QUIC socket may bind a wildcard local address; the peer
					// still observes its concrete loopback address and exact port.
					if boundErr != nil || observedErr != nil || bound.Port() != observed.Port() ||
						!bound.Addr().IsUnspecified() && bound.Addr().Unmap() != observed.Addr().Unmap() || observed.Addr().IsUnspecified() {
						t.Fatalf("accepted peer socket mismatch: %v / %v", addresses[0], addresses[1])
					}
				}
				state := remote.TLSConnectionState()
				if !state.HandshakeComplete || state.NegotiatedProtocol != ALPN || state.ServerName != "relay.test" {
					t.Fatalf("accepted peer lost TLS identity: %+v", state)
				}
			})
			t.Run("full duplex and half close", func(t *testing.T) {
				client, server := test.pair(t)
				a, b := streamPair(t, client, server)
				// larger than either stream's window: both readers and both writers
				// must make progress concurrently, before either half closes.
				left, right := bytes.Repeat([]byte("left"), 300000), bytes.Repeat([]byte("right"), 240000)
				gate := make(chan struct{})
				results := make(chan error, 4)
				joined := make(chan struct{})
				t.Cleanup(func() { _ = a.Close(); _ = b.Close(); muxAwait(t, joined) })
				var workers sync.WaitGroup
				for _, direction := range []struct {
					stream     Stream
					send, want []byte
				}{{a, left, right}, {b, right, left}} {
					workers.Go(func() {
						<-gate
						_, err := direction.stream.Write(direction.send)
						if err == nil {
							err = direction.stream.CloseWrite()
						}
						results <- err
					})
					workers.Go(func() {
						<-gate
						got, err := io.ReadAll(direction.stream)
						if err == nil && !bytes.Equal(got, direction.want) {
							err = fmt.Errorf("received %d bytes, want %d", len(got), len(direction.want))
						}
						results <- err
					})
				}
				go func() { workers.Wait(); close(joined) }()
				close(gate)
				for range 4 {
					if err := muxAwait(t, results); err != nil {
						t.Error(err)
					}
				}
				assertRoundTrip(t, client, server, "after half closes")
			})
			t.Run("concurrent streams", func(t *testing.T) { client, server := test.pair(t); assertConcurrentStreams(t, client, server) })
			t.Run("accept cancellation", func(t *testing.T) {
				_, server := test.pair(t)
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				if _, err := server.AcceptStream(ctx); !errors.Is(err, context.Canceled) {
					t.Fatalf("AcceptStream: %v", err)
				}
			})
			t.Run("close unblocks accept", func(t *testing.T) {
				_, server := test.pair(t)
				done := make(chan struct{})
				result := make(chan error, 1)
				t.Cleanup(func() { _ = server.Close(); muxAwait(t, done) })
				go func() { defer close(done); _, err := server.AcceptStream(context.Background()); result <- err }()
				_ = server.Close()
				if err := muxAwait(t, result); !errors.Is(err, ErrClosed) {
					t.Fatalf("AcceptStream: %v", err)
				}
			})
			t.Run("reset unblocks peer and isolates stream", func(t *testing.T) {
				client, server := test.pair(t)
				a, b := streamPair(t, client, server)
				started, done := make(chan struct{}), make(chan struct{})
				result := make(chan error, 1)
				t.Cleanup(func() { _ = a.Close(); _ = b.Close(); muxAwait(t, done) })
				go func() { defer close(done); close(started); _, err := b.Read(make([]byte, 1)); result <- err }()
				muxAwait(t, started)
				if err := a.Reset(7); err != nil {
					t.Fatal(err)
				}
				err := muxAwait(t, result)
				var timeout net.Error
				if err == nil || errors.As(err, &timeout) && timeout.Timeout() {
					t.Fatalf("peer did not observe reset: %v", err)
				}
				assertRoundTrip(t, client, server, "still alive")
			})
		})
	}
}
