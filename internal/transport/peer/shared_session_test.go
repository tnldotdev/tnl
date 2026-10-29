package peer

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
)

func TestSharedSessionRegistersAndJoinsWithoutClosingTransport(t *testing.T) {
	for _, tcp := range []bool{false, true} {
		t.Run(map[bool]string{false: "quic", true: "tls-tcp"}[tcp], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			serverTLS, clientTLS := peerTLS(t)
			var left, right muxsession.Session
			if tcp {
				left, right = sharedTLSPair(t, ctx, serverTLS, clientTLS)
			} else {
				left, right = sharedQUICPair(t, ctx, serverTLS, clientTLS)
			}
			a, err := NewSharedSession(ctx, left)
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			b, err := NewDispatchedSharedSession(ctx, right)
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			accepted := make(chan struct{})
			go func() {
				defer close(accepted)
				if tcp {
					stream, err := right.AcceptStream(ctx)
					if err == nil {
						b.AcceptIntroduction(ctx, stream)
					}
				}
			}()
			outgoing, incoming := sharedBinding(t, 1, RelayA)
			sender, err := a.Register(outgoing, true)
			if err != nil {
				t.Fatal(err)
			}
			receiver, err := b.Register(incoming, false)
			if err != nil {
				t.Fatal(err)
			}
			frame := signedFrame(t, outgoing)
			if err := sender.Send(ctx, frame); err != nil {
				t.Fatal(err)
			}
			if got, err := receiver.Receive(ctx); err != nil || !bytes.Equal(got, frame) {
				t.Fatal("registered transport lost its frame", err)
			}
			<-accepted
			_ = a.Close()
			_ = b.Close()
			if left.Err() != nil || right.Err() != nil {
				t.Fatal("packet cleanup closed its borrowed transport")
			}
			if _, err := a.Register(outgoing, true); err == nil {
				t.Fatal("closed owner accepted a registration")
			}
		})
	}
}
