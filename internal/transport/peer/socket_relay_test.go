package peer_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/stun/v4"
	"github.com/tnldotdev/tnl/internal/relay"
	"github.com/tnldotdev/tnl/internal/transport/peer"
)

func TestSocketICEGathersThroughRelaySTUN(t *testing.T) {
	for _, address := range []string{"127.0.0.1:0", "[::1]:0"} {
		t.Run(address, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			packet, err := net.ListenPacket("udp", address)
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- relay.ServeSTUN(ctx, packet, nil) }()
			t.Cleanup(func() {
				cancel()
				_ = packet.Close()
				if err := <-done; err != nil {
					t.Error(err)
				}
			})
			socket, err := peer.ListenSocket(ctx, "udp", address)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = socket.Close() })
			url, err := stun.ParseURI("stun:" + packet.LocalAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			agent, err := socket.NewICE([]*stun.URI{url}, true)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = agent.GracefulClose() })
			complete := make(chan struct{})
			found := false
			if err := agent.OnCandidate(func(c ice.Candidate) {
				if c == nil {
					close(complete)
				} else if c.Type() == ice.CandidateTypeServerReflexive && c.Port() == socket.LocalAddr().(*net.UDPAddr).Port {
					found = true
				}
			}); err != nil {
				t.Fatal(err)
			}
			if err := agent.GatherCandidates(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-complete:
				if !found {
					t.Fatal("relay anti-amplification checks rejected socket discovery")
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		})
	}
}
