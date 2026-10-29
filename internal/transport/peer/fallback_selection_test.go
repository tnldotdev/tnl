package peer

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestPeerSpeculativeRelayFallbackPreservesHealthyPreference(t *testing.T) {
	for _, test := range []struct {
		name          string
		alive, failed [pathCount]bool
		want          int
	}{
		{"healthy direct", [3]bool{true, true, true}, [3]bool{}, Direct},
		{"healthy first relay", [3]bool{true, true, false}, [3]bool{}, RelayA},
		{"healthy second before speculative first", [3]bool{false, true, false}, [3]bool{}, RelayB},
		{"all unhealthy", [3]bool{}, [3]bool{}, RelayA},
		{"first relay failed", [3]bool{}, [3]bool{true, false, false}, RelayB},
		{"failed direct not healthy", [3]bool{false, true, true}, [3]bool{false, false, true}, RelayB},
		{"failed first not healthy", [3]bool{true, true, false}, [3]bool{true, false, false}, RelayB},
	} {
		t.Run(test.name, func(t *testing.T) {
			endpoint := &Endpoint{active: Direct}
			type evidence struct {
				alive, failed bool
				generation    uint64
				ack           time.Time
				challenge     [16]byte
			}
			var before [pathCount]evidence
			for index := range pathCount {
				p := &path{alive: test.alive[index], failed: test.failed[index], generation: uint64(index + 7), ack: time.Now(), challenge: [16]byte{byte(index + 1)}}
				endpoint.paths[index] = p
				before[index] = evidence{p.alive, p.failed, p.generation, p.ack, p.challenge}
			}
			endpoint.chooseLocked()
			if endpoint.active != test.want {
				t.Fatalf("selected path=%d, want=%d", endpoint.active, test.want)
			}
			for index, p := range endpoint.paths {
				if got := (evidence{p.alive, p.failed, p.generation, p.ack, p.challenge}); got != before[index] {
					t.Fatal("selection changed health, generation, or probe evidence")
				}
			}
		})
	}
}

func fallbackQueueEndpoint(ctx context.Context, cancel context.CancelFunc) *Endpoint {
	endpoint := &Endpoint{ctx: ctx, cancel: cancel, active: Direct, config: Config{Key: [32]byte{1}}}
	for index := range pathCount {
		endpoint.paths[index] = &path{queue: make(chan queuedFrame, packetQueue)}
	}
	return endpoint
}

func TestPeerSpeculativeRelayFallbackWithoutEligibleRelayStaysLossy(t *testing.T) {
	for _, last := range []int{Direct, RelayA, RelayB} {
		ctx, cancel := context.WithCancel(t.Context())
		endpoint := fallbackQueueEndpoint(ctx, cancel)
		endpoint.active = last
		endpoint.paths[RelayA].failed = true
		endpoint.paths[RelayB].failed = true
		if _, err := endpoint.WriteTo([]byte("encrypted packet"), endpoint.RemoteAddr()); err != nil {
			t.Fatal(err)
		}
		if endpoint.ActivePath() != last {
			t.Fatal("missing eligible relay forced a different last path")
		}
		for _, p := range endpoint.paths {
			if p.alive || len(p.queue) != 0 {
				t.Fatal("missing eligible relay granted health or queued a packet")
			}
		}
		if last == Direct && endpoint.Stats(Direct).DroppedFrames != 1 {
			t.Fatal("unhealthy direct data gate was bypassed")
		}
		cancel()
	}
}

func TestPeerSpeculativeRelayFallbackFullQueueDoesNotFanOut(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	endpoint := fallbackQueueEndpoint(ctx, cancel)
	for range packetQueue {
		endpoint.paths[RelayA].queue <- queuedFrame{}
	}
	if _, err := endpoint.WriteTo([]byte("encrypted packet"), endpoint.RemoteAddr()); err != nil {
		t.Fatal(err)
	}
	if endpoint.ActivePath() != RelayA || endpoint.Stats(RelayA).DroppedFrames != 1 || len(endpoint.paths[RelayA].queue) != packetQueue {
		t.Fatal("speculative delivery escaped its bounded queue")
	}
	if len(endpoint.paths[RelayB].queue) != 0 || len(endpoint.paths[Direct].queue) != 0 {
		t.Fatal("a full speculative queue fanned a packet out to another carrier")
	}
	cancel()
	if _, err := endpoint.WriteTo([]byte("after cancellation"), endpoint.RemoteAddr()); !errors.Is(err, net.ErrClosed) {
		t.Fatal("canceled endpoint accepted speculative delivery", err)
	}
}

func TestPeerSpeculativeRelayFallbackPreservesQueuedGenerationFence(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	endpoint := fallbackQueueEndpoint(ctx, cancel)
	slot := NewCarrierSlot()
	t.Cleanup(func() { _ = slot.Close() })
	old, oldPeer := memoryPair()
	if err := slot.Install(old); err != nil {
		t.Fatal(err)
	}
	endpoint.paths[RelayA].carrier = slot
	if _, err := endpoint.WriteTo([]byte("old encrypted packet"), endpoint.RemoteAddr()); err != nil {
		t.Fatal(err)
	}
	queued := <-endpoint.paths[RelayA].queue
	if queued.generation != slot.Generation() {
		t.Fatal("speculative delivery did not capture its carrier generation")
	}
	next, nextPeer := memoryPair()
	if err := slot.Install(next); err != nil {
		t.Fatal(err)
	}
	if err := slot.SendGeneration(ctx, queued.data, queued.generation); err != nil {
		t.Fatal(err)
	}
	if len(oldPeer.in) != 0 || len(nextPeer.in) != 0 {
		t.Fatal("old-generation ciphertext crossed a replacement boundary")
	}
	if _, err := endpoint.WriteTo([]byte("current encrypted packet"), endpoint.RemoteAddr()); err != nil {
		t.Fatal(err)
	}
	current := <-endpoint.paths[RelayA].queue
	if current.generation != slot.Generation() || current.generation == queued.generation {
		t.Fatal("speculative delivery retained a replaced generation")
	}
	if err := slot.SendGeneration(ctx, current.data, current.generation); err != nil {
		t.Fatal(err)
	}
	frame := <-nextPeer.in
	packet, err := tunnelv1.ParsePeerPacket(frame)
	if err != nil || string(packet.Payload) != "current encrypted packet" || packet.Path != RelayA {
		t.Fatal("current-generation speculative delivery changed packet or path", err)
	}
	if endpoint.paths[RelayA].alive || endpoint.paths[RelayB].alive || endpoint.paths[Direct].alive {
		t.Fatal("generation replacement minted probe health")
	}
}
