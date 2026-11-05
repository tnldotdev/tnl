package peer

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestPeerPacketQueuedFramesOwnTheirBytes(t *testing.T) {
	for _, tc := range []struct {
		name     string
		kind     tunnelv1.PeerPacketKind
		fragment uint8
		total    uint16
		size     int
	}{
		{"data", tunnelv1.PeerData, 0, 64, 64},
		{"first", tunnelv1.PeerData, 0, 1200, 1000},
		{"second", tunnelv1.PeerData, 1, 1200, 200},
		{"probe", tunnelv1.PeerProbe, 0, 16, 16},
		{"reply", tunnelv1.PeerProbeReply, 0, 16, 16},
	} {
		for role := range uint8(2) {
			for index := range pathCount {
				t.Run(fmt.Sprintf("%s/role%d/path%d", tc.name, role, index), func(t *testing.T) {
					key := [32]byte{1}
					packet := tunnelv1.PeerPacket{Kind: tc.kind, Sequence: 42, Fragment: tc.fragment, Total: tc.total, Payload: bytes.Repeat([]byte{7}, tc.size), MAC: [32]byte{9}}
					endpoint := &Endpoint{config: Config{Key: key, Role: role}}
					endpoint.paths[index] = &path{queue: make(chan []byte, 2)}
					endpoint.enqueue(index, packet)
					for i := range packet.Payload {
						packet.Payload[i] = 8
					}
					packet.Sequence++
					endpoint.enqueue(index, packet)
					binding := PairBinding{Key: key, Role: 1 - role, Path: uint8(index)}
					for number := range 2 {
						var frame []byte
						select {
						case frame = <-endpoint.paths[index].queue:
						default:
							t.Fatal("frame was not queued")
						}
						original := bytes.Clone(frame)
						got, ok := authenticatePacket(frame, key, 1-role, index)
						if !ok || !binding.authentic(frame, role) {
							t.Fatal("queued frame failed authentication")
						}
						if got.Sequence != uint64(42+number) || got.Kind != tc.kind || got.Fragment != tc.fragment || got.Total != tc.total || !bytes.Equal(got.Payload, bytes.Repeat([]byte{byte(7 + number)}, tc.size)) {
							t.Fatal("caller reuse or a later frame changed queued bytes")
						}
						if !bytes.Equal(frame, original) {
							t.Fatal("authentication changed the received frame")
						}
					}
				})
			}
		}
	}
}
