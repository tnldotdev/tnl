package peer

import (
	"bytes"
	"testing"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func BenchmarkPeerPacket(b *testing.B) {
	for _, tc := range []struct {
		name     string
		kind     tunnelv1.PeerPacketKind
		fragment uint8
		total    uint16
		size     int
	}{
		{"data64", tunnelv1.PeerData, 0, 64, 64},
		{"first1000", tunnelv1.PeerData, 0, 1200, 1000},
		{"second200", tunnelv1.PeerData, 1, 1200, 200},
		{"probe", tunnelv1.PeerProbe, 0, 16, 16},
		{"reply", tunnelv1.PeerProbeReply, 0, 16, 16},
	} {
		b.Run(tc.name, func(b *testing.B) {
			key := [32]byte{1}
			packet := tunnelv1.PeerPacket{Kind: tc.kind, Sequence: 42, Fragment: tc.fragment, Total: tc.total, Payload: bytes.Repeat([]byte{7}, tc.size)}
			endpoint := &Endpoint{config: Config{Key: key}}
			endpoint.paths[RelayB] = &path{queue: make(chan []byte, 1)}
			endpoint.enqueue(RelayB, packet)
			var frame []byte
			select {
			case frame = <-endpoint.paths[RelayB].queue:
			default:
				b.Fatal("fixture was not queued")
			}
			binding := PairBinding{Key: key, Role: 1, Path: RelayB}
			b.Run("enqueue", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(frame)))
				// include the real queue lock and handoff, without background probes or sockets.
				for b.Loop() {
					endpoint.enqueue(RelayB, packet)
					select {
					case got := <-endpoint.paths[RelayB].queue:
						if len(got) != len(frame) {
							b.Fatal("frame size changed")
						}
					default:
						b.Fatal("frame was not queued")
					}
				}
			})
			b.Run("authenticate", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(frame)))
				for b.Loop() {
					if _, ok := authenticatePacket(frame, key, 1, RelayB); !ok {
						b.Fatal("valid frame rejected")
					}
				}
			})
			b.Run("binding", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(frame)))
				for b.Loop() {
					if !binding.authentic(frame, 0) {
						b.Fatal("valid binding rejected")
					}
				}
			})
		})
	}
}
