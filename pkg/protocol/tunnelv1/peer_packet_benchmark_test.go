package tunnelv1

import (
	"bytes"
	"testing"
)

func BenchmarkPeerDelivery(b *testing.B) {
	for _, tc := range []struct {
		name     string
		fragment uint8
		total    uint16
		size     int
	}{
		{"data64", 0, 64, 64},
		{"first1000", 0, 1200, 1000},
		{"second200", 1, 1200, 200},
	} {
		b.Run(tc.name, func(b *testing.B) {
			delivery := PeerDelivery{Pair: [16]byte{1}, Generation: 42}
			key := [32]byte{3}
			frame, err := (PeerPacket{Kind: PeerData, Sequence: 42, Fragment: tc.fragment, Total: tc.total, Payload: bytes.Repeat([]byte{7}, tc.size)}).MarshalBinary()
			if err != nil {
				b.Fatal(err)
			}
			wire, err := delivery.Seal(PeerDeliveryDatagram, key, frame)
			if err != nil {
				b.Fatal(err)
			}
			b.Run("seal", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(wire)))
				for b.Loop() {
					if got, err := delivery.Seal(PeerDeliveryDatagram, key, frame); err != nil || len(got) != len(wire) {
						b.Fatal("delivery seal failed", err)
					}
				}
			})
			b.Run("open", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(wire)))
				for b.Loop() {
					if got, payload, err := OpenPeerDelivery(wire, PeerDeliveryDatagram, key); err != nil || got != delivery || len(payload) != len(frame) {
						b.Fatal("delivery open failed", err)
					}
				}
			})
		})
	}
}
