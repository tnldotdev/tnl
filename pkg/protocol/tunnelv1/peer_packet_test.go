package tunnelv1

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"testing"
)

func TestPeerPacketGoldenAndBounds(t *testing.T) {
	p := PeerPacket{Kind: PeerData, Path: 1, Sequence: 42, Total: 3, Payload: []byte("abc")}
	b, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	const golden = "0101000100000000000000002a000300036162630000000000000000000000000000000000000000000000000000000000000000"
	if hex.EncodeToString(b) != golden {
		t.Fatalf("packet wire changed: %x", b)
	}
	var stream bytes.Buffer
	if err := WritePeerFrame(&stream, b); err != nil {
		t.Fatal(err)
	}
	got, err := ReadPeerFrame(&stream)
	if err != nil || !bytes.Equal(got, b) {
		t.Fatal("reliable carrier changed packet boundaries", err)
	}
	for _, mutate := range []func([]byte){
		func(b []byte) { b[0] = 2 },
		func(b []byte) { b[1] = 4 },
		func(b []byte) { b[2] = 2 },
		func(b []byte) { b[3] = 3 },
		func(b []byte) { b[4] = 2 },
		func(b []byte) { b[12] = 0 },
		func(b []byte) { b[14] = 4 },
		func(b []byte) { b[16] = 4 },
	} {
		invalid := bytes.Clone(b)
		mutate(invalid)
		if _, err := ParsePeerPacket(invalid); !errors.Is(err, ErrPeerPacket) {
			t.Fatal("malformed packet accepted", err)
		}
	}
	for n := range len(b) {
		if _, err := ParsePeerPacket(b[:n]); !errors.Is(err, ErrPeerPacket) {
			t.Fatal("truncated packet accepted", n, err)
		}
	}
	for _, input := range [][]byte{{0xff, 0xff}, {0, 0}, {0, 49}} {
		if _, err := ReadPeerFrame(bytes.NewReader(input)); !errors.Is(err, ErrPeerPacket) {
			t.Fatal("invalid frame allocated or read its payload", err)
		}
	}
	large := PeerPacket{Kind: PeerData, Sequence: 1, Total: MaxPeerPacketBytes, Payload: bytes.Repeat([]byte{1}, PeerFragmentBytes)}
	if b, err := large.MarshalBinary(); err != nil || len(b) != MaxPeerFrameBytes || len(b) > 1100 {
		t.Fatal("fragment cannot fit a minimum-size outer QUIC packet", len(b), err)
	}
	if _, err := ReadPeerFrame(bytes.NewReader([]byte{0})); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal("lost read cause", err)
	}
}

func FuzzPeerPackets(f *testing.F) {
	b, _ := (PeerPacket{Kind: PeerData, Sequence: 1, Total: 1, Payload: []byte{1}}).MarshalBinary()
	f.Add(b)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := ParsePeerPacket(b)
		if err != nil {
			return
		}
		encoded, err := p.MarshalBinary()
		if err != nil || !bytes.Equal(b, encoded) {
			t.Fatal("packet is not canonical", err)
		}
	})
}
