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
		if _, prefix, err := ParsePeerPacketWithAuthenticatedBytes(invalid); !errors.Is(err, ErrPeerPacket) || prefix != nil {
			t.Fatal("malformed packet returned a MAC input", err)
		}
	}
	for n := range len(b) {
		if _, err := ParsePeerPacket(b[:n]); !errors.Is(err, ErrPeerPacket) {
			t.Fatal("truncated packet accepted", n, err)
		}
		if _, prefix, err := ParsePeerPacketWithAuthenticatedBytes(b[:n]); !errors.Is(err, ErrPeerPacket) || prefix != nil {
			t.Fatal("truncated packet returned a MAC input", n, err)
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

func TestPeerPacketAuthenticatedPrefixBorrowsCanonicalFrame(t *testing.T) {
	const golden = "0101000100000000000000002a00030003616263d1475c7153bdd3e6f0b4bf86d5c3d142368d3a697b196273d7514a424636c06d"
	frame, err := hex.DecodeString(golden)
	if err != nil {
		t.Fatal(err)
	}
	original := bytes.Clone(frame)
	packet, prefix, err := ParsePeerPacketWithAuthenticatedBytes(frame)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := packet.AuthenticatedBytes()
	if err != nil || !bytes.Equal(prefix, canonical) || &prefix[0] != &frame[0] {
		t.Fatal("MAC input is not the original canonical prefix", err)
	}
	// appending to the borrowed prefix must not overwrite the received MAC.
	_ = append(prefix, bytes.Repeat([]byte{0xff}, len(packet.MAC))...)
	if !bytes.Equal(frame, original) {
		t.Fatal("using the prefix changed its source frame")
	}
	for _, invalid := range [][]byte{append(bytes.Clone(frame), 0), make([]byte, MaxPeerFrameBytes+1)} {
		if _, prefix, err := ParsePeerPacketWithAuthenticatedBytes(invalid); !errors.Is(err, ErrPeerPacket) || prefix != nil {
			t.Fatal("extended packet returned a MAC input", err)
		}
	}
}

func FuzzPeerPackets(f *testing.F) {
	b, _ := (PeerPacket{Kind: PeerData, Sequence: 1, Total: 1, Payload: []byte{1}}).MarshalBinary()
	f.Add(b)
	f.Add([]byte{})
	for _, packet := range []PeerPacket{
		{Kind: PeerData, Sender: 1, Path: 2, Sequence: ^uint64(0), Total: 1200, Payload: bytes.Repeat([]byte{7}, 1000)},
		{Kind: PeerData, Sender: 1, Path: 2, Sequence: ^uint64(0), Fragment: 1, Total: 1200, Payload: bytes.Repeat([]byte{8}, 200)},
		{Kind: PeerProbe, Path: 1, Sequence: 42, Total: 16, Payload: bytes.Repeat([]byte{9}, 16)},
		{Kind: PeerProbeReply, Sender: 1, Path: 2, Sequence: 43, Total: 16, Payload: bytes.Repeat([]byte{10}, 16)},
	} {
		b, err := packet.MarshalBinary()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		p, prefix, err := ParsePeerPacketWithAuthenticatedBytes(b)
		if err != nil {
			if prefix != nil {
				t.Fatal("invalid packet returned a MAC input")
			}
			return
		}
		encoded, err := p.MarshalBinary()
		if err != nil || !bytes.Equal(b, encoded) {
			t.Fatal("packet is not canonical", err)
		}
		canonical, err := p.AuthenticatedBytes()
		if err != nil || !bytes.Equal(prefix, canonical) {
			t.Fatal("original prefix differs from the canonical MAC input", err)
		}
	})
}
