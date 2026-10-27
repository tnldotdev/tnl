package tunnelv1

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"testing"
)

func TestPeerDeliveryBoundsAndGenerationFence(t *testing.T) {
	d := PeerDelivery{Pair: [16]byte{1}, Generation: 42}
	key := [32]byte{3}
	frame, err := (PeerPacket{Kind: PeerData, Sequence: 1, Total: 1, Payload: []byte{7}}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	b, err := d.Seal(PeerDeliveryDatagram, key, frame)
	if err != nil {
		t.Fatal(err)
	}
	const golden = "0101000000000000000000000000000000000000000000002a010100000000000000000000010001000107000000000000000000000000000000000000000000000000000000000000000050da532275655921bba7dd65ea2b478d349bdd8ce6a9b58f026c8d2ff8e72d95"
	if hex.EncodeToString(b) != golden {
		t.Fatal("peer delivery wire changed")
	}
	got, packet, err := OpenPeerDelivery(b, PeerDeliveryDatagram, key)
	if err != nil || got != d || !bytes.Equal(packet, frame) {
		t.Fatal(got, err)
	}
	for _, bad := range [][]byte{
		b[:PeerDeliveryHeaderBytes],
		append(bytes.Clone(b), 0),
		append(bytes.Repeat([]byte{0}, PeerDeliveryHeaderBytes), b[PeerDeliveryHeaderBytes:]...),
		func() []byte { changed := bytes.Clone(b); changed[1]++; return changed }(),
		func() []byte { changed := bytes.Clone(b); changed[17]++; return changed }(),
		func() []byte { changed := bytes.Clone(b); changed[len(changed)-1]++; return changed }(),
	} {
		if _, _, err := OpenPeerDelivery(bad, PeerDeliveryDatagram, key); !errors.Is(err, ErrPeerPacket) {
			t.Fatal("accepted malformed delivery", err)
		}
	}
	if _, _, err := OpenPeerDelivery(b, PeerDeliveryStream, key); !errors.Is(err, ErrPeerPacket) {
		t.Fatal("datagram accepted as stream")
	}
	if _, _, err := OpenPeerDelivery(b, PeerDeliveryDatagram, [32]byte{4}); !errors.Is(err, ErrPeerPacket) {
		t.Fatal("wrong key accepted")
	}
	for _, invalid := range []PeerDelivery{{}, {Pair: d.Pair}, {Generation: 42}} {
		if _, err := invalid.Seal(PeerDeliveryDatagram, key, frame); !errors.Is(err, ErrPeerPacket) {
			t.Fatal("accepted empty pair/generation")
		}
	}
	if _, err := d.Seal(0, key, frame); !errors.Is(err, ErrPeerPacket) {
		t.Fatal("unknown carrier mode")
	}
	var reliable bytes.Buffer
	stream, err := d.Seal(PeerDeliveryStream, key, frame)
	if err != nil {
		t.Fatal(err)
	}
	if err := WritePeerDeliveryFrame(&reliable, stream, PeerDeliveryStream, key); err != nil {
		t.Fatal(err)
	}
	const streamGolden = "006b0101000000000000000000000000000000000000000000002a0101000000000000000000000100010001070000000000000000000000000000000000000000000000000000000000000000817c59579e7a94ec8e50caedd46a89bda16475f8fb4f38787a6d2f30a107f4fc"
	if hex.EncodeToString(reliable.Bytes()) != streamGolden {
		t.Fatal("peer stream wire changed")
	}
	streamWire := bytes.Clone(reliable.Bytes())
	if got, payload, err := ReadPeerDeliveryFrame(&reliable, PeerDeliveryStream, key); err != nil || got != d || !bytes.Equal(payload, frame) {
		t.Fatal("stream framing", err)
	}
	corrupt := bytes.Clone(streamWire)
	corrupt[len(corrupt)-1]++
	if _, _, err := ReadPeerDeliveryFrame(bytes.NewReader(corrupt), PeerDeliveryStream, key); !errors.Is(err, ErrPeerPacket) {
		t.Fatal("invalid stream tag accepted", err)
	}
	if _, _, err := ReadPeerDeliveryFrame(bytes.NewReader(streamWire[:len(streamWire)-1]), PeerDeliveryStream, key); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal("truncated authenticated stream frame", err)
	}
	large := PeerPacket{Kind: PeerData, Sequence: 1, Total: MaxPeerPacketBytes, Payload: bytes.Repeat([]byte{1}, PeerFragmentBytes)}
	frame, _ = large.MarshalBinary()
	if b, err := d.Seal(PeerDeliveryDatagram, key, frame); err != nil || len(b) != MaxPeerDeliveryBytes || len(b) > 1200 {
		t.Fatal("outer datagram exceeds path MTU", err)
	}
	if _, _, err := ReadPeerDeliveryFrame(bytes.NewReader([]byte{0xff, 0xff}), PeerDeliveryStream, key); !errors.Is(err, ErrPeerPacket) {
		t.Fatal("oversized stream frame allocated", err)
	}
	if _, _, err := ReadPeerDeliveryFrame(bytes.NewReader([]byte{0}), PeerDeliveryStream, key); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal("truncated stream header", err)
	}
}

func FuzzPeerDelivery(f *testing.F) {
	d := PeerDelivery{Pair: [16]byte{1}, Generation: 7}
	key := [32]byte{3}
	frame, _ := (PeerPacket{Kind: PeerData, Sequence: 1, Total: 1, Payload: []byte{1}}).MarshalBinary()
	valid, _ := d.Seal(PeerDeliveryDatagram, key, frame)
	stream, _ := d.Seal(PeerDeliveryStream, key, frame)
	f.Add(byte(PeerDeliveryDatagram), valid)
	f.Add(byte(PeerDeliveryStream), stream)
	f.Add(byte(0), []byte{1, 2, 3})
	f.Fuzz(func(t *testing.T, rawMode byte, b []byte) {
		mode := PeerDeliveryMode(rawMode)
		delivery, packet, err := OpenPeerDelivery(b, mode, key)
		if err != nil {
			return
		}
		rebuilt, err := delivery.Seal(mode, key, packet)
		if err != nil || !bytes.Equal(rebuilt, b) {
			t.Fatal("delivery was not canonical", err)
		}
	})
}
