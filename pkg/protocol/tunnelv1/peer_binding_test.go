package tunnelv1

import (
	"bytes"
	"errors"
	"testing"
)

func TestPeerSessionMACIsIndependentOfRelayCredential(t *testing.T) {
	session, envelope := [32]byte{1}, [32]byte{2}
	packet := PeerPacket{BindingGeneration: 42, Kind: PeerProbeReply, Sender: 1, Path: 1, Sequence: 7, Total: 16, Payload: bytes.Repeat([]byte{3}, 16)}
	frame, err := SignPeerPacketFrame(packet, session)
	if err != nil {
		t.Fatal(err)
	}
	delivery := PeerDelivery{Pair: [16]byte{4}, Generation: 42}
	wire, err := delivery.Seal(PeerDeliveryDatagram, envelope, frame)
	if err != nil {
		t.Fatal(err)
	}
	_, got, err := OpenPeerDelivery(wire, PeerDeliveryDatagram, envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyPeerPacketFrame(got, session); err != nil {
		t.Fatal("endpoint rejected its stable session key", err)
	}
	if _, err := VerifyPeerPacketFrame(got, envelope); !errors.Is(err, ErrPeerPacket) {
		t.Fatal("relay envelope credential verified the inner MAC", err)
	}
	forged := bytes.Clone(frame)
	forged[len(forged)-1]++
	sealed, err := delivery.Seal(PeerDeliveryDatagram, envelope, forged)
	if err != nil {
		t.Fatal("relay required the endpoint-only session MAC", err)
	}
	_, admitted, err := OpenPeerDelivery(sealed, PeerDeliveryDatagram, envelope)
	if err != nil {
		t.Fatal("relay could not validate an envelope independently", err)
	}
	if _, err := VerifyPeerPacketFrame(admitted, session); !errors.Is(err, ErrPeerPacket) {
		t.Fatal("endpoint admitted a relay-minted inner MAC", err)
	}
	for _, index := range []int{2, 3, 12, 24, 25, len(frame) - 1} {
		forged := bytes.Clone(frame)
		forged[index] ^= 1
		if _, err := VerifyPeerPacketFrame(forged, session); !errors.Is(err, ErrPeerPacket) {
			t.Fatal("inner MAC did not bind its direction, path, sequence, revision, and payload", index, err)
		}
	}
	delivery.Generation++
	if _, err := delivery.Seal(PeerDeliveryDatagram, envelope, frame); !errors.Is(err, ErrPeerPacket) {
		t.Fatal("delivery revision disagreed with inner authenticated revision", err)
	}
}

func TestPeerBindingProbeBindsEveryTupleField(t *testing.T) {
	nonce := bytes.Repeat([]byte{7}, 16)
	base, err := ConnectorPeerBindingProbe("pair", "operation", 42, "challenge", 0, 0, nonce)
	if err != nil {
		t.Fatal(err)
	}
	for index := range 7 {
		pair, operation, challenge := "pair", "operation", "challenge"
		generation, role, path := int64(42), uint8(0), uint8(0)
		changedNonce := bytes.Clone(nonce)
		switch index {
		case 0:
			pair += "2"
		case 1:
			operation += "2"
		case 2:
			generation++
		case 3:
			challenge += "2"
		case 4:
			role++
		case 5:
			path++
		case 6:
			changedNonce[0]++
		}
		got, err := ConnectorPeerBindingProbe(pair, operation, generation, challenge, role, path, changedNonce)
		if err != nil || got == base {
			t.Fatal("probe did not separate its canonical tuple", index, err)
		}
	}
	if _, err := ConnectorPeerBindingProbe("pair", "operation", 0, "challenge", 0, 0, nonce); !errors.Is(err, ErrPeerPacket) {
		t.Fatal("zero revision accepted", err)
	}
	if _, err := ConnectorPeerBindingProbe("pair", "operation", 42, "challenge", 0, 0, nonce[:15]); !errors.Is(err, ErrPeerPacket) {
		t.Fatal("noncanonical nonce length accepted", err)
	}
}
