package tunnelv1

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"strings"
	"testing"
)

const connectorPeerDirectTestDomain = "tnl connector direct packet v1\x00"

func connectorPeerDirectFixture(t testing.TB) (ConnectorPeerDirect, [32]byte, []byte, []byte) {
	t.Helper()
	// the peer_packet_test.go golden with only its path byte changed to 2.
	const inner = "0101000100000000000000002a0003000300000000000000016162630000000000000000000000000000000000000000000000000000000000000000"
	frame, err := hex.DecodeString(inner)
	if err != nil {
		t.Fatal("could not decode fixed inner fixture")
	}
	frame[3] = 2
	// calculated independently with Python struct.pack('>BQQ') and HMAC-SHA256.
	golden, err := hex.DecodeString(strings.TrimSpace(string(readFixture(t, "connector-peer-direct.packet.hex"))))
	if err != nil {
		t.Fatal("could not decode direct packet golden")
	}
	return ConnectorPeerDirect{Generation: 1, Attempt: 0x0102030405060708}, [32]byte{3}, frame, golden
}

// sign test-authored bytes without calling the production envelope encoder.
func signConnectorPeerDirectFixture(body []byte, key [32]byte, domain string) []byte {
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte(domain))
	_, _ = mac.Write(body)
	return append(bytes.Clone(body), mac.Sum(nil)...)
}

func assertInvalidConnectorPeerDirect(t testing.TB, packet []byte, key [32]byte) {
	t.Helper()
	d, frame, err := OpenConnectorPeerDirect(packet, key)
	if !errors.Is(err, ErrPeerPacket) || d != (ConnectorPeerDirect{}) || frame != nil {
		t.Fatal("invalid direct packet returned data or lost its protocol error")
	}
}

func TestConnectorPeerDirectGoldenAndAuthentication(t *testing.T) {
	d, key, frame, golden := connectorPeerDirectFixture(t)
	packet, err := d.Seal(frame, key)
	if err != nil || !bytes.Equal(packet, golden) {
		t.Fatal("direct packet does not match the independent binary golden")
	}
	got, inner, err := OpenConnectorPeerDirect(golden, key)
	if err != nil || got != d || !bytes.Equal(inner, frame) {
		t.Fatal("direct packet golden did not preserve its counters and inner frame")
	}
	for i := range golden {
		tampered := bytes.Clone(golden)
		tampered[i] ^= 1
		assertInvalidConnectorPeerDirect(t, tampered, key)
	}
	for length := range len(golden) {
		assertInvalidConnectorPeerDirect(t, golden[:length], key)
	}
	assertInvalidConnectorPeerDirect(t, append(bytes.Clone(golden), 0), key)
	assertInvalidConnectorPeerDirect(t, golden, [32]byte{})
	assertInvalidConnectorPeerDirect(t, golden, [32]byte{4})
	for _, domain := range []string{
		"", "connector_peer\x00", "tnl-peer-delivery-v1\x00\x01", "tnl connector direct packet v1",
	} {
		forged := signConnectorPeerDirectFixture(golden[:len(golden)-32], key, domain)
		assertInvalidConnectorPeerDirect(t, forged, key)
	}
}

func TestConnectorPeerDirectRejectsAuthenticatedInvalidFields(t *testing.T) {
	_, key, _, golden := connectorPeerDirectFixture(t)
	for _, test := range []struct {
		name   string
		change func([]byte)
	}{
		{"version", func(b []byte) { b[0] = 2 }},
		{"zero generation", func(b []byte) { binary.BigEndian.PutUint64(b[1:9], 0) }},
		{"zero attempt", func(b []byte) { binary.BigEndian.PutUint64(b[9:17], 0) }},
		{"generation mismatch", func(b []byte) { binary.BigEndian.PutUint64(b[1:9], 2) }},
		{"first relay path", func(b []byte) { b[17+3] = 0 }},
		{"second relay path", func(b []byte) { b[17+3] = 1 }},
		{"invalid inner frame", func(b []byte) { b[17] = 2 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := bytes.Clone(golden[:len(golden)-32])
			test.change(body)
			// a correct outer tag must not bypass structural or binding checks.
			assertInvalidConnectorPeerDirect(t, signConnectorPeerDirectFixture(body, key, connectorPeerDirectTestDomain), key)
		})
	}
}

func TestConnectorPeerDirectSealValidationAndAttemptBinding(t *testing.T) {
	d, key, frame, golden := connectorPeerDirectFixture(t)
	for _, test := range []struct {
		name string
		d    ConnectorPeerDirect
		key  [32]byte
	}{
		{"zero generation", ConnectorPeerDirect{Attempt: d.Attempt}, key},
		{"zero attempt", ConnectorPeerDirect{Generation: d.Generation}, key},
		{"wrong generation", ConnectorPeerDirect{Generation: 2, Attempt: d.Attempt}, key},
		{"zero key", d, [32]byte{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if packet, err := test.d.Seal(frame, test.key); !errors.Is(err, ErrPeerPacket) || packet != nil {
				t.Fatal("invalid direct binding produced a packet")
			}
		})
	}
	for _, path := range []byte{0, 1} {
		relayFrame := bytes.Clone(frame)
		relayFrame[3] = path
		if packet, err := d.Seal(relayFrame, key); !errors.Is(err, ErrPeerPacket) || packet != nil {
			t.Fatal("relay frame acquired a direct envelope")
		}
	}
	for _, invalid := range [][]byte{nil, frame[:len(frame)-1], make([]byte, MaxPeerFrameBytes+1)} {
		if packet, err := d.Seal(invalid, key); !errors.Is(err, ErrPeerPacket) || packet != nil {
			t.Fatal("malformed inner frame acquired a direct envelope")
		}
	}
	next := d
	next.Attempt++
	packet, err := next.Seal(frame, key)
	if err != nil || bytes.Equal(packet, golden) || bytes.Equal(packet[len(packet)-32:], golden[len(golden)-32:]) {
		t.Fatal("new attempt did not change the authenticated packet")
	}
	got, inner, err := OpenConnectorPeerDirect(packet, key)
	// callers compare these authenticated counters with the active attempt.
	if err != nil || got != next || !bytes.Equal(inner, frame) {
		t.Fatal("new attempt was not returned with its authenticated frame")
	}
}

func TestConnectorPeerDirectBounds(t *testing.T) {
	if ConnectorPeerDirectHeaderBytes != 17 || ConnectorPeerDirectTagBytes != 32 || MaxConnectorPeerDirectBytes != 1106 {
		t.Fatal("direct packet wire bounds changed")
	}
	for _, test := range []struct {
		generation, attempt uint64
		payload             int
	}{
		{1, 1, 1}, {math.MaxUint64, math.MaxUint64, 1000},
	} {
		d := ConnectorPeerDirect{Generation: test.generation, Attempt: test.attempt}
		frame, err := (PeerPacket{BindingGeneration: d.Generation, Kind: PeerData, Path: 2, Sequence: 42,
			Total: uint16(test.payload), Payload: bytes.Repeat([]byte{1}, test.payload)}).MarshalBinary()
		if err != nil {
			t.Fatal("could not build bounded inner frame")
		}
		key := [32]byte{3}
		packet, err := d.Seal(frame, key)
		if err != nil || len(packet) != 17+57+test.payload+32 || len(packet) > 1200 {
			t.Fatal("direct envelope did not preserve its exact packet bound")
		}
		got, inner, err := OpenConnectorPeerDirect(packet, key)
		if err != nil || got != d || !bytes.Equal(inner, frame) {
			t.Fatal("bounded direct envelope did not round trip")
		}
		if test.payload == 1000 {
			// keep a correct outer tag when crossing either frame-size boundary.
			body := packet[:len(packet)-32]
			assertInvalidConnectorPeerDirect(t, signConnectorPeerDirectFixture(append(bytes.Clone(body), 0), key, connectorPeerDirectTestDomain), key)
			assertInvalidConnectorPeerDirect(t, signConnectorPeerDirectFixture(body[:17+57], key, connectorPeerDirectTestDomain), key)
		}
	}
}

func FuzzConnectorPeerDirect(f *testing.F) {
	_, key, _, golden := connectorPeerDirectFixture(f)
	f.Add(golden)
	f.Add(golden[:len(golden)-32])
	f.Add([]byte{})
	f.Add(make([]byte, MaxConnectorPeerDirectBytes+1))
	f.Fuzz(func(t *testing.T, input []byte) {
		packets := [][]byte{input}
		if len(input) <= MaxConnectorPeerDirectBytes-32 {
			// authenticating fuzzed bytes exercises checks behind the HMAC fence.
			packets = append(packets, signConnectorPeerDirectFixture(input, key, connectorPeerDirectTestDomain))
		}
		for _, packet := range packets {
			d, frame, err := OpenConnectorPeerDirect(packet, key)
			if err != nil {
				if !errors.Is(err, ErrPeerPacket) || d != (ConnectorPeerDirect{}) || frame != nil {
					t.Fatal("failed direct decode returned data or lost its protocol error")
				}
				continue
			}
			if len(packet) <= 17+57+32 || len(packet) > 1106 || d.Generation == 0 || d.Attempt == 0 {
				t.Fatal("accepted direct packet violated wire bounds")
			}
			inner, err := ParsePeerPacket(frame)
			if err != nil || inner.BindingGeneration != d.Generation || inner.Path != 2 {
				t.Fatal("accepted direct packet lost its generation or path binding")
			}
			encoded, err := d.Seal(frame, key)
			if err != nil || !bytes.Equal(encoded, packet) {
				t.Fatal("accepted direct packet was not canonical")
			}
		}
	})
}
