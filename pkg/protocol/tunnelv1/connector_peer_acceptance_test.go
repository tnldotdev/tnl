package tunnelv1

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestConnectorPeerVisitorAcceptanceGoldenAndRawResponseBoundary(t *testing.T) {
	const visitor = "vc_aaaaaaaaaaaaaaaaaaaaaa"
	const body = `{"protocol_version":1,"kind":"connector_peer_visitor_accepted","visitor_connection_id":"vc_aaaaaaaaaaaaaaaaaaaaaa"}`
	want := append(binary.BigEndian.AppendUint32(nil, uint32(len(body))), body...)
	var wire bytes.Buffer
	if err := WriteConnectorPeerVisitorAccepted(&wire, visitor); err != nil || !bytes.Equal(wire.Bytes(), want) {
		t.Fatal("application admission acceptance wire changed", err)
	}
	for n := range len(want) {
		if err := ReadConnectorPeerVisitorAccepted(bytes.NewReader(want[:n]), visitor); err == nil {
			t.Fatal("truncated application acceptance was accepted", n)
		}
	}
	wire.Write([]byte{0x16, 0x03, 0x03, 0x00, 0x01, 0xff})
	if err := ReadConnectorPeerVisitorAccepted(&wire, visitor); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire.Bytes(), []byte{0x16, 0x03, 0x03, 0x00, 0x01, 0xff}) {
		t.Fatal("admission acknowledgement consumed raw protocol response bytes")
	}
	if err := ReadConnectorPeerVisitorAccepted(bytes.NewReader(want), "vc_bbbbbbbbbbbbbbbbbbbbbb"); !errors.Is(err, ErrConnectorPeerVisitorOpening) {
		t.Fatal("application acceptance transferred to another visitor", err)
	}
	var empty bytes.Buffer
	if err := WriteConnectorPeerVisitorAccepted(&empty, "invalid"); err == nil || empty.Len() != 0 {
		t.Fatal("invalid visitor emitted acceptance bytes", err)
	}
	for _, size := range []uint32{0, 257, ^uint32(0)} {
		r := &headerOnlyReader{header: bytes.NewReader(binary.BigEndian.AppendUint32(nil, size))}
		if err := ReadConnectorPeerVisitorAccepted(r, visitor); err == nil || r.payloadReads != 0 {
			t.Fatal("oversized application acceptance reached payload reading", err)
		}
	}
}
