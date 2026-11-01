package tunnelv1

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"reflect"
	"testing"
)

func TestConnectorRequestFramesGoldenAndTruncatedWire(t *testing.T) {
	for _, test := range []struct {
		frame ConnectorRequestFrame
		wire  string
	}{
		{ConnectorRequestFrame{Kind: ConnectorRequestData, Data: []byte{0x16, 3, 1}}, "0100000003160301"},
		{ConnectorRequestFrame{Kind: ConnectorRequestEnded}, "0300000000"},
	} {
		var wire bytes.Buffer
		if err := WriteConnectorRequestFrame(&wire, test.frame); err != nil || hex.EncodeToString(wire.Bytes()) != test.wire {
			t.Fatalf("connector request wire changed: %x %v", wire.Bytes(), err)
		}
		decoded, err := ReadConnectorRequestFrame(bytes.NewReader(wire.Bytes()))
		if err != nil || !reflect.DeepEqual(decoded, test.frame) {
			t.Fatal("connector request did not round trip", err)
		}
		for size := range wire.Len() {
			if _, err := ReadConnectorRequestFrame(bytes.NewReader(wire.Bytes()[:size])); err == nil {
				t.Fatal("truncated connector request was accepted")
			}
		}
	}
	permission := peerOpeningFixture().Permission
	var frame bytes.Buffer
	if err := WriteConnectorRequestFrame(&frame, ConnectorRequestFrame{Kind: ConnectorRequestPermission, Permission: permission}); err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	if err := writeJSONFrame(&body, permission, MaxConnectorPermissionBytes); err != nil {
		t.Fatal(err)
	}
	if frame.Bytes()[0] != byte(ConnectorRequestPermission) || !bytes.Equal(frame.Bytes()[1:], body.Bytes()) {
		t.Fatal("renewal changed the canonical connector permission encoding")
	}
	got, err := ReadConnectorRequestFrame(&frame)
	if err != nil || got.Permission != permission || got.Kind != ConnectorRequestPermission || len(got.Data) != 0 {
		t.Fatal("renewal lost its exact signed proof", err)
	}
}

func TestConnectorRequestBoundsRejectBeforeReadingPayload(t *testing.T) {
	for _, test := range []struct {
		kind   ConnectorRequestKind
		length uint32
	}{
		{0, 1}, {255, 1}, {ConnectorRequestData, 0}, {ConnectorRequestData, MaxInitialBytes + 1},
		{ConnectorRequestPermission, 0}, {ConnectorRequestPermission, MaxConnectorPermissionBytes + 1}, {ConnectorRequestEnded, 1},
	} {
		reader := &headerOnlyReader{header: bytes.NewReader(binary.BigEndian.AppendUint32([]byte{byte(test.kind)}, test.length))}
		if _, err := ReadConnectorRequestFrame(reader); !errors.Is(err, ErrConnectorRequest) || reader.payloadReads != 0 {
			t.Fatal("invalid native length reached payload reading", err)
		}
	}
	var wire bytes.Buffer
	for _, frame := range []ConnectorRequestFrame{
		{Kind: ConnectorRequestData, Data: make([]byte, MaxInitialBytes+1)},
		{Kind: ConnectorRequestData, Data: []byte("app bytes"), Permission: peerOpeningFixture().Permission},
		{Kind: ConnectorRequestPermission},
		{Kind: ConnectorRequestEnded, Data: []byte("app bytes")},
	} {
		if err := WriteConnectorRequestFrame(&wire, frame); !errors.Is(err, ErrConnectorRequest) || wire.Len() != 0 {
			t.Fatal("invalid connector request was written", err)
		}
	}
	if err := WriteConnectorRequestFrame(io.Discard, ConnectorRequestFrame{Kind: ConnectorRequestData, Data: make([]byte, MaxInitialBytes)}); err != nil {
		t.Fatal(err)
	}
}

func FuzzConnectorRequestFrames(f *testing.F) {
	f.Add([]byte{1, 0, 0, 0, 1, 0x16})
	f.Add([]byte{3, 0, 0, 0, 0})
	var renewal bytes.Buffer
	if err := WriteConnectorRequestFrame(&renewal, ConnectorRequestFrame{Kind: ConnectorRequestPermission, Permission: peerOpeningFixture().Permission}); err != nil {
		f.Fatal(err)
	}
	f.Add(renewal.Bytes())
	f.Fuzz(func(t *testing.T, data []byte) {
		frame, err := ReadConnectorRequestFrame(bytes.NewReader(data))
		if err == nil {
			if err := WriteConnectorRequestFrame(io.Discard, frame); err != nil {
				t.Fatal("decoded request could not be written", err)
			}
		}
	})
}
