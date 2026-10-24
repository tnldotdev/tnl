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

func TestNativeRequestFramesGoldenAndTruncatedWire(t *testing.T) {
	for _, test := range []struct {
		frame NativeRequestFrame
		wire  string
	}{
		{NativeRequestFrame{Kind: NativeRequestData, Data: []byte{0x16, 3, 1}}, "0100000003160301"},
		{NativeRequestFrame{Kind: NativeRequestEnded}, "0300000000"},
	} {
		var wire bytes.Buffer
		if err := WriteNativeRequestFrame(&wire, test.frame); err != nil || hex.EncodeToString(wire.Bytes()) != test.wire {
			t.Fatalf("native request wire changed: %x %v", wire.Bytes(), err)
		}
		decoded, err := ReadNativeRequestFrame(bytes.NewReader(wire.Bytes()))
		if err != nil || !reflect.DeepEqual(decoded, test.frame) {
			t.Fatal("native request did not round trip", err)
		}
		for size := range wire.Len() {
			if _, err := ReadNativeRequestFrame(bytes.NewReader(wire.Bytes()[:size])); err == nil {
				t.Fatal("truncated native request was accepted")
			}
		}
	}
	permission := nativeTestEntry().Permission
	var frame bytes.Buffer
	if err := WriteNativeRequestFrame(&frame, NativeRequestFrame{Kind: NativeRequestPermission, Permission: permission}); err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	if err := writeJSONFrame(&body, permission, MaxNativePermissionBytes); err != nil {
		t.Fatal(err)
	}
	if frame.Bytes()[0] != byte(NativeRequestPermission) || !bytes.Equal(frame.Bytes()[1:], body.Bytes()) {
		t.Fatal("renewal changed the canonical native permission encoding")
	}
	got, err := ReadNativeRequestFrame(&frame)
	if err != nil || got.Permission != permission || got.Kind != NativeRequestPermission || len(got.Data) != 0 {
		t.Fatal("renewal lost its exact signed proof", err)
	}
}

func TestNativeRequestBoundsRejectBeforeReadingPayload(t *testing.T) {
	for _, test := range []struct {
		kind   NativeRequestKind
		length uint32
	}{
		{0, 1}, {255, 1}, {NativeRequestData, 0}, {NativeRequestData, MaxInitialBytes + 1},
		{NativeRequestPermission, 0}, {NativeRequestPermission, MaxNativePermissionBytes + 1}, {NativeRequestEnded, 1},
	} {
		reader := &headerOnlyReader{header: bytes.NewReader(binary.BigEndian.AppendUint32([]byte{byte(test.kind)}, test.length))}
		if _, err := ReadNativeRequestFrame(reader); !errors.Is(err, ErrNativeRequest) || reader.payloadReads != 0 {
			t.Fatal("invalid native length reached payload reading", err)
		}
	}
	var wire bytes.Buffer
	for _, frame := range []NativeRequestFrame{
		{Kind: NativeRequestData, Data: make([]byte, MaxInitialBytes+1)},
		{Kind: NativeRequestData, Data: []byte("app bytes"), Permission: nativeTestEntry().Permission},
		{Kind: NativeRequestPermission},
		{Kind: NativeRequestEnded, Data: []byte("app bytes")},
	} {
		if err := WriteNativeRequestFrame(&wire, frame); !errors.Is(err, ErrNativeRequest) || wire.Len() != 0 {
			t.Fatal("invalid native request was written", err)
		}
	}
	if err := WriteNativeRequestFrame(io.Discard, NativeRequestFrame{Kind: NativeRequestData, Data: make([]byte, MaxInitialBytes)}); err != nil {
		t.Fatal(err)
	}
}

func FuzzNativeRequestFrames(f *testing.F) {
	f.Add([]byte{1, 0, 0, 0, 1, 0x16})
	f.Add([]byte{3, 0, 0, 0, 0})
	var renewal bytes.Buffer
	if err := WriteNativeRequestFrame(&renewal, NativeRequestFrame{Kind: NativeRequestPermission, Permission: nativeTestEntry().Permission}); err != nil {
		f.Fatal(err)
	}
	f.Add(renewal.Bytes())
	f.Fuzz(func(t *testing.T, data []byte) {
		frame, err := ReadNativeRequestFrame(bytes.NewReader(data))
		if err == nil {
			if err := WriteNativeRequestFrame(io.Discard, frame); err != nil {
				t.Fatal("decoded request could not be written", err)
			}
		}
	})
}
