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

func TestReturnFrameGoldenAndBounds(t *testing.T) {
	for _, invalid := range []ReturnFrame{{Kind: ReturnAccepted, Code: Internal}, {Kind: ReturnRejected}, {Kind: ReturnRejected, Code: "unknown"}} {
		var out bytes.Buffer
		if err := WriteReturnFrame(&out, invalid); err == nil || out.Len() != 0 {
			t.Fatal("invalid response wrote bytes")
		}
	}
	for _, test := range []struct {
		frame ReturnFrame
		hex   string
	}{
		{ReturnFrame{Kind: ReturnAccepted}, "0100000000"},
		{ReturnFrame{Kind: ReturnRejected, Code: Unavailable}, "020000000b756e617661696c61626c65"},
		{ReturnFrame{Kind: ReturnData, Data: []byte("TLS")}, "0400000003544c53"},
		{ReturnFrame{Kind: ReturnEnded}, "0500000000"},
	} {
		var out bytes.Buffer
		if err := WriteReturnFrame(&out, test.frame); err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(out.Bytes()) != test.hex {
			t.Fatalf("wire %x, want %s", out.Bytes(), test.hex)
		}
		wire := bytes.Clone(out.Bytes())
		got, err := ReadReturnFrame(&out)
		if err != nil || !reflect.DeepEqual(got, test.frame) {
			t.Fatal(got, err)
		}
		for n := range len(wire) {
			if _, err := ReadReturnFrame(bytes.NewReader(wire[:n])); err == nil {
				t.Fatalf("accepted truncation %d", n)
			}
		}
		for _, short := range []bool{false, true} {
			cause := errors.New("write failed")
			w := &failingWriter{failAt: 1, short: short, failure: cause}
			want := cause
			if short {
				want = io.ErrShortWrite
			}
			if err := WriteReturnFrame(w, test.frame); !errors.Is(err, want) {
				t.Fatal(err)
			}
		}
	}
	for _, test := range []struct {
		kind ReturnFrameKind
		size uint32
	}{
		{ReturnAccepted, 1}, {ReturnEnded, 1}, {ReturnRejected, 0}, {ReturnRejected, 129},
		{ReturnFrameKind(3), 0}, {ReturnFrameKind(3), MaxHeaderBytes + 1}, {ReturnData, 0}, {ReturnData, MaxStreamDataBytes + 1}, {99, 1},
	} {
		header := binary.BigEndian.AppendUint32([]byte{byte(test.kind)}, test.size)
		r := &headerOnlyReader{header: bytes.NewReader(header)}
		if _, err := ReadReturnFrame(r); !errors.Is(err, ErrReturnFrame) || r.payloadReads != 0 {
			t.Fatal("invalid length read payload", err)
		}
	}
	for _, size := range []int{1, MaxStreamDataBytes} {
		var wire bytes.Buffer
		data := bytes.Repeat([]byte{0x80}, size)
		if err := WriteReturnFrame(&wire, ReturnFrame{Kind: ReturnData, Data: data}); err != nil {
			t.Fatal(err)
		}
		wire.WriteString("next")
		got, err := ReadReturnFrame(&wire)
		if err != nil || !bytes.Equal(got.Data, data) || wire.String() != "next" {
			t.Fatal("data bound or consumption", err)
		}
	}
}

func FuzzReturnFrame(f *testing.F) {
	f.Add([]byte{1, 0, 0, 0, 0})
	f.Add([]byte{4, 0, 0, 0, 1, 'x'})
	f.Fuzz(func(t *testing.T, wire []byte) {
		frame, err := ReadReturnFrame(bytes.NewReader(wire))
		if err != nil {
			return
		}
		var out bytes.Buffer
		if err := WriteReturnFrame(&out, frame); err != nil {
			t.Fatal(err)
		}
		got, err := ReadReturnFrame(&out)
		if err != nil || !reflect.DeepEqual(got, frame) {
			t.Fatal("frame did not round trip", err)
		}
	})
}
