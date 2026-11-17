package tunnelv1

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func TestOpeningFramingAndEveryPartialWrite(t *testing.T) {
	h, err := ReadServiceForwardingHeader(bytes.NewReader(goldenWire(t, "service-forwarding-header")))
	if err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	if n, err := WriteServiceOpening(&wire, h); err != nil || n != 0 {
		t.Fatalf("opening count=%d: %v", n, err)
	}
	want := append(goldenWire(t, "service-forwarding-header"), binary.BigEndian.AppendUint32(nil, 0)...)
	if !bytes.Equal(wire.Bytes(), want) {
		t.Fatal("opening changed the header or length-prefixed bytes")
	}
	reader := bytes.NewReader(append(bytes.Clone(want), []byte("raw continuation")...))
	got, err := ReadServiceForwardingHeader(reader)
	if err != nil || !bytes.Equal(wireJSON(t, got), wireJSON(t, h)) {
		t.Fatalf("opening decode: %v", err)
	}
	data, err := ReadInitialBytes(reader)
	if err != nil || len(data) != 0 {
		t.Fatalf("unexpected initial visitor bytes: %v", err)
	}
	rest, _ := io.ReadAll(reader)
	if string(rest) != "raw continuation" {
		t.Fatalf("overconsumed: %q", rest)
	}
	cause := errors.New("opening write failed")
	for n := 0; n <= len(want); n++ {
		for _, failure := range []error{cause, nil} {
			writer := openingCutWriter{count: n, err: failure}
			got, err := WriteServiceOpening(writer, h)
			if got != 0 {
				t.Fatalf("partial write %d counted %d visitor bytes", n, got)
			}
			if failure != nil && !errors.Is(err, failure) || failure == nil && n < len(want) && !errors.Is(err, io.ErrShortWrite) || failure == nil && n == len(want) && err != nil {
				t.Fatalf("partial write %d: %v", n, err)
			}
		}
	}
	for n := 0; n < len(want); n++ {
		reader := bytes.NewReader(want[:n])
		if _, err := ReadServiceForwardingHeader(reader); err == nil {
			if _, err := ReadInitialBytes(reader); err == nil {
				t.Fatalf("accepted truncation %d", n)
			}
		}
	}
}

type openingCutWriter struct {
	count int
	err   error
}

func (w openingCutWriter) Write([]byte) (int, error) { return w.count, w.err }

func TestOpeningInitialBounds(t *testing.T) {
	for _, size := range []int{0, MaxInitialBytes, MaxInitialBytes + 1} {
		var wire bytes.Buffer
		initial := bytes.Repeat([]byte{0xff}, size)
		n, err := writeOpening(&wire, initial, func(w io.Writer) error {
			return WriteServiceForwardingHeader(w, publicServiceAdmissionFixture())
		})
		if size > MaxInitialBytes {
			if !errors.Is(err, ErrOpeningSize) || n != 0 || wire.Len() != 0 {
				t.Fatal("oversized opening wrote bytes", n, err)
			}
			continue
		}
		if err != nil || n != size {
			t.Fatal(n, err)
		}
		if _, err := ReadServiceForwardingHeader(&wire); err != nil {
			t.Fatal(err)
		}
		data, err := ReadInitialBytes(&wire)
		if err != nil || !bytes.Equal(data, initial) {
			t.Fatal("bounded opening lost bytes", err)
		}
	}
	r := &headerOnlyReader{header: bytes.NewReader(binary.BigEndian.AppendUint32(nil, MaxInitialBytes+1))}
	if _, err := ReadInitialBytes(r); !errors.Is(err, ErrOpeningSize) || r.payloadReads != 0 {
		t.Fatal("oversized block read payload", err)
	}
}
