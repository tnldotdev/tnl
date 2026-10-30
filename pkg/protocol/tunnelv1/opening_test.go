package tunnelv1

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func TestOpeningFramingAndEveryPartialWrite(t *testing.T) {
	h, err := ReadInternalForwardingHeader(bytes.NewReader(goldenWire(t, "internal-forwarding-header")))
	if err != nil {
		t.Fatal(err)
	}
	proxy, initial := []byte("proxy metadata"), []byte("visitor TLS")
	var wire bytes.Buffer
	if n, err := WriteForwardingOpening(&wire, h, proxy, initial); err != nil || n != len(initial) {
		t.Fatalf("opening count=%d: %v", n, err)
	}
	want := append(goldenWire(t, "internal-forwarding-header"), binary.BigEndian.AppendUint32(nil, uint32(len(proxy)+len(initial)))...)
	want = append(want, proxy...)
	want = append(want, initial...)
	if !bytes.Equal(wire.Bytes(), want) {
		t.Fatal("opening changed the header or length-prefixed bytes")
	}
	reader := bytes.NewReader(append(bytes.Clone(want), []byte("raw continuation")...))
	got, service, data, err := ReadForwardingOpening(reader)
	if err != nil || service != nil || got != h || !bytes.Equal(data, append(bytes.Clone(proxy), initial...)) {
		t.Fatalf("opening decode: %v", err)
	}
	rest, _ := io.ReadAll(reader)
	if string(rest) != "raw continuation" {
		t.Fatalf("overconsumed: %q", rest)
	}
	cause := errors.New("opening write failed")
	boundary := len(want) - len(initial)
	for n := 0; n <= len(want); n++ {
		for _, failure := range []error{cause, nil} {
			writer := openingCutWriter{count: n, err: failure}
			got, err := WriteForwardingOpening(writer, h, proxy, initial)
			if got != max(0, n-boundary) {
				t.Fatalf("partial write %d counted %d visitor bytes", n, got)
			}
			if failure != nil && !errors.Is(err, failure) || failure == nil && n < len(want) && !errors.Is(err, io.ErrShortWrite) || failure == nil && n == len(want) && err != nil {
				t.Fatalf("partial write %d: %v", n, err)
			}
		}
	}
	for n := 0; n < len(want); n++ {
		if _, _, _, err := ReadForwardingOpening(bytes.NewReader(want[:n])); err == nil {
			t.Fatalf("accepted truncation %d", n)
		}
	}
}

type openingCutWriter struct {
	count int
	err   error
}

func (w openingCutWriter) Write([]byte) (int, error) { return w.count, w.err }

func TestOpeningInitialBounds(t *testing.T) {
	h, err := ReadVisitorStreamHeader(bytes.NewReader(goldenWire(t, "visitor-stream-header")))
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{0, MaxInitialBytes, MaxInitialBytes + 1} {
		var wire bytes.Buffer
		initial := bytes.Repeat([]byte{0xff}, size)
		n, err := WriteVisitorOpening(&wire, h, initial)
		if size > MaxInitialBytes {
			if !errors.Is(err, ErrOpeningSize) || n != 0 || wire.Len() != 0 {
				t.Fatal("oversized opening wrote bytes", n, err)
			}
			continue
		}
		if err != nil || n != size {
			t.Fatal(n, err)
		}
		got, data, err := ReadVisitorOpening(&wire)
		if err != nil || got != h || !bytes.Equal(data, initial) {
			t.Fatal("bounded opening lost bytes", err)
		}
	}
	r := &headerOnlyReader{header: bytes.NewReader(binary.BigEndian.AppendUint32(nil, MaxInitialBytes+1))}
	if _, err := ReadInitialBytes(r); !errors.Is(err, ErrOpeningSize) || r.payloadReads != 0 {
		t.Fatal("oversized block read payload", err)
	}
}
