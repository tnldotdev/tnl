package tunnelv1

import (
	"bytes"
	"io"
	"testing"
)

func FuzzReadFrames(f *testing.F) {
	for kind, reader := range frameReaders {
		f.Add(uint8(kind), goldenWire(f, reader.name), uint8(1))
		f.Add(uint8(kind), append(goldenWire(f, reader.name), 0, 0, 0, 1, 0xff), uint8(1))
		f.Add(uint8(kind), []byte{}, uint8(1))
		f.Add(uint8(kind), []byte{0, 0, 0, 0}, uint8(2))
	}
	f.Fuzz(func(t *testing.T, kind uint8, input []byte, readSize uint8) {
		reader := &limitedReader{Reader: bytes.NewReader(input), Size: int(readSize%32) + 1}
		_ = frameReaders[int(kind)%len(frameReaders)].read(reader)
		initial, err := ReadInitialBytes(bytes.NewReader(input))
		if err == nil && (len(initial) > MaxInitialBytes || len(input) < 4+len(initial)) {
			t.Fatal("unbounded opening")
		}
		opening := &limitedReader{Reader: bytes.NewReader(input), Size: int(readSize%32) + 1}
		if kind%2 == 0 {
			_, _, _ = ReadVisitorOpening(opening)
		} else {
			_, _, _, _ = ReadForwardingOpening(opening)
		}
	})
}

type limitedReader struct {
	Reader io.Reader
	Size   int
}

func (r *limitedReader) Read(p []byte) (int, error) {
	if len(p) > r.Size {
		p = p[:r.Size]
	}
	return r.Reader.Read(p)
}
