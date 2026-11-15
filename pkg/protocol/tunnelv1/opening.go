package tunnelv1

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

const MaxInitialBytes = 64 << 10

var ErrOpeningSize = errors.New("initial visitor bytes exceed the opening limit")

// an opening is a bounded service header and length-prefixed initial block,
// followed by raw visitor bytes. public service openings confirm before bytes.
func WriteServiceOpening(w io.Writer, h ServiceForwardingHeader) (int, error) {
	return writeOpening(w, nil, func(w io.Writer) error { return WriteServiceForwardingHeader(w, h) })
}

func writeOpening(w io.Writer, initial []byte, header func(io.Writer) error) (int, error) {
	if len(initial) > MaxInitialBytes {
		return 0, ErrOpeningSize
	}
	var frame bytes.Buffer
	if err := header(&frame); err != nil {
		return 0, err
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(initial)))
	frame.Write(length[:])
	boundary := frame.Len()
	frame.Write(initial)
	n, err := w.Write(frame.Bytes())
	if n < 0 || n > frame.Len() {
		return len(initial), io.ErrShortWrite
	}
	if err == nil && n != frame.Len() {
		err = io.ErrShortWrite
	}
	return max(0, n-boundary), err
}

func ReadInitialBytes(r io.Reader) ([]byte, error) {
	var length [4]byte
	if _, err := io.ReadFull(r, length[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(length[:])
	if size > MaxInitialBytes {
		return nil, ErrOpeningSize
	}
	initial := make([]byte, size)
	_, err := io.ReadFull(r, initial)
	return initial, err
}
