package tunnelv1

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

const MaxInitialBytes = 64 << 10

var ErrOpeningSize = errors.New("initial visitor bytes exceed the opening limit")

// an opening is a bounded header and length-prefixed initial block, followed
// by raw request bytes. the returned count excludes the trusted PROXY metadata.
func WriteVisitorOpening(w io.Writer, h VisitorStreamHeader, initial []byte) (int, error) {
	return writeOpening(w, nil, initial, func(w io.Writer) error { return WriteVisitorStreamHeader(w, h) })
}

func ReadVisitorOpening(r io.Reader) (VisitorStreamHeader, []byte, error) {
	h, err := ReadVisitorStreamHeader(r)
	if err != nil {
		return h, nil, err
	}
	initial, err := ReadInitialBytes(r)
	return h, initial, err
}

func WriteForwardingOpening(w io.Writer, h InternalForwardingHeader, proxy, initial []byte) (int, error) {
	return writeOpening(w, proxy, initial, func(w io.Writer) error { return WriteInternalForwardingHeader(w, h) })
}

func ReadForwardingOpening(r io.Reader) (InternalForwardingHeader, *ServiceForwardingHeader, []byte, error) {
	h, service, err := ReadForwardingHeader(r)
	if err != nil {
		return h, service, nil, err
	}
	initial, err := ReadInitialBytes(r)
	return h, service, initial, err
}

func WriteServiceOpening(w io.Writer, h ServiceForwardingHeader) (int, error) {
	return writeOpening(w, nil, nil, func(w io.Writer) error { return WriteServiceForwardingHeader(w, h) })
}

func writeOpening(w io.Writer, proxy, initial []byte, header func(io.Writer) error) (int, error) {
	if len(proxy) > MaxInitialBytes || len(initial) > MaxInitialBytes-len(proxy) {
		return 0, ErrOpeningSize
	}
	var frame bytes.Buffer
	if err := header(&frame); err != nil {
		return 0, err
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(proxy)+len(initial)))
	frame.Write(length[:])
	frame.Write(proxy)
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
