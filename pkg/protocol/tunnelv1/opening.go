package tunnelv1

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

const MaxInitialBytes = 64 << 10

func WriteConnectorVisitorOpening(w io.Writer, h ConnectorVisitorEntry, initial []byte) (bool, error) {
	return writeOpening(w, nil, initial, func(w io.Writer) error { return WriteConnectorVisitorEntry(w, h) })
}

func ReadConnectorVisitorOpening(r io.Reader) (ConnectorVisitorEntry, []byte, error) {
	h, err := ReadConnectorVisitorEntry(r)
	if err != nil {
		return h, nil, err
	}
	initial, err := ReadInitialBytes(r)
	return h, initial, err
}

// an opening is one bounded header followed by a length-prefixed initial byte
// block. subsequent request bytes are raw. the sender does not wait for a reply.
func WriteVisitorOpening(w io.Writer, h VisitorStreamHeader, initial []byte) (bool, error) {
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

func WriteForwardingOpening(w io.Writer, h InternalForwardingHeader, proxy, initial []byte) (bool, error) {
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

func WriteServiceOpening(w io.Writer, h ServiceForwardingHeader, initial []byte) (bool, error) {
	return writeOpening(w, nil, initial, func(w io.Writer) error { return WriteServiceForwardingHeader(w, h) })
}

func ReadServiceOpening(r io.Reader) (ServiceForwardingHeader, []byte, error) {
	h, err := ReadServiceForwardingHeader(r)
	if err != nil {
		return h, nil, err
	}
	initial, err := ReadInitialBytes(r)
	return h, initial, err
}

func writeOpening(w io.Writer, proxy, initial []byte, header func(io.Writer) error) (bool, error) {
	if len(proxy) > MaxInitialBytes || len(initial) > MaxInitialBytes-len(proxy) {
		return false, errors.New("initial visitor bytes exceed the opening limit")
	}
	var frame bytes.Buffer
	if err := header(&frame); err != nil {
		return false, err
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(proxy)+len(initial)))
	frame.Write(length[:])
	frame.Write(proxy)
	boundary := frame.Len()
	frame.Write(initial)
	// one write combines metadata and initial bytes. a short write still reports
	// whether any visitor byte crossed the no-retry boundary.
	n, err := w.Write(frame.Bytes())
	if n < 0 || n > frame.Len() {
		return true, io.ErrShortWrite
	}
	if err == nil && n != frame.Len() {
		err = io.ErrShortWrite
	}
	return n > boundary, err
}

func ReadInitialBytes(r io.Reader) ([]byte, error) {
	var length [4]byte
	if _, err := io.ReadFull(r, length[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(length[:])
	if size > MaxInitialBytes {
		return nil, errors.New("initial visitor bytes exceed the opening limit")
	}
	initial := make([]byte, size)
	_, err := io.ReadFull(r, initial)
	return initial, err
}
