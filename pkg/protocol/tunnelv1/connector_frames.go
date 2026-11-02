package tunnelv1

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

// connector request framing keeps permission renewal outside visitor TLS and native
// protocol bytes. permission frames contain no application data and grant no
// authority until the receiving policy owner verifies their signed key proof.
type ConnectorRequestKind uint8

const (
	ConnectorRequestData ConnectorRequestKind = iota + 1
	ConnectorRequestPermission
	ConnectorRequestEnded
)

const MaxConnectorPermissionBytes = 4 << 10

var ErrConnectorRequest = errors.New("tunnelv1: invalid connector request frame")

type ConnectorRequestFrame struct {
	Kind       ConnectorRequestKind
	Data       []byte
	Permission ConnectorVisitorPermission
}

type ConnectorRequestHeader struct {
	Kind   ConnectorRequestKind
	Length uint32
}

func ParseConnectorRequestHeader(header []byte) (ConnectorRequestHeader, error) {
	if len(header) != 5 {
		return ConnectorRequestHeader{}, ErrConnectorRequest
	}
	h := ConnectorRequestHeader{Kind: ConnectorRequestKind(header[0]), Length: binary.BigEndian.Uint32(header[1:])}
	switch h.Kind {
	case ConnectorRequestData:
		if h.Length == 0 || h.Length > MaxInitialBytes {
			return ConnectorRequestHeader{}, ErrConnectorRequest
		}
	case ConnectorRequestPermission:
		if h.Length == 0 || h.Length > MaxConnectorPermissionBytes {
			return ConnectorRequestHeader{}, ErrConnectorRequest
		}
	case ConnectorRequestEnded:
		if h.Length != 0 {
			return ConnectorRequestHeader{}, ErrConnectorRequest
		}
	default:
		return ConnectorRequestHeader{}, ErrConnectorRequest
	}
	return h, nil
}

func WriteConnectorRequestFrame(w io.Writer, f ConnectorRequestFrame) error {
	var frame bytes.Buffer
	frame.WriteByte(byte(f.Kind))
	switch f.Kind {
	case ConnectorRequestData:
		if len(f.Data) == 0 || len(f.Data) > MaxInitialBytes || f.Permission != (ConnectorVisitorPermission{}) {
			return ErrConnectorRequest
		}
		frame.Write(binary.BigEndian.AppendUint32(nil, uint32(len(f.Data))))
		frame.Write(f.Data)
	case ConnectorRequestPermission:
		if len(f.Data) != 0 || !f.Permission.valid() {
			return ErrConnectorRequest
		}
		if err := writeJSONFrame(&frame, f.Permission, MaxConnectorPermissionBytes); err != nil {
			return err
		}
	case ConnectorRequestEnded:
		if len(f.Data) != 0 || f.Permission != (ConnectorVisitorPermission{}) {
			return ErrConnectorRequest
		}
		frame.Write([]byte{0, 0, 0, 0})
	default:
		return ErrConnectorRequest
	}
	n, err := w.Write(frame.Bytes())
	if err == nil && n != frame.Len() {
		return io.ErrShortWrite
	}
	return err
}

func ReadConnectorRequestFrame(r io.Reader) (ConnectorRequestFrame, error) {
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return ConnectorRequestFrame{}, err
	}
	parsed, err := ParseConnectorRequestHeader(header[:])
	if err != nil {
		return ConnectorRequestFrame{}, err
	}
	f := ConnectorRequestFrame{Kind: parsed.Kind}
	size := parsed.Length
	switch f.Kind {
	case ConnectorRequestData:
		if size == 0 || size > MaxInitialBytes {
			return ConnectorRequestFrame{}, ErrConnectorRequest
		}
		f.Data = make([]byte, size)
		if _, err := io.ReadFull(r, f.Data); err != nil {
			return ConnectorRequestFrame{}, err
		}
	case ConnectorRequestPermission:
		if size == 0 || size > MaxConnectorPermissionBytes {
			return ConnectorRequestFrame{}, ErrConnectorRequest
		}
		if err := readJSONFrame(io.MultiReader(bytes.NewReader(header[1:]), r), &f.Permission, MaxConnectorPermissionBytes); err != nil || !f.Permission.valid() {
			return ConnectorRequestFrame{}, ErrConnectorRequest
		}
	case ConnectorRequestEnded:
		if size != 0 {
			return ConnectorRequestFrame{}, ErrConnectorRequest
		}
	default:
		return ConnectorRequestFrame{}, ErrConnectorRequest
	}
	return f, nil
}
