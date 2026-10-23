package tunnelv1

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

// native request framing keeps permission renewal outside visitor TLS and native
// protocol bytes. permission frames contain no application data and grant no
// authority until the receiving policy owner verifies their signed key proof.
type NativeRequestKind uint8

const (
	NativeRequestData NativeRequestKind = iota + 1
	NativeRequestPermission
	NativeRequestEnded
)

const MaxNativePermissionBytes = 4 << 10

var ErrNativeRequest = errors.New("tunnelv1: invalid native request frame")

type NativeRequestFrame struct {
	Kind       NativeRequestKind
	Data       []byte
	Permission NativeVisitorPermission
}

type NativeRequestHeader struct {
	Kind   NativeRequestKind
	Length uint32
}

func ParseNativeRequestHeader(header []byte) (NativeRequestHeader, error) {
	if len(header) != 5 {
		return NativeRequestHeader{}, ErrNativeRequest
	}
	h := NativeRequestHeader{Kind: NativeRequestKind(header[0]), Length: binary.BigEndian.Uint32(header[1:])}
	switch h.Kind {
	case NativeRequestData:
		if h.Length == 0 || h.Length > MaxInitialBytes {
			return NativeRequestHeader{}, ErrNativeRequest
		}
	case NativeRequestPermission:
		if h.Length == 0 || h.Length > MaxNativePermissionBytes {
			return NativeRequestHeader{}, ErrNativeRequest
		}
	case NativeRequestEnded:
		if h.Length != 0 {
			return NativeRequestHeader{}, ErrNativeRequest
		}
	default:
		return NativeRequestHeader{}, ErrNativeRequest
	}
	return h, nil
}

func WriteNativeRequestFrame(w io.Writer, f NativeRequestFrame) error {
	var frame bytes.Buffer
	frame.WriteByte(byte(f.Kind))
	switch f.Kind {
	case NativeRequestData:
		if len(f.Data) == 0 || len(f.Data) > MaxInitialBytes || f.Permission != (NativeVisitorPermission{}) {
			return ErrNativeRequest
		}
		frame.Write(binary.BigEndian.AppendUint32(nil, uint32(len(f.Data))))
		frame.Write(f.Data)
	case NativeRequestPermission:
		if len(f.Data) != 0 || !f.Permission.valid() {
			return ErrNativeRequest
		}
		if err := writeJSONFrame(&frame, f.Permission, MaxNativePermissionBytes); err != nil {
			return err
		}
	case NativeRequestEnded:
		if len(f.Data) != 0 || f.Permission != (NativeVisitorPermission{}) {
			return ErrNativeRequest
		}
		frame.Write([]byte{0, 0, 0, 0})
	default:
		return ErrNativeRequest
	}
	n, err := w.Write(frame.Bytes())
	if err == nil && n != frame.Len() {
		return io.ErrShortWrite
	}
	return err
}

func ReadNativeRequestFrame(r io.Reader) (NativeRequestFrame, error) {
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return NativeRequestFrame{}, err
	}
	parsed, err := ParseNativeRequestHeader(header[:])
	if err != nil {
		return NativeRequestFrame{}, err
	}
	f := NativeRequestFrame{Kind: parsed.Kind}
	size := parsed.Length
	switch f.Kind {
	case NativeRequestData:
		if size == 0 || size > MaxInitialBytes {
			return NativeRequestFrame{}, ErrNativeRequest
		}
		f.Data = make([]byte, size)
		if _, err := io.ReadFull(r, f.Data); err != nil {
			return NativeRequestFrame{}, err
		}
	case NativeRequestPermission:
		if size == 0 || size > MaxNativePermissionBytes {
			return NativeRequestFrame{}, ErrNativeRequest
		}
		if err := readJSONFrame(io.MultiReader(bytes.NewReader(header[1:]), r), &f.Permission, MaxNativePermissionBytes); err != nil || !f.Permission.valid() {
			return NativeRequestFrame{}, ErrNativeRequest
		}
	case NativeRequestEnded:
		if size != 0 {
			return NativeRequestFrame{}, ErrNativeRequest
		}
	default:
		return NativeRequestFrame{}, ErrNativeRequest
	}
	return f, nil
}
