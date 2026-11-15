package tunnelv1

import (
	"encoding/binary"
	"errors"
	"io"
)

const MaxStreamDataBytes = 64 << 10

type ReturnFrameKind byte

const (
	ReturnAccepted ReturnFrameKind = 1
	ReturnRejected ReturnFrameKind = 2
	ReturnData     ReturnFrameKind = 4
	ReturnEnded    ReturnFrameKind = 5
)

var ErrReturnFrame = errors.New("visitor return frame is invalid")

// ReturnFrame is outer tunnel framing, never visitor TLS plaintext.
type ReturnFrame struct {
	Kind ReturnFrameKind
	Code ErrorCode
	Data []byte
}

func (f ReturnFrame) Validate() error {
	if f.Kind != ReturnRejected && f.Code != "" || f.Kind != ReturnData && len(f.Data) != 0 {
		return ErrReturnFrame
	}
	switch f.Kind {
	case ReturnAccepted, ReturnEnded:
	case ReturnRejected:
		if !validErrorCode(f.Code) {
			return ErrReturnFrame
		}
	case ReturnData:
		if len(f.Data) < 1 || len(f.Data) > MaxStreamDataBytes {
			return ErrReturnFrame
		}
	default:
		return ErrReturnFrame
	}
	return nil
}

func WriteReturnFrame(w io.Writer, f ReturnFrame) error {
	if err := f.Validate(); err != nil {
		return err
	}
	var payload []byte
	switch f.Kind {
	case ReturnRejected:
		payload = []byte(f.Code)
	case ReturnData:
		payload = f.Data
	}
	wire := make([]byte, 5+len(payload))
	wire[0] = byte(f.Kind)
	binary.BigEndian.PutUint32(wire[1:5], uint32(len(payload)))
	copy(wire[5:], payload)
	n, err := w.Write(wire)
	if err == nil && n != len(wire) {
		err = io.ErrShortWrite
	}
	return err
}

func ReadReturnFrame(r io.Reader) (ReturnFrame, error) {
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return ReturnFrame{}, err
	}
	f := ReturnFrame{Kind: ReturnFrameKind(header[0])}
	length := binary.BigEndian.Uint32(header[1:])
	switch f.Kind {
	case ReturnAccepted, ReturnEnded:
		if length != 0 {
			return f, ErrReturnFrame
		}
	case ReturnRejected:
		if length < 1 || length > 128 {
			return f, ErrReturnFrame
		}
	case ReturnData:
		if length < 1 || length > MaxStreamDataBytes {
			return f, ErrReturnFrame
		}
	default:
		return f, ErrReturnFrame
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return f, err
	}
	switch f.Kind {
	case ReturnRejected:
		f.Code = ErrorCode(payload)
	case ReturnData:
		f.Data = payload
	}
	return f, f.Validate()
}
