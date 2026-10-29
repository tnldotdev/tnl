package tunnelv1

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
)

const MaxStreamDataBytes = 64 << 10

type ReturnFrameKind byte

const (
	ReturnAccepted ReturnFrameKind = 1
	ReturnRejected ReturnFrameKind = 2
	ReturnPromoted ReturnFrameKind = 3
	ReturnData     ReturnFrameKind = 4
	ReturnEnded    ReturnFrameKind = 5
)

var ErrReturnFrame = errors.New("visitor return frame is invalid")

// ReturnFrame is outer tunnel framing, never visitor TLS plaintext. promotion
// is ordered with the response bytes it permits on this exact visitor stream.
type ReturnFrame struct {
	Kind      ReturnFrameKind
	Code      ErrorCode
	Promotion AdmissionHeader
	Data      []byte
}

func (f ReturnFrame) Validate() error {
	if f.Kind != ReturnRejected && f.Code != "" || f.Kind != ReturnPromoted && f.Promotion != (AdmissionHeader{}) || f.Kind != ReturnData && len(f.Data) != 0 {
		return ErrReturnFrame
	}
	switch f.Kind {
	case ReturnAccepted, ReturnEnded:
	case ReturnRejected:
		if !validErrorCode(f.Code) {
			return ErrReturnFrame
		}
	case ReturnPromoted:
		if f.Promotion.Validate() != nil {
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
	case ReturnPromoted:
		var err error
		payload, err = json.Marshal(f.Promotion)
		if err != nil {
			return err
		}
		if len(payload) > MaxHeaderBytes {
			return ErrReturnFrame
		}
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
	case ReturnPromoted:
		if length < 1 || length > MaxHeaderBytes {
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
	case ReturnPromoted:
		decoder := json.NewDecoder(bytes.NewReader(payload))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&f.Promotion); err != nil {
			return f, err
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return f, ErrReturnFrame
		}
	case ReturnData:
		f.Data = payload
	}
	return f, f.Validate()
}
