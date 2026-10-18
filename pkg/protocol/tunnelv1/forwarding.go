package tunnelv1

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// ReadForwardingHeader dispatches one bounded frame without consuming any
// following visitor bytes. private and public selectors cannot be combined.
func ReadForwardingHeader(reader io.Reader) (InternalForwardingHeader, *PrivateForwardingHeader, error) {
	var raw json.RawMessage
	if err := readJSONFrame(reader, &raw, MaxPrivateHeaderBytes); err != nil {
		return InternalForwardingHeader{}, nil, err
	}
	var kind struct {
		Kind StreamKind `json:"kind"`
	}
	if err := json.Unmarshal(raw, &kind); err != nil {
		return InternalForwardingHeader{}, nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if kind.Kind == PrivateForwardingStream {
		var header PrivateForwardingHeader
		if err := decoder.Decode(&header); err != nil {
			return InternalForwardingHeader{}, nil, err
		}
		return InternalForwardingHeader{}, &header, header.Validate()
	}
	if len(raw) > MaxHeaderBytes {
		return InternalForwardingHeader{}, nil, errors.New("tunnelv1: public forwarding header too large")
	}
	var header InternalForwardingHeader
	if err := decoder.Decode(&header); err != nil {
		return header, nil, err
	}
	return header, nil, header.Validate()
}
