package tunnelv1

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

// VisitorSubject is the visitor principal, independent of publisher identity.
// exactly one variant is populated; a workload never enrolls a human device.
type VisitorSubject struct {
	Kind              string `json:"kind"`
	IdentityID        string `json:"identity_id,omitempty"`
	DeviceID          string `json:"device_id,omitempty"`
	WorkloadSessionID string `json:"workload_session_id,omitempty"`
}

const (
	VisitorHumanDevice     = "human_device"
	VisitorWorkloadSession = "workload_session"
)

var ErrInvalidVisitorSubject = errors.New("invalid visitor subject")

// UnmarshalJSON rejects fields from another variant even when empty. the same
// tagged contract is used in hello, acceptance and forwarding frames.
func (s *VisitorSubject) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil {
		return ErrInvalidVisitorSubject
	}
	type plain VisitorSubject
	var value plain
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil {
		return ErrInvalidVisitorSubject
	}
	r := VisitorSubject(value)
	if r.Validate() != nil || r.Kind == VisitorHumanDevice && len(fields) != 3 || r.Kind == VisitorWorkloadSession && len(fields) != 2 {
		return ErrInvalidVisitorSubject
	}
	*s = r
	return nil
}

func (s VisitorSubject) Validate() error {
	switch s.Kind {
	case VisitorHumanDevice:
		if opaqueid.Valid(s.IdentityID, opaqueid.IdentityPrefix) && opaqueid.Valid(s.DeviceID, opaqueid.VisitorDevicePrefix) && s.WorkloadSessionID == "" {
			return nil
		}
	case VisitorWorkloadSession:
		if opaqueid.Valid(s.WorkloadSessionID, "wls_") && s.IdentityID == "" && s.DeviceID == "" {
			return nil
		}
	}
	return ErrInvalidVisitorSubject
}
