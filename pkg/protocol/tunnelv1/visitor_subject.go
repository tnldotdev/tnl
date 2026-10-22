package tunnelv1

import (
	"bytes"
	"crypto/sha256"
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

// VisitorConnectorClaim is the subject-aware private authentication source
// contract. transport adapters carry this proof without inventing device IDs.
type VisitorConnectorClaim struct {
	Subject    VisitorSubject `json:"subject"`
	ServiceID  string         `json:"private_service_id"`
	SessionID  string         `json:"connector_session_id"`
	Credential string         `json:"session_credential"`
	Nonce      []byte         `json:"nonce"`
	Signature  []byte         `json:"signature"`
}

func (c VisitorConnectorClaim) Digest() ([]byte, error) {
	if c.Subject.Validate() != nil || !opaqueid.Valid(c.ServiceID, opaqueid.PrivateServicePrefix) || !opaqueid.Valid(c.SessionID, opaqueid.PrivateConnectorSessionPrefix) || len(c.Nonce) != 32 || len(c.Credential) != 43 || !validCredential(c.Credential) {
		return nil, errors.New("invalid visitor connector claim")
	}
	data, _ := json.Marshal([]any{"tnl-visitor-connector/v1", c.Subject, c.ServiceID, c.SessionID, c.Credential, c.Nonce})
	digest := sha256.Sum256(data)
	return digest[:], nil
}
