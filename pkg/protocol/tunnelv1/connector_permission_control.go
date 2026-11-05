package tunnelv1

import (
	"errors"
	"io"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

const MaxConnectorPermissionBytes = 4 << 10

// the first inner bidirectional stream negotiates this implementation before
// signed application openings. older request-framed peers cannot acknowledge it.
const ConnectorPermissionControl StreamKind = "connector_permission_control"
const ConnectorPermissionControlAccepted StreamKind = "connector_permission_control_accepted"

type connectorPermissionHello struct {
	ProtocolVersion      uint32     `json:"protocol_version"`
	Kind                 StreamKind `json:"kind"`
	ApplicationAdmission bool       `json:"application_admission"`
}

func WriteConnectorPermissionHello(w io.Writer, accepted bool) error {
	kind := ConnectorPermissionControl
	if accepted {
		kind = ConnectorPermissionControlAccepted
	}
	return writeJSONFrame(w, connectorPermissionHello{ProtocolVersion: Version, Kind: kind, ApplicationAdmission: true}, 256)
}

func ReadConnectorPermissionHello(r io.Reader, accepted bool) error {
	var hello connectorPermissionHello
	kind := ConnectorPermissionControl
	if accepted {
		kind = ConnectorPermissionControlAccepted
	}
	if err := readJSONFrame(r, &hello, 256); err != nil {
		return err
	}
	if hello.ProtocolVersion != Version || hello.Kind != kind || !hello.ApplicationAdmission {
		return ErrConnectorPermissionUpdate
	}
	return nil
}

var ErrConnectorPermissionUpdate = errors.New("tunnelv1: invalid connector permission update")

// ConnectorPermissionUpdate travels only on the retained inner QUIC session's
// dedicated control stream. the admission supplies the original
// opening's pair, run and subject when checking this per-visitor signed proof.
type ConnectorPermissionUpdate struct {
	VisitorConnectionID string                     `json:"visitor_connection_id"`
	UpdateNumber        uint64                     `json:"update_number"`
	DeliveryGeneration  int64                      `json:"delivery_generation"`
	Permission          ConnectorVisitorPermission `json:"permission"`
}

func (u ConnectorPermissionUpdate) valid() bool {
	return opaqueid.Valid(u.VisitorConnectionID, opaqueid.VisitorConnectionPrefix) && u.UpdateNumber > 0 && u.DeliveryGeneration > 0 && u.Permission.valid()
}

type ConnectorPermissionResult struct {
	VisitorConnectionID string     `json:"visitor_connection_id"`
	UpdateNumber        uint64     `json:"update_number"`
	DeliveryGeneration  int64      `json:"delivery_generation"`
	Kind                StreamKind `json:"kind"`
}

const ConnectorPermissionAccepted StreamKind = "connector_permission_accepted"
const ConnectorPermissionRejected StreamKind = "connector_permission_rejected"
const ConnectorPermissionStale StreamKind = "connector_permission_stale"

func (r ConnectorPermissionResult) valid() bool {
	return opaqueid.Valid(r.VisitorConnectionID, opaqueid.VisitorConnectionPrefix) && r.UpdateNumber > 0 && r.DeliveryGeneration > 0 &&
		(r.Kind == ConnectorPermissionAccepted || r.Kind == ConnectorPermissionRejected || r.Kind == ConnectorPermissionStale)
}

func WriteConnectorPermissionResult(w io.Writer, result ConnectorPermissionResult) error {
	if !result.valid() {
		return ErrConnectorPermissionUpdate
	}
	return writeJSONFrame(w, result, 256)
}

func ReadConnectorPermissionResult(r io.Reader) (ConnectorPermissionResult, error) {
	var result ConnectorPermissionResult
	if err := readJSONFrame(r, &result, 256); err != nil {
		return ConnectorPermissionResult{}, err
	}
	if !result.valid() {
		return ConnectorPermissionResult{}, ErrConnectorPermissionUpdate
	}
	return result, nil
}

func WriteConnectorPermissionUpdate(w io.Writer, u ConnectorPermissionUpdate) error {
	if !u.valid() {
		return ErrConnectorPermissionUpdate
	}
	return writeJSONFrame(w, u, MaxConnectorPermissionBytes)
}

// an invalid bounded payload is consumed in full and returns the sentinel, so
// another visitor's next update remains readable. framing/IO errors are terminal.
func ReadConnectorPermissionUpdate(r io.Reader) (ConnectorPermissionUpdate, error) {
	payload, err := readFramePayload(r, MaxConnectorPermissionBytes)
	if err != nil {
		return ConnectorPermissionUpdate{}, err
	}
	var u ConnectorPermissionUpdate
	if decodeJSONPayload(payload, &u) != nil || !u.valid() {
		return ConnectorPermissionUpdate{}, ErrConnectorPermissionUpdate
	}
	return u, nil
}
