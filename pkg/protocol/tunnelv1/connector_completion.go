package tunnelv1

import (
	"encoding/json"
	"io"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

const ConnectorVisitorCompleted StreamKind = "connector_visitor_completed"

// ConnectorVisitorCompletion confirms that the connector copied the full return
// direction and joined both application copy workers. it grants no authority.
type ConnectorVisitorCompletion struct {
	Kind                StreamKind `json:"kind"`
	VisitorConnectionID string     `json:"visitor_connection_id"`
	DeliveryGeneration  int64      `json:"delivery_generation"`
}

func (c ConnectorVisitorCompletion) valid() bool {
	return c.Kind == ConnectorVisitorCompleted && opaqueid.Valid(c.VisitorConnectionID, opaqueid.VisitorConnectionPrefix) && c.DeliveryGeneration > 0
}

type ConnectorControlMessage interface{ connectorControlMessage() }

func (ConnectorPermissionUpdate) connectorControlMessage()  {}
func (ConnectorVisitorCompletion) connectorControlMessage() {}

func WriteConnectorVisitorCompletion(w io.Writer, c ConnectorVisitorCompletion) error {
	if !c.valid() {
		return ErrConnectorPermissionUpdate
	}
	return writeJSONFrame(w, c, 256)
}

// ReadConnectorControlMessage consumes one bounded update or completion. existing
// permission updates have no kind; completion has a distinct closed wire shape.
func ReadConnectorControlMessage(r io.Reader) (ConnectorControlMessage, error) {
	payload, err := readFramePayload(r, MaxConnectorPermissionBytes)
	if err != nil {
		return nil, err
	}
	var header struct {
		Kind StreamKind `json:"kind"`
	}
	if json.Unmarshal(payload, &header) != nil {
		return nil, ErrConnectorPermissionUpdate
	}
	if header.Kind == ConnectorVisitorCompleted {
		var c ConnectorVisitorCompletion
		if decodeJSONPayload(payload, &c) != nil || !c.valid() {
			return nil, ErrConnectorPermissionUpdate
		}
		return c, nil
	}
	if header.Kind == "" {
		var u ConnectorPermissionUpdate
		if decodeJSONPayload(payload, &u) != nil || !u.valid() {
			return nil, ErrConnectorPermissionUpdate
		}
		return u, nil
	}
	return nil, ErrConnectorPermissionUpdate
}
