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
	TerminalNumber      uint64     `json:"terminal_number"`
}

func (c ConnectorVisitorCompletion) valid() bool {
	return c.Kind == ConnectorVisitorCompleted && opaqueid.Valid(c.VisitorConnectionID, opaqueid.VisitorConnectionPrefix) && c.DeliveryGeneration > 0 && c.TerminalNumber > 0
}

type ConnectorControlMessage interface{ connectorControlMessage() }

func (ConnectorPermissionUpdate) connectorControlMessage()  {}
func (ConnectorVisitorCompletion) connectorControlMessage() {}

func WriteConnectorVisitorCompletion(w io.Writer, c ConnectorVisitorCompletion) error {
	if !c.valid() {
		return ErrConnectorPermissionUpdate
	}
	return writeJSONFrame(w, c, MaxConnectorTerminalBytes)
}

// the request decoder accepts only updates, completion, abort, and observed.
// permission updates alone have no kind.
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
	if header.Kind != "" && len(payload) > MaxConnectorTerminalBytes {
		return nil, ErrConnectorPermissionUpdate
	}
	switch header.Kind {
	case ConnectorVisitorCompleted:
		var c ConnectorVisitorCompletion
		if decodeConnectorControlPayload(payload, &c) != nil || !c.valid() {
			return nil, ErrConnectorPermissionUpdate
		}
		return c, nil
	case ConnectorVisitorAborted:
		var a ConnectorVisitorAbort
		if decodeConnectorControlPayload(payload, &a) != nil || !a.valid() {
			return nil, ErrConnectorPermissionUpdate
		}
		return a, nil
	case ConnectorVisitorTerminalObservedKind:
		var o ConnectorVisitorTerminalObserved
		if decodeConnectorControlPayload(payload, &o) != nil || !o.valid() {
			return nil, ErrConnectorPermissionUpdate
		}
		return o, nil
	case "":
		var u ConnectorPermissionUpdate
		if decodeConnectorControlPayload(payload, &u) != nil || !u.valid() {
			return nil, ErrConnectorPermissionUpdate
		}
		return u, nil
	default:
		return nil, ErrConnectorPermissionUpdate
	}
}
