package tunnelv1

import (
	"bytes"
	"encoding/json"
	"io"
	"unicode/utf8"
)

// only connector control uses these exact required fields. unrelated protocol
// readers keep their own decoding rules.
func decodeConnectorControlPayload(payload []byte, value any) error {
	var fields []string
	switch value.(type) {
	case *connectorPermissionHello:
		fields = []string{"protocol_version", "kind", "application_admission", "control_revision"}
	case *ConnectorPermissionUpdate:
		fields = []string{"visitor_connection_id", "update_number", "delivery_generation", "permission"}
	case *ConnectorPermissionResult:
		fields = []string{"visitor_connection_id", "update_number", "delivery_generation", "kind"}
	case *ConnectorVisitorCompletion, *ConnectorVisitorAbort:
		fields = []string{"kind", "visitor_connection_id", "delivery_generation", "terminal_number"}
	case *ConnectorVisitorTerminalResult, *ConnectorVisitorTerminalObserved:
		fields = []string{"kind", "visitor_connection_id", "delivery_generation", "terminal_number", "purpose", "outcome"}
	default:
		return ErrConnectorPermissionUpdate
	}
	object, err := connectorControlObject(payload, fields)
	if err != nil {
		return err
	}
	if _, update := value.(*ConnectorPermissionUpdate); update {
		if _, err := connectorControlObject(object["permission"], []string{"visitor_token", "public_key", "signature"}); err != nil {
			return err
		}
	}
	if json.Unmarshal(payload, value) != nil {
		return ErrConnectorPermissionUpdate
	}
	return nil
}

// tokenized names catch duplicate and case-folded fields before unmarshaling
// into a struct can discard that distinction.
func connectorControlObject(payload []byte, fields []string) (map[string]json.RawMessage, error) {
	if !utf8.Valid(payload) {
		return nil, ErrConnectorPermissionUpdate
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, ErrConnectorPermissionUpdate
	}
	object := make(map[string]json.RawMessage, len(fields))
	for decoder.More() {
		token, err := decoder.Token()
		name, ok := token.(string)
		if err != nil || !ok {
			return nil, ErrConnectorPermissionUpdate
		}
		allowed := false
		for _, field := range fields {
			if name == field {
				allowed = true
				break
			}
		}
		if _, duplicate := object[name]; !allowed || duplicate {
			return nil, ErrConnectorPermissionUpdate
		}
		var raw json.RawMessage
		if decoder.Decode(&raw) != nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return nil, ErrConnectorPermissionUpdate
		}
		object[name] = raw
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') || len(object) != len(fields) {
		return nil, ErrConnectorPermissionUpdate
	}
	var trailing json.RawMessage
	if decoder.Decode(&trailing) != io.EOF {
		return nil, ErrConnectorPermissionUpdate
	}
	return object, nil
}
