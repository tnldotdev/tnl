package tunnelv1

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func TestConnectorPairLegBindingStateIsExplicitAndClosed(t *testing.T) {
	now := time.Now()
	receipt := ConnectorPairLegAccepted{PairID: "cpp_1234567890123456789012", DeliveryID: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16)),
		DeliveryGeneration: 7, ConnectionSlot: 0, SourceIP: "192.0.2.1", ObservedAt: now, ExpiresAt: now.Add(time.Minute)}
	for _, state := range []ConnectorPeerLegBindingState{ConnectorPeerLegBindingActive, ConnectorPeerLegBindingPrepared} {
		receipt.BindingState = state
		wire, err := json.Marshal(receipt)
		if err != nil || receipt.Validate() != nil {
			t.Fatal("explicit receipt rejected", err)
		}
		if !bytes.Contains(wire, []byte(`"binding_state":"`+state+`"`)) {
			t.Fatal("receipt omitted its binding state")
		}
		var message bytes.Buffer
		if err := WriteControl(&message, Message{Type: HelloAccepted, ProtocolVersion: Version, ConnectorPairLegAccepted: &receipt}); err != nil {
			t.Fatal(err)
		}
		got, err := ReadControl(&message)
		if err != nil || got.ConnectorPairLegAccepted == nil || got.ConnectorPairLegAccepted.BindingState != state {
			t.Fatal("receipt changed binding state", err)
		}
	}
	for _, state := range []ConnectorPeerLegBindingState{"", "installed"} {
		receipt.BindingState = state
		if receipt.Validate() == nil {
			t.Fatalf("invalid binding state %q accepted", state)
		}
		var message bytes.Buffer
		if err := WriteControl(&message, Message{Type: HelloAccepted, ProtocolVersion: Version, ConnectorPairLegAccepted: &receipt}); err == nil {
			t.Fatalf("invalid binding state %q written", state)
		}
	}
	receipt.BindingState = ConnectorPeerLegBindingActive
	wire, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, replacement := range []string{"", `"binding_state":"",`, `"binding_state":null,`, `"binding_state":"installed",`} {
		invalid := bytes.Replace(wire, []byte(`"binding_state":"active",`), []byte(replacement), 1)
		if err := readControl(frame(`{"type":"hello_accepted","protocol_version":1,"connector_pair_leg_accepted":` + string(invalid) + `}`)); err == nil {
			t.Fatalf("invalid binding state field %q read", replacement)
		}
	}
}
