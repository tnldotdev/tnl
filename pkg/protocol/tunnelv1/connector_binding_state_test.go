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
	for _, state := range []ConnectorPeerLegBindingState{"", ConnectorPeerLegBindingActive, ConnectorPeerLegBindingPrepared} {
		receipt.BindingState = state
		wire, err := json.Marshal(receipt)
		if err != nil || receipt.Validate() != nil {
			t.Fatal("compatible receipt rejected", err)
		}
		if state == "" && bytes.Contains(wire, []byte("binding_state")) {
			t.Fatal("legacy receipt gained active authority")
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
	receipt.BindingState = "installed"
	if receipt.Validate() == nil {
		t.Fatal("publisher preparation state became relay activation")
	}
}
