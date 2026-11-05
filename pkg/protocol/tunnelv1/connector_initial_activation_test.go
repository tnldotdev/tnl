package tunnelv1

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestConnectorInitialBindingActivationKeepsStableOperationAndFreshHelloDistinct(t *testing.T) {
	operation := ConnectorHandoffID{9}
	for _, hello := range []ConnectorHelloNonce{{1}, {2}} {
		activation, err := InitialConnectorBindingActivation(hello, operation)
		if err != nil {
			t.Fatal(err)
		}
		binding := activation.Binding()
		if !bytes.Equal(binding.Nonce, hello[:]) || !bytes.Equal(binding.InitialHandoffID, operation[:]) || activation.SelectedHandoff() != operation || !activation.Matches(ConnectorPairLegProof{Nonce: hello[:]}) {
			t.Fatal("initial operation replaced its authenticated hello")
		}
		payload, err := json.Marshal(binding)
		if err != nil {
			t.Fatal(err)
		}
		var wire ConnectorLegBinding
		if err := json.Unmarshal(payload, &wire); err != nil {
			t.Fatal(err)
		}
		parsed, err := wire.Activation()
		if err != nil || parsed != activation {
			t.Fatal("stable initial operation did not round-trip", err)
		}
		for _, kind := range []MessageType{ConnectorLegActivate, ConnectorLegActivated} {
			message := Message{Type: kind, ProtocolVersion: Version, RequestID: "initial-binding", ConnectorLegBinding: &wire}
			if kind == ConnectorLegActivate {
				message.Role = Connector
			}
			var framed bytes.Buffer
			if err := WriteControl(&framed, message); err != nil {
				t.Fatal(err)
			}
			decoded, err := ReadControl(&framed)
			if err != nil || decoded.ConnectorLegBinding == nil {
				t.Fatal("closed control parser rejected initial binding", err)
			}
			decodedActivation, err := decoded.ConnectorLegBinding.Activation()
			if err != nil || decodedActivation != activation {
				t.Fatal("control parser changed initial operation", err)
			}
		}
		binding.InitialHandoffID[0]++
		if got, ok := activation.InitialOperation(); !ok || got != operation {
			t.Fatal("initial operation aliased mutable wire bytes")
		}
		handoff, err := NewConnectorHandoff(operation, ConnectorHandoffID{10}, 1)
		if err != nil {
			t.Fatal(err)
		}
		replacement := activation.Replacing(handoff)
		if _, initial := replacement.InitialOperation(); initial || replacement.Binding().InitialHandoffID != nil {
			t.Fatal("numbered replacement retained a conflicting initial operation")
		}
	}
}

func TestConnectorInitialBindingActivationRejectsMixedOrInvalidOperation(t *testing.T) {
	if _, err := InitialConnectorBindingActivation(ConnectorHelloNonce{1}, ConnectorHandoffID{}); err == nil {
		t.Fatal("zero stable initial operation accepted")
	}
	activation, err := InitialConnectorBindingActivation(ConnectorHelloNonce{1}, ConnectorHandoffID{9})
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*ConnectorLegBinding){
		func(b *ConnectorLegBinding) { b.InitialHandoffID = b.InitialHandoffID[:31] },
		func(b *ConnectorLegBinding) { b.InitialHandoffID = make([]byte, 32) },
		func(b *ConnectorLegBinding) { b.PreviousNonce = make([]byte, 32) },
		func(b *ConnectorLegBinding) { b.ReplacementNonce = make([]byte, 32) },
		func(b *ConnectorLegBinding) { b.HandoffRevision = 1 },
	} {
		invalid := activation.Binding()
		mutate(&invalid)
		if invalid.Validate() == nil {
			t.Fatal("invalid or mixed initial operation accepted")
		}
	}
}
