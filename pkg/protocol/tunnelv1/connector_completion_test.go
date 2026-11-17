package tunnelv1

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

func TestConnectorCompletionWireIsBoundedAndNotPermission(t *testing.T) {
	want := ConnectorVisitorCompletion{Kind: ConnectorVisitorCompleted, VisitorConnectionID: "vc_aaaaaaaaaaaaaaaaaaaaaa", DeliveryGeneration: 7, TerminalNumber: 1}
	body := `{"kind":"connector_visitor_completed","visitor_connection_id":"vc_aaaaaaaaaaaaaaaaaaaaaa","delivery_generation":7,"terminal_number":1}`
	wire := append(binary.BigEndian.AppendUint32(nil, uint32(len(body))), body...)
	var encoded bytes.Buffer
	if err := WriteConnectorVisitorCompletion(&encoded, want); err != nil || !bytes.Equal(encoded.Bytes(), wire) {
		t.Fatal("completion receipt wire changed", err)
	}
	got, err := ReadConnectorControlMessage(bytes.NewReader(wire))
	if err != nil || got != want {
		t.Fatal("completion lost its exact visitor and original delivery", err)
	}
	if _, err := ReadConnectorPermissionUpdate(bytes.NewReader(wire)); !errors.Is(err, ErrConnectorPermissionUpdate) {
		t.Fatal("a completion receipt became visitor permission", err)
	}
	for n := range len(wire) {
		if _, err := ReadConnectorControlMessage(bytes.NewReader(wire[:n])); err == nil {
			t.Fatal("truncated completion accepted", n)
		}
	}
	for _, invalid := range []string{
		strings.Replace(body, `"delivery_generation":7`, `"delivery_generation":0`, 1),
		strings.Replace(body, `,"terminal_number":1`, "", 1),
		strings.Replace(body, `"terminal_number":1`, `"terminal_number":0`, 1),
		strings.Replace(body, `"vc_aaaaaaaaaaaaaaaaaaaaaa"`, `""`, 1),
		strings.Replace(body, `"connector_visitor_completed"`, `"unknown_completion"`, 1),
		strings.TrimSuffix(body, "}") + `,"permission":{}}`,
		strings.TrimSuffix(body, "}") + `,"extra":true}`,
	} {
		input := bytes.NewBuffer(append(binary.BigEndian.AppendUint32(nil, uint32(len(invalid))), invalid...))
		update := permissionUpdateFixture()
		if err := WriteConnectorPermissionUpdate(input, update); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadConnectorControlMessage(input); !errors.Is(err, ErrConnectorPermissionUpdate) {
			t.Fatal("invalid receipt escaped its closed shape", invalid, err)
		}
		got, err := ReadConnectorControlMessage(input)
		if err != nil || got != update {
			t.Fatal("invalid bounded receipt consumed another visitor's permission update", err)
		}
	}
	for _, length := range []uint32{0, MaxConnectorPermissionBytes + 1, ^uint32(0)} {
		reader := &headerOnlyReader{header: bytes.NewReader(binary.BigEndian.AppendUint32(nil, length))}
		if _, err := ReadConnectorControlMessage(reader); err == nil || reader.payloadReads != 0 {
			t.Fatal("oversized control receipt reached payload allocation")
		}
	}
}

func FuzzConnectorControlMessage(f *testing.F) {
	var seed bytes.Buffer
	_ = WriteConnectorVisitorCompletion(&seed, ConnectorVisitorCompletion{
		Kind: ConnectorVisitorCompleted, VisitorConnectionID: "vc_aaaaaaaaaaaaaaaaaaaaaa", DeliveryGeneration: 1, TerminalNumber: 1,
	})
	f.Add(seed.Bytes())
	for _, fixture := range append(connectorTerminalWireFixtures(), connectorTerminalMaximumWireFixtures()...) {
		if _, reply := fixture.message.(ConnectorControlReply); !reply {
			f.Add(connectorTerminalFrame(fixture.payload))
		}
	}
	var update bytes.Buffer
	_ = WriteConnectorPermissionUpdate(&update, permissionUpdateFixture())
	f.Add(update.Bytes())
	f.Fuzz(func(t *testing.T, wire []byte) {
		message, err := ReadConnectorControlMessage(bytes.NewReader(wire))
		if err != nil {
			return
		}
		var out bytes.Buffer
		switch message := message.(type) {
		case ConnectorVisitorCompletion:
			err = WriteConnectorVisitorCompletion(&out, message)
		case ConnectorPermissionUpdate:
			err = WriteConnectorPermissionUpdate(&out, message)
		case ConnectorVisitorAbort:
			err = WriteConnectorVisitorAbort(&out, message)
		case ConnectorVisitorTerminalObserved:
			err = WriteConnectorVisitorTerminalObserved(&out, message)
		default:
			t.Fatal("unknown typed control message")
		}
		if err != nil {
			t.Fatal("accepted control message could not be written", err)
		}
		if _, err := ReadConnectorControlMessage(&out); err != nil {
			t.Fatal("accepted control message did not round-trip", err)
		}
	})
}
