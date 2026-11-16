package tunnelv1

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

func permissionUpdateFixture() ConnectorPermissionUpdate {
	return ConnectorPermissionUpdate{VisitorConnectionID: "vc_aaaaaaaaaaaaaaaaaaaaaa", UpdateNumber: 1, DeliveryGeneration: 7, Permission: ConnectorVisitorPermission{Token: "signed-visitor-token", PublicKey: strings.Repeat("A", 43), Signature: strings.Repeat("A", 86)}}
}

func TestConnectorPermissionControlGoldenAndTruncation(t *testing.T) {
	u := permissionUpdateFixture()
	body := `{"visitor_connection_id":"vc_aaaaaaaaaaaaaaaaaaaaaa","update_number":1,"delivery_generation":7,"permission":{"visitor_token":"signed-visitor-token","public_key":"` + strings.Repeat("A", 43) + `","signature":"` + strings.Repeat("A", 86) + `"}}`
	var frame bytes.Buffer
	if err := WriteConnectorPermissionUpdate(&frame, u); err != nil {
		t.Fatal(err)
	}
	want := binary.BigEndian.AppendUint32(nil, uint32(len(body)))
	want = append(want, body...)
	if !bytes.Equal(frame.Bytes(), want) {
		t.Fatal("permission control wire changed")
	}
	got, err := ReadConnectorPermissionUpdate(bytes.NewReader(want))
	if err != nil || got != u {
		t.Fatal("signed per-visitor proof changed", err)
	}
	for n := range len(want) {
		if _, err := ReadConnectorPermissionUpdate(bytes.NewReader(want[:n])); err == nil {
			t.Fatal("truncated control update accepted", n)
		}
	}
	for _, kind := range []StreamKind{ConnectorPermissionAccepted, ConnectorPermissionRejected, ConnectorPermissionStale} {
		result := ConnectorPermissionResult{VisitorConnectionID: u.VisitorConnectionID, UpdateNumber: 1, DeliveryGeneration: u.DeliveryGeneration, Kind: kind}
		body := `{"visitor_connection_id":"vc_aaaaaaaaaaaaaaaaaaaaaa","update_number":1,"delivery_generation":7,"kind":"` + string(kind) + `"}`
		wire := append(binary.BigEndian.AppendUint32(nil, uint32(len(body))), body...)
		var encoded bytes.Buffer
		if WriteConnectorPermissionResult(&encoded, result) != nil || !bytes.Equal(encoded.Bytes(), wire) {
			t.Fatal("permission ACK wire changed")
		}
		if got, err := ReadConnectorPermissionResult(bytes.NewReader(wire)); err != nil || got != result {
			t.Fatal("permission ACK lost its exact visitor/request binding", err)
		}
		for n := range len(wire) {
			if _, err := ReadConnectorPermissionResult(bytes.NewReader(wire[:n])); err == nil {
				t.Fatal("truncated ACK accepted", n)
			}
		}
	}
	for _, accepted := range []bool{false, true} {
		var hello bytes.Buffer
		if err := WriteConnectorPermissionHello(&hello, accepted); err != nil {
			t.Fatal(err)
		}
		kind := "connector_permission_control"
		if accepted {
			kind += "_accepted"
		}
		body := `{"protocol_version":1,"kind":"` + kind + `","application_admission":true,"control_revision":2}`
		want := append(binary.BigEndian.AppendUint32(nil, uint32(len(body))), body...)
		if !bytes.Equal(hello.Bytes(), want) || ReadConnectorPermissionHello(bytes.NewReader(want), accepted) != nil || ReadConnectorPermissionHello(bytes.NewReader(want), !accepted) == nil {
			t.Fatal("control negotiation lost its exact direction")
		}
		for n := range len(want) {
			if ReadConnectorPermissionHello(bytes.NewReader(want[:n]), accepted) == nil {
				t.Fatal("truncated control negotiation accepted", n)
			}
		}
		old := `{"protocol_version":1,"kind":"` + kind + `"}`
		oldWire := append(binary.BigEndian.AppendUint32(nil, uint32(len(old))), old...)
		if ReadConnectorPermissionHello(bytes.NewReader(oldWire), accepted) == nil {
			t.Fatal("control peer without application admission ordering was accepted")
		}
	}
}

func TestConnectorPermissionControlBoundsAndInvalidPayloadIsolation(t *testing.T) {
	for _, length := range []uint32{0, MaxConnectorPermissionBytes + 1, ^uint32(0)} {
		r := &headerOnlyReader{header: bytes.NewReader(binary.BigEndian.AppendUint32(nil, length))}
		if _, err := ReadConnectorPermissionUpdate(r); err == nil || r.payloadReads != 0 {
			t.Fatal("invalid control size reached payload reading", err)
		}
	}
	for _, length := range []uint32{0, 257, ^uint32(0)} {
		r := &headerOnlyReader{header: bytes.NewReader(binary.BigEndian.AppendUint32(nil, length))}
		if _, err := ReadConnectorPermissionResult(r); err == nil || r.payloadReads != 0 {
			t.Fatal("invalid ACK size reached payload reading", err)
		}
	}
	u := permissionUpdateFixture()
	for _, body := range []string{"null", `{}`, `{"visitor_connection_id":null}`, `{"unknown":true}`, strings.Repeat(" ", MaxConnectorPermissionBytes), `{} {}`} {
		var wire bytes.Buffer
		wire.Write(binary.BigEndian.AppendUint32(nil, uint32(len(body))))
		wire.WriteString(body)
		if err := WriteConnectorPermissionUpdate(&wire, u); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadConnectorPermissionUpdate(&wire); !errors.Is(err, ErrConnectorPermissionUpdate) {
			t.Fatal("bounded invalid update was not classified", err)
		}
		if next, err := ReadConnectorPermissionUpdate(&wire); err != nil || next != u {
			t.Fatal("invalid update consumed its sibling", err)
		}
	}
	for _, invalid := range []ConnectorPermissionUpdate{{}, {VisitorConnectionID: u.VisitorConnectionID}, {Permission: u.Permission}} {
		var wire bytes.Buffer
		if err := WriteConnectorPermissionUpdate(&wire, invalid); !errors.Is(err, ErrConnectorPermissionUpdate) || wire.Len() != 0 {
			t.Fatal("invalid proof emitted control bytes", err)
		}
	}
	for _, generation := range []int64{0, -1} {
		invalid := u
		invalid.DeliveryGeneration = generation
		if WriteConnectorPermissionUpdate(io.Discard, invalid) == nil ||
			WriteConnectorPermissionResult(io.Discard, ConnectorPermissionResult{VisitorConnectionID: u.VisitorConnectionID, UpdateNumber: 1, DeliveryGeneration: generation, Kind: ConnectorPermissionAccepted}) == nil {
			t.Fatal("permission control accepted an unbound revision")
		}
	}
	var old bytes.Buffer
	if _, err := WriteConnectorPeerVisitorOpening(&old, peerOpeningFixture(), nil); err != nil {
		t.Fatal(err)
	}
	if ReadConnectorPermissionHello(&old, false) == nil {
		t.Fatal("old application opening negotiated the new protocol")
	}
}

func TestConnectorPermissionHelloRequiresExactControlRevision(t *testing.T) {
	for _, accepted := range []bool{false, true} {
		kind := "connector_permission_control"
		if accepted {
			kind += "_accepted"
		}
		body := `{"protocol_version":1,"kind":"` + kind + `","application_admission":true,"control_revision":2}`
		invalid := []string{
			strings.Replace(body, `,"control_revision":2`, "", 1),
			strings.Replace(body, `"protocol_version":1`, `"protocol_version":2`, 1),
			strings.Replace(body, `"application_admission":true`, `"application_admission":false`, 1),
		}
		for _, revision := range []string{"null", "0", "1", "3", "4294967296", "2.0", `"2"`} {
			invalid = append(invalid, strings.Replace(body, `"control_revision":2`, `"control_revision":`+revision, 1))
		}
		for _, payload := range invalid {
			if err := ReadConnectorPermissionHello(bytes.NewReader(connectorTerminalFrame(payload)), accepted); err != ErrConnectorPermissionUpdate {
				t.Fatal("hello accepted missing, old, future, or malformed control revision", payload, err)
			}
		}
	}
}

func TestConnectorPermissionStrictFieldsAndSiblingIsolation(t *testing.T) {
	var update bytes.Buffer
	if err := WriteConnectorPermissionUpdate(&update, permissionUpdateFixture()); err != nil {
		t.Fatal(err)
	}
	updatePayload := string(update.Bytes()[4:])
	for _, test := range []struct {
		name    string
		payload string
		read    func(io.Reader) error
	}{
		{"hello", `{"protocol_version":1,"kind":"connector_permission_control","application_admission":true,"control_revision":2}`,
			func(r io.Reader) error { return ReadConnectorPermissionHello(r, false) }},
		{"accepted-hello", `{"protocol_version":1,"kind":"connector_permission_control_accepted","application_admission":true,"control_revision":2}`,
			func(r io.Reader) error { return ReadConnectorPermissionHello(r, true) }},
		{"update", updatePayload,
			func(r io.Reader) error { _, err := ReadConnectorPermissionUpdate(r); return err }},
		{"request-update", updatePayload,
			func(r io.Reader) error { _, err := ReadConnectorControlMessage(r); return err }},
		{"result", `{"visitor_connection_id":"vc_aaaaaaaaaaaaaaaaaaaaaa","update_number":1,"delivery_generation":7,"kind":"connector_permission_accepted"}`,
			func(r io.Reader) error { _, err := ReadConnectorPermissionResult(r); return err }},
		{"reply-result", `{"visitor_connection_id":"vc_aaaaaaaaaaaaaaaaaaaaaa","update_number":1,"delivery_generation":7,"kind":"connector_permission_accepted"}`,
			func(r io.Reader) error { _, err := ReadConnectorControlReply(r); return err }},
	} {
		invalid := connectorControlInvalidPayloads(t, test.payload)
		if test.payload == updatePayload {
			permission := `{"visitor_token":"signed-visitor-token","public_key":"` + strings.Repeat("A", 43) + `","signature":"` + strings.Repeat("A", 86) + `"}`
			for _, nested := range connectorControlInvalidPayloads(t, permission) {
				invalid = append(invalid, connectorControlInvalidPayload{
					name:    "permission-" + nested.name,
					payload: strings.Replace(test.payload, permission, nested.payload, 1),
				})
			}
		}
		for _, invalid := range invalid {
			t.Run(test.name+"/"+invalid.name, func(t *testing.T) {
				reader := bytes.NewReader(append(connectorTerminalFrame(invalid.payload), connectorTerminalFrame(test.payload)...))
				if err := test.read(reader); err != ErrConnectorPermissionUpdate {
					t.Fatal("strict bounded failure was not an inert malformed leaf", err)
				}
				if err := test.read(reader); err != nil || reader.Len() != 0 {
					t.Fatal("malformed control payload consumed its valid sibling", err)
				}
			})
		}
	}
}

func FuzzConnectorPermissionControl(f *testing.F) {
	var seed bytes.Buffer
	_ = WriteConnectorPermissionUpdate(&seed, permissionUpdateFixture())
	f.Add(seed.Bytes())
	var ack bytes.Buffer
	_ = WriteConnectorPermissionResult(&ack, ConnectorPermissionResult{VisitorConnectionID: permissionUpdateFixture().VisitorConnectionID, UpdateNumber: 1, DeliveryGeneration: 7, Kind: ConnectorPermissionAccepted})
	f.Add(ack.Bytes())
	var opening bytes.Buffer
	_ = WriteConnectorPeerVisitorAccepted(&opening, permissionUpdateFixture().VisitorConnectionID)
	f.Add(opening.Bytes())
	f.Add([]byte{0, 0, 0, 1, '{'})
	f.Fuzz(func(t *testing.T, data []byte) {
		update, err := ReadConnectorPermissionUpdate(bytes.NewReader(data))
		if err == nil && WriteConnectorPermissionUpdate(io.Discard, update) != nil {
			t.Fatal("decoded control proof cannot be written")
		}
		_ = ReadConnectorPermissionHello(bytes.NewReader(data), false)
		result, err := ReadConnectorPermissionResult(bytes.NewReader(data))
		if err == nil && WriteConnectorPermissionResult(io.Discard, result) != nil {
			t.Fatal("decoded ACK cannot be written")
		}
		_ = ReadConnectorPeerVisitorAccepted(bytes.NewReader(data), permissionUpdateFixture().VisitorConnectionID)
	})
}
