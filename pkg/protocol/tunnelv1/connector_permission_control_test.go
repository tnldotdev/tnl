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
	return ConnectorPermissionUpdate{VisitorConnectionID: "vc_aaaaaaaaaaaaaaaaaaaaaa", UpdateNumber: 1, Permission: ConnectorVisitorPermission{Token: "signed-visitor-token", PublicKey: strings.Repeat("A", 43), Signature: strings.Repeat("A", 86)}}
}

func TestConnectorPermissionControlGoldenAndTruncation(t *testing.T) {
	u := permissionUpdateFixture()
	body := `{"visitor_connection_id":"vc_aaaaaaaaaaaaaaaaaaaaaa","update_number":1,"permission":{"visitor_token":"signed-visitor-token","public_key":"` + strings.Repeat("A", 43) + `","signature":"` + strings.Repeat("A", 86) + `"}}`
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
	for _, kind := range []StreamKind{ConnectorPermissionAccepted, ConnectorPermissionRejected} {
		result := ConnectorPermissionResult{VisitorConnectionID: u.VisitorConnectionID, UpdateNumber: 1, Kind: kind}
		body := `{"visitor_connection_id":"vc_aaaaaaaaaaaaaaaaaaaaaa","update_number":1,"kind":"` + string(kind) + `"}`
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
		body := `{"protocol_version":1,"kind":"` + kind + `","application_admission":true}`
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
	var old bytes.Buffer
	if _, err := WriteConnectorPeerVisitorOpening(&old, peerOpeningFixture(), nil); err != nil {
		t.Fatal(err)
	}
	if ReadConnectorPermissionHello(&old, false) == nil {
		t.Fatal("old application opening negotiated the new protocol")
	}
}

func FuzzConnectorPermissionControl(f *testing.F) {
	var seed bytes.Buffer
	_ = WriteConnectorPermissionUpdate(&seed, permissionUpdateFixture())
	f.Add(seed.Bytes())
	var ack bytes.Buffer
	_ = WriteConnectorPermissionResult(&ack, ConnectorPermissionResult{VisitorConnectionID: permissionUpdateFixture().VisitorConnectionID, UpdateNumber: 1, Kind: ConnectorPermissionAccepted})
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
