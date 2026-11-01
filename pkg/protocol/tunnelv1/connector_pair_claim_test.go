package tunnelv1

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestConnectorPairLegProofWireAndBounds(t *testing.T) {
	p := ConnectorPairLegProof{PairID: "cpp_1234567890123456789012", DeliveryGeneration: 3,
		ServiceID: "svc_1234567890123456789012", ServiceRunID: "srun_1234567890123456789012",
		PublisherIdentityID: "pub_1234567890123456789012", RunNumber: 4, ConnectionSlot: 1,
		PublisherConnectionID: "pc_1234567890123456789012", AssignmentRevision: 7,
		RelayServiceID: "relay-b", RelayID: "relay-1", RelayRunID: "process-1", RelayLeaseRevision: 2,
		RequestedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Nonce: bytes.Repeat([]byte{1}, 32),
		Signature: bytes.Repeat([]byte{2}, ed25519.SignatureSize)}
	message, err := p.Message()
	if err != nil || !bytes.HasPrefix(message, []byte("tnl connector pair leg claim v1\x00")) {
		t.Fatal("missing signed domain", err)
	}
	var frame bytes.Buffer
	if err := WriteConnectorPairLegProof(&frame, p); err != nil {
		t.Fatal(err)
	}
	const golden = `{"pair_id":"cpp_1234567890123456789012","delivery_generation":3,"service_id":"svc_1234567890123456789012","service_run_id":"srun_1234567890123456789012","run_number":4,"publisher_identity_id":"pub_1234567890123456789012","connection_slot":1,"publisher_connection_id":"pc_1234567890123456789012","assignment_revision":7,"relay_service_id":"relay-b","relay_id":"relay-1","relay_run_id":"process-1","relay_lease_revision":2,"requested_at":"2026-01-01T00:00:00Z","nonce":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","signature":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg=="}`
	if wire := frame.Bytes(); len(wire) != len(golden)+4 || binary.BigEndian.Uint32(wire[:4]) != uint32(len(golden)) || string(wire[4:]) != golden {
		t.Fatal("connector leg proof frame changed")
	}
	got, err := ReadConnectorPairLegProof(&frame)
	if err != nil || !bytes.Equal(got.Nonce, p.Nonce) || got.PairID != p.PairID {
		t.Fatal("proof wire changed", err)
	}
	// client-supplied source hints cannot enter the canonical proof. the relay
	// owner must pass the observed socket source separately to state.
	raw, _ := json.Marshal(p)
	raw = bytes.Replace(raw, []byte(`"nonce":`), []byte(`"source_ip":"192.0.2.10","nonce":`), 1)
	var hint bytes.Buffer
	hint.Write(binary.BigEndian.AppendUint32(nil, uint32(len(raw))))
	hint.Write(raw)
	if _, err := ReadConnectorPairLegProof(&hint); err == nil {
		t.Fatal("accepted a client-supplied source hint")
	}
	for _, mutate := range []func(*ConnectorPairLegProof){
		func(v *ConnectorPairLegProof) { v.ConnectionSlot = 2 },
		func(v *ConnectorPairLegProof) { v.Nonce = v.Nonce[:31] },
		func(v *ConnectorPairLegProof) { v.Signature = nil },
		func(v *ConnectorPairLegProof) { v.DeliveryGeneration = 0 },
	} {
		bad := p
		mutate(&bad)
		if err := WriteConnectorPairLegProof(&bytes.Buffer{}, bad); !errors.Is(err, ErrConnectorPairLegProof) {
			t.Fatal("accepted invalid proof", err)
		}
	}
	var oversized bytes.Buffer
	oversized.Write(binary.BigEndian.AppendUint32(nil, MaxConnectorPairLegProofBytes+1))
	if _, err := ReadConnectorPairLegProof(&oversized); err == nil {
		t.Fatal("oversized proof allocated")
	}
}
