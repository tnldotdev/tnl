package tunnelv1

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func connectorPairGoldenProof() ConnectorPeerPairProof {
	return ConnectorPeerPairProof{Action: "create", ServiceID: "svc_1234567890123456789012", ServiceRunID: "srun_1234567890123456789012",
		RunNumber: 2, PublisherIdentityID: "pub_1234567890123456789012",
		Subject:        VisitorSubject{Kind: VisitorHumanDevice, IdentityID: "ident_1234567890123456789012", DeviceID: "vdev_1234567890123456789012"},
		IdempotencyKey: "pair-one", RequestedAt: time.Date(2026, 1, 2, 4, 4, 5, 123456999, time.FixedZone("other", 3600)),
		ExpectedRelays: [2]ConnectorPeerPairRelay{
			{PublisherConnectionID: "pc_1234567890123456789012", AssignmentRevision: 5,
				RelayLease:   ConnectorPeerRelayLease{RelayServiceID: "relay-a", RelayID: "node-a", RelayRunID: "process-a", RelayLeaseRevision: 3},
				RelayAddress: "a.example.test:443", TLSServerName: "a.example.test"},
			{PublisherConnectionID: "pc_abcdefghijklmnopqrstuv", AssignmentRevision: 6,
				RelayLease:   ConnectorPeerRelayLease{RelayServiceID: "relay-b", RelayID: "node-b", RelayRunID: "process-b", RelayLeaseRevision: 4},
				RelayAddress: "b.example.test:443", TLSServerName: "b.example.test"},
		}}
}

func TestConnectorPeerPairProofGolden(t *testing.T) {
	proof := connectorPairGoldenProof()
	message, err := proof.Message()
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/connector-peer-pair-proof.json")
	if err != nil {
		t.Fatal(err)
	}
	const domain = "tnl connector peer pair v1\x00"
	var compact bytes.Buffer
	if err := json.Compact(&compact, want); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(message, append([]byte(domain), compact.Bytes()...)) || !bytes.Contains(message, []byte(`"RelayLeaseRevision":3`)) || bytes.Contains(message, []byte(`"relay_lease_revision"`)) {
		t.Fatalf("canonical proof changed: %s", message)
	}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	signature := ed25519.Sign(private, message)
	const goldenSignature = "c5271a64a25fd2b667bec6443f490ce3229991e0072ecdbb17ed7d3c4cd6e437d4887fbd6e7a38ef5422eacb4efc0199a8432661928e2f65327119d92b55970f"
	if hex.EncodeToString(signature) != goldenSignature || !ed25519.Verify(private.Public().(ed25519.PublicKey), message, signature) {
		t.Fatalf("signed proof changed: %s", hex.EncodeToString(signature))
	}
	legacy, err := hex.DecodeString("70f4de6323c4570fc5c14c35ac3212ef66c149990524b52d03f55b4a88f6b0d83bda6a6751d9829619c6f1e5b916fbe7aa4633cd86ebc9a3afe8ccacd671f004")
	if err != nil {
		t.Fatal(err)
	}
	if ed25519.Verify(private.Public().(ed25519.PublicKey), message, legacy) {
		t.Fatal("retired native proof signature was accepted")
	}
}

func TestConnectorPeerPairProofRejectsChangedBindings(t *testing.T) {
	for _, change := range []struct {
		name string
		edit func(*ConnectorPeerPairProof)
	}{
		{"service id", func(p *ConnectorPeerPairProof) { p.ServiceID = "svc_bad" }},
		{"publisher id", func(p *ConnectorPeerPairProof) { p.PublisherIdentityID = "pub_bad" }},
		{"subject", func(p *ConnectorPeerPairProof) { p.Subject.DeviceID = "vdev_bad" }},
		{"retry key", func(p *ConnectorPeerPairProof) { p.IdempotencyKey = " changed" }},
		{"slot services", func(p *ConnectorPeerPairProof) { p.ExpectedRelays[1].RelayLease.RelayServiceID = "relay-a" }},
		{"replace without prior pair", func(p *ConnectorPeerPairProof) { p.Action = "replace" }},
	} {
		t.Run(change.name, func(t *testing.T) {
			proof := connectorPairGoldenProof()
			change.edit(&proof)
			if _, err := proof.Message(); err == nil {
				t.Fatal("invalid binding signed")
			}
		})
	}
}
