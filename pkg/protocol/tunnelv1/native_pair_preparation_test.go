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

func nativePairGoldenProof() NativePeerPairProof {
	return NativePeerPairProof{Action: "create", ServiceID: "svc_1234567890123456789012", ServiceRunID: "srun_1234567890123456789012",
		RunNumber: 2, PublisherIdentityID: "pub_1234567890123456789012",
		Subject:        VisitorSubject{Kind: VisitorHumanDevice, IdentityID: "ident_1234567890123456789012", DeviceID: "vdev_1234567890123456789012"},
		IdempotencyKey: "pair-one", RequestedAt: time.Date(2026, 1, 2, 4, 4, 5, 123456999, time.FixedZone("other", 3600)),
		ExpectedRelays: [2]NativePeerPairRelay{
			{PublisherConnectionID: "pc_1234567890123456789012", AssignmentRevision: 5,
				RelayLease:   NativePeerRelayLease{RelayServiceID: "relay-a", RelayID: "node-a", RelayRunID: "process-a", RelayLeaseRevision: 3},
				RelayAddress: "a.example.test:443", TLSServerName: "a.example.test"},
			{PublisherConnectionID: "pc_abcdefghijklmnopqrstuv", AssignmentRevision: 6,
				RelayLease:   NativePeerRelayLease{RelayServiceID: "relay-b", RelayID: "node-b", RelayRunID: "process-b", RelayLeaseRevision: 4},
				RelayAddress: "b.example.test:443", TLSServerName: "b.example.test"},
		}}
}

func TestNativePeerPairProofGolden(t *testing.T) {
	proof := nativePairGoldenProof()
	message, err := proof.Message()
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/native-peer-pair-proof.json")
	if err != nil {
		t.Fatal(err)
	}
	const domain = "tnl native peer pair v1\x00"
	var compact bytes.Buffer
	if err := json.Compact(&compact, want); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(message, append([]byte(domain), compact.Bytes()...)) || !bytes.Contains(message, []byte(`"RelayLeaseRevision":3`)) || bytes.Contains(message, []byte(`"relay_lease_revision"`)) {
		t.Fatalf("canonical proof changed: %s", message)
	}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	signature := ed25519.Sign(private, message)
	const goldenSignature = "70f4de6323c4570fc5c14c35ac3212ef66c149990524b52d03f55b4a88f6b0d83bda6a6751d9829619c6f1e5b916fbe7aa4633cd86ebc9a3afe8ccacd671f004"
	if hex.EncodeToString(signature) != goldenSignature || !ed25519.Verify(private.Public().(ed25519.PublicKey), message, signature) {
		t.Fatalf("signed proof changed: %s", hex.EncodeToString(signature))
	}
}

func TestNativePeerPairProofRejectsChangedBindings(t *testing.T) {
	for _, change := range []struct {
		name string
		edit func(*NativePeerPairProof)
	}{
		{"service id", func(p *NativePeerPairProof) { p.ServiceID = "svc_bad" }},
		{"publisher id", func(p *NativePeerPairProof) { p.PublisherIdentityID = "pub_bad" }},
		{"subject", func(p *NativePeerPairProof) { p.Subject.DeviceID = "vdev_bad" }},
		{"retry key", func(p *NativePeerPairProof) { p.IdempotencyKey = " changed" }},
		{"slot services", func(p *NativePeerPairProof) { p.ExpectedRelays[1].RelayLease.RelayServiceID = "relay-a" }},
		{"replace without prior pair", func(p *NativePeerPairProof) { p.Action = "replace" }},
	} {
		t.Run(change.name, func(t *testing.T) {
			proof := nativePairGoldenProof()
			change.edit(&proof)
			if _, err := proof.Message(); err == nil {
				t.Fatal("invalid binding signed")
			}
		})
	}
}
