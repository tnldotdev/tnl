package tunnelv1

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"os"
	"strings"
	"testing"
	"time"
)

func connectorRebindFixture(t *testing.T, phase string) ConnectorPeerPairRebindProof {
	t.Helper()
	initial := connectorPairGoldenProof()
	p := ConnectorPeerPairRebindProof{Phase: phase, ServiceID: initial.ServiceID, PairID: "cpp_1234567890123456789012",
		ServiceRunID: initial.ServiceRunID, RunNumber: initial.RunNumber, PublisherIdentityID: initial.PublisherIdentityID,
		Subject: initial.Subject, IdempotencyKey: initial.IdempotencyKey, ExpectedGeneration: 7, TrustRevision: 9, RequestedAt: initial.RequestedAt}
	if phase != "inspect" {
		p.OperationID = "ik_1234567890123456789012"
	}
	if phase == "prepare" {
		p.ExpectedRelays = append([]ConnectorPeerPairRelay(nil), initial.ExpectedRelays[:]...)
		for slot := range p.ExpectedRelays {
			p.ExpectedRelays[slot].RelayLease.RelayRunID = "rr_1234567890123456789012"
		}
	}
	if phase == "activate" {
		p.BindingChallenge = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
		for slot := range 2 {
			frame, err := (PeerPacket{BindingGeneration: uint64(p.ExpectedGeneration), Kind: PeerProbeReply, Sender: 1, Path: uint8(slot), Sequence: uint64(slot + 1), Total: 16,
				Payload: bytes.Repeat([]byte{2}, 16)}).MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			p.PathProofs = append(p.PathProofs, ConnectorPeerPairPathProof{ConnectionSlot: slot,
				ProbeNonce: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 16)), ReplyFrame: base64.RawURLEncoding.EncodeToString(frame)})
		}
	}
	return p
}

func TestConnectorPeerPairRebindProofGolden(t *testing.T) {
	p := connectorRebindFixture(t, "inspect")
	message, err := p.Message()
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/connector-peer-rebind-proof.json")
	if err != nil {
		t.Fatal(err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, want); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(message, append([]byte("tnl connector peer rebind v1\x00"), compact.Bytes()...)) {
		t.Fatalf("rebind proof changed: %s", message)
	}
	p.ExpectedRelays, p.PathProofs = []ConnectorPeerPairRelay{}, []ConnectorPeerPairPathProof{}
	next, err := p.Message()
	if err != nil || !bytes.Equal(message, next) {
		t.Fatal("nil and empty signing arrays differ", err)
	}
}

func TestConnectorPeerPairRebindProofPhasesAndSignature(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	for _, phase := range []string{"inspect", "prepare", "activate", "abort"} {
		t.Run(phase, func(t *testing.T) {
			p := connectorRebindFixture(t, phase)
			message, err := p.Message()
			if err != nil {
				t.Fatal(err)
			}
			signature := ed25519.Sign(key, message)
			for _, edit := range []func(*ConnectorPeerPairRebindProof){
				func(p *ConnectorPeerPairRebindProof) { p.ExpectedGeneration++ },
				func(p *ConnectorPeerPairRebindProof) { p.TrustRevision++ },
				func(p *ConnectorPeerPairRebindProof) { p.PairID = "cpp_abcdefghijklmnopqrstuv" },
				func(p *ConnectorPeerPairRebindProof) { p.RequestedAt = p.RequestedAt.Add(time.Microsecond) },
				func(p *ConnectorPeerPairRebindProof) { p.IdempotencyKey = "other-owner" },
			} {
				next := p
				edit(&next)
				changed, err := next.Message()
				if err != nil || ed25519.Verify(key.Public().(ed25519.PublicKey), changed, signature) {
					t.Fatal("changed lifecycle identity retained its signature", err)
				}
			}
			initial, err := connectorPairGoldenProof().Message()
			if err != nil || ed25519.Verify(key.Public().(ed25519.PublicKey), initial, signature) {
				t.Fatal("rebind proof crossed preparation domain", err)
			}
		})
	}
}

func TestConnectorPeerPairRebindProofRejectsInvalidPhases(t *testing.T) {
	for _, test := range []struct {
		name, phase string
		edit        func(*ConnectorPeerPairRebindProof)
	}{
		{"unknown", "replace", func(*ConnectorPeerPairRebindProof) {}},
		{"zero revision", "inspect", func(p *ConnectorPeerPairRebindProof) { p.ExpectedGeneration = 0 }},
		{"bad pair", "inspect", func(p *ConnectorPeerPairRebindProof) { p.PairID = "cpp_bad" }},
		{"control in owner", "inspect", func(p *ConnectorPeerPairRebindProof) { p.IdempotencyKey = "owner\x00key" }},
		{"long owner", "inspect", func(p *ConnectorPeerPairRebindProof) { p.IdempotencyKey = strings.Repeat("x", 129) }},
		{"zero time", "inspect", func(p *ConnectorPeerPairRebindProof) { p.RequestedAt = time.Time{} }},
		{"zero trust", "inspect", func(p *ConnectorPeerPairRebindProof) { p.TrustRevision = 0 }},
		{"inspect operation", "inspect", func(p *ConnectorPeerPairRebindProof) { p.OperationID = "ik_1234567890123456789012" }},
		{"inspect relays", "inspect", func(p *ConnectorPeerPairRebindProof) { p.ExpectedRelays = make([]ConnectorPeerPairRelay, 2) }},
		{"prepare exhausted", "prepare", func(p *ConnectorPeerPairRebindProof) { p.ExpectedGeneration = math.MaxInt64 }},
		{"prepare operation", "prepare", func(p *ConnectorPeerPairRebindProof) { p.OperationID = "bad" }},
		{"prepare missing relay", "prepare", func(p *ConnectorPeerPairRebindProof) { p.ExpectedRelays = p.ExpectedRelays[:1] }},
		{"prepare repeated service", "prepare", func(p *ConnectorPeerPairRebindProof) {
			p.ExpectedRelays[1].RelayLease.RelayServiceID = p.ExpectedRelays[0].RelayLease.RelayServiceID
		}},
		{"prepare repeated connection", "prepare", func(p *ConnectorPeerPairRebindProof) {
			p.ExpectedRelays[1].PublisherConnectionID = p.ExpectedRelays[0].PublisherConnectionID
		}},
		{"prepare old process", "prepare", func(p *ConnectorPeerPairRebindProof) { p.ExpectedRelays[0].RelayLease.RelayRunID = "old" }},
		{"prepare lease overflow", "prepare", func(p *ConnectorPeerPairRebindProof) {
			p.ExpectedRelays[0].RelayLease.RelayLeaseRevision = math.MaxUint64
		}},
		{"prepare negative assignment", "prepare", func(p *ConnectorPeerPairRebindProof) { p.ExpectedRelays[0].AssignmentRevision = -1 }},
		{"prepare address bound", "prepare", func(p *ConnectorPeerPairRebindProof) { p.ExpectedRelays[0].RelayAddress = strings.Repeat("a", 257) }},
		{"activate missing proof", "activate", func(p *ConnectorPeerPairRebindProof) { p.PathProofs = p.PathProofs[:1] }},
		{"activate reversed slots", "activate", func(p *ConnectorPeerPairRebindProof) {
			p.PathProofs[0], p.PathProofs[1] = p.PathProofs[1], p.PathProofs[0]
		}},
		{"activate padded challenge", "activate", func(p *ConnectorPeerPairRebindProof) { p.BindingChallenge += "=" }},
		{"activate noncanonical nonce", "activate", func(p *ConnectorPeerPairRebindProof) { p.PathProofs[0].ProbeNonce = strings.Repeat("A", 21) + "B" }},
		{"activate oversized frame", "activate", func(p *ConnectorPeerPairRebindProof) {
			p.PathProofs[0].ReplyFrame = base64.RawURLEncoding.EncodeToString(make([]byte, MaxConnectorPeerPairReplyFrameBytes+1))
		}},
		{"activate wrong direction", "activate", func(p *ConnectorPeerPairRebindProof) {
			frame, _ := base64.RawURLEncoding.DecodeString(p.PathProofs[0].ReplyFrame)
			packet, _ := ParsePeerPacket(frame)
			packet.Sender = 0
			frame, _ = packet.MarshalBinary()
			p.PathProofs[0].ReplyFrame = base64.RawURLEncoding.EncodeToString(frame)
		}},
		{"abort challenge", "abort", func(p *ConnectorPeerPairRebindProof) { p.BindingChallenge = "unused" }},
		{"abort proofs", "abort", func(p *ConnectorPeerPairRebindProof) { p.PathProofs = make([]ConnectorPeerPairPathProof, 2) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := connectorRebindFixture(t, test.phase)
			test.edit(&p)
			if _, err := p.Message(); !errors.Is(err, ErrConnectorPeerPairRebindProof) {
				t.Fatal("invalid phase-specific proof signed", err)
			}
		})
	}
}

func TestStaleNetworkBindingControlRoundTrip(t *testing.T) {
	for _, code := range []ErrorCode{StaleNetworkBinding, Unauthenticated} {
		var wire bytes.Buffer
		if err := WriteControl(&wire, Message{Type: Error, ProtocolVersion: Version, Code: code}); err != nil {
			t.Fatal(err)
		}
		got, err := ReadControl(&wire)
		if err != nil || got.Code != code {
			t.Fatal("stale binding and denial must remain distinct", got.Code, err)
		}
	}
}

func FuzzConnectorPeerPairRebindProof(f *testing.F) {
	f.Add("inspect", "owner", int64(1), "", "")
	f.Add("activate", "owner", int64(2), "invalid", "invalid")
	f.Fuzz(func(t *testing.T, phase, owner string, generation int64, challenge, frame string) {
		p := connectorRebindFixture(t, "inspect")
		p.Phase, p.IdempotencyKey, p.ExpectedGeneration, p.BindingChallenge = phase, owner, generation, challenge
		if frame != "" {
			p.PathProofs = []ConnectorPeerPairPathProof{{ConnectionSlot: 0, ProbeNonce: challenge, ReplyFrame: frame}}
		}
		_, _ = p.Message()
	})
}
