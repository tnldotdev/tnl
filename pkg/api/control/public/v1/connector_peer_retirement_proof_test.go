package controlv1

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func retireRequestFixture() ConnectorPeerPairRetireRequest {
	return ConnectorPeerPairRetireRequest{ServiceRunId: "srun_1234567890123456789012", RunNumber: 2,
		PublisherIdentityId: "pub_1234567890123456789012", DeliveryId: "AQEBAQEBAQEBAQEBAQEBAQ",
		IdempotencyKey: "retained-owner", RequestedAt: time.Date(2026, 1, 2, 3, 4, 5, 123456000, time.UTC)}
}

func TestConnectorPeerRetireProofAdapterUsesHandwrittenBytes(t *testing.T) {
	const service, pair = "svc_1234567890123456789012", "cpp_1234567890123456789012"
	body := retireRequestFixture()
	proof, err := ConnectorPeerPairRetireProof(service, pair, body)
	if err != nil {
		t.Fatal(err)
	}
	want := tunnelv1.ConnectorPeerPairRetireProof{ServiceID: service, PairID: pair, ServiceRunID: body.ServiceRunId,
		RunNumber: body.RunNumber, PublisherIdentityID: body.PublisherIdentityId, DeliveryID: body.DeliveryId,
		IdempotencyKey: body.IdempotencyKey, RequestedAt: body.RequestedAt}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	mac, err := want.SessionProof(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	message, err := proof.Message(mac)
	if err != nil {
		t.Fatal(err)
	}
	wantMessage, err := want.Message(mac)
	if err != nil || !bytes.Equal(message, wantMessage) {
		t.Fatal("generated adapter defined different signing bytes", err)
	}
	body.SessionProof = base64.RawURLEncoding.EncodeToString(mac)
	body.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, message))
	gotMAC, signature, err := ConnectorPeerPairRetireAuthentication(body)
	if err != nil || !bytes.Equal(gotMAC, mac) || proof.VerifySignature(key.Public().(ed25519.PublicKey), gotMAC, signature) != nil {
		t.Fatal("adapter changed authentication material", err)
	}
	for _, edit := range []func(*ConnectorPeerPairRetireRequest){
		func(b *ConnectorPeerPairRetireRequest) { b.SessionProof += "=" },
		func(b *ConnectorPeerPairRetireRequest) { b.Signature += "=" },
		func(b *ConnectorPeerPairRetireRequest) { b.SessionProof = b.SessionProof[:42] + "B" },
		func(b *ConnectorPeerPairRetireRequest) { b.Signature = b.Signature[:85] + "B" },
		func(b *ConnectorPeerPairRetireRequest) { b.SessionProof = "" },
		func(b *ConnectorPeerPairRetireRequest) { b.Signature = "" },
	} {
		changed := body
		edit(&changed)
		if _, _, err := ConnectorPeerPairRetireAuthentication(changed); err == nil {
			t.Fatal("noncanonical or missing authentication accepted")
		}
	}
}

func TestConnectorPeerRetirementClosedWireAndExactReceipt(t *testing.T) {
	const service, pair = "svc_1234567890123456789012", "cpp_1234567890123456789012"
	body := retireRequestFixture()
	at := body.RequestedAt.Add(time.Second)
	result := ConnectorPeerPairRetirement{ServiceId: service, ServiceRunId: body.ServiceRunId, RunNumber: body.RunNumber,
		PublisherIdentityId: body.PublisherIdentityId, PairId: pair, DeliveryId: body.DeliveryId, IdempotencyKey: body.IdempotencyKey,
		Disposition: ConnectorPeerPairDispositionRetired, OwnerRevision: 2,
		Retirement: ConnectorPeerPairRetirementObservation{ObservedAt: at, RetiredAt: at, RetainedUntil: at.Add(time.Minute)}}
	if err := result.ValidateFor(service, pair, body); err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(result)
	if err != nil || !bytes.Contains(wire, []byte(`"owner_revision":"2"`)) || !bytes.Contains(wire, []byte(`"run_number":"2"`)) {
		t.Fatal("wire counters lost decimal-string encoding", err)
	}
	for _, edit := range []func(*ConnectorPeerPairRetirement){
		func(r *ConnectorPeerPairRetirement) { r.ServiceId = "svc_abcdefghijklmnopqrstuv" },
		func(r *ConnectorPeerPairRetirement) { r.PairId = "cpp_abcdefghijklmnopqrstuv" },
		func(r *ConnectorPeerPairRetirement) { r.ServiceRunId = "srun_abcdefghijklmnopqrstuv" },
		func(r *ConnectorPeerPairRetirement) { r.RunNumber++ },
		func(r *ConnectorPeerPairRetirement) { r.PublisherIdentityId = "pub_abcdefghijklmnopqrstuv" },
		func(r *ConnectorPeerPairRetirement) { r.DeliveryId = "AgICAgICAgICAgICAgICAg" },
		func(r *ConnectorPeerPairRetirement) { r.IdempotencyKey = "another-owner" },
		func(r *ConnectorPeerPairRetirement) { r.Disposition = ConnectorPeerPairDispositionCandidate },
		func(r *ConnectorPeerPairRetirement) { r.Disposition = ConnectorPeerPairDisposition("unknown") },
		func(r *ConnectorPeerPairRetirement) { r.OwnerRevision = 1 },
		func(r *ConnectorPeerPairRetirement) { r.OwnerRevision = 3 },
		func(r *ConnectorPeerPairRetirement) { r.Retirement.RetiredAt = time.Time{} },
		func(r *ConnectorPeerPairRetirement) { r.Retirement.ObservedAt = at.Add(-time.Second) },
		func(r *ConnectorPeerPairRetirement) { r.Retirement.RetainedUntil = at },
		func(r *ConnectorPeerPairRetirement) {
			r.Retirement.RetainedUntil = at.Add(5*time.Minute + 5*time.Second + time.Nanosecond)
		},
	} {
		changed := result
		edit(&changed)
		if err := changed.ValidateFor(service, pair, body); err == nil {
			t.Fatal("mismatched or contradictory retirement accepted", changed)
		}
	}
	if ConnectorPeerPairDisposition("").Valid() || ConnectorPeerPairDisposition("unknown").Valid() ||
		!ConnectorPeerPairDispositionCandidate.Valid() || !ConnectorPeerPairDispositionRetired.Valid() {
		t.Fatal("generated disposition enum is not closed")
	}
}
