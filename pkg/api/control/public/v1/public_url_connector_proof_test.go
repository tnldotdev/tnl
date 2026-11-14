package controlv1

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestPublicURLConnectorProofAdaptersKeepCanonicalTypedSigning(t *testing.T) {
	const url, pair = "url_1234567890123456789012", "cpp_1234567890123456789012"
	base := rebindRequestFixture()
	rebind := PublicURLConnectorPeerPairRebindRequest{Phase: base.Phase, IdempotencyKey: base.IdempotencyKey,
		ExpectedGeneration: base.ExpectedGeneration, RequestedAt: base.RequestedAt,
		PublishRunId: "pr_1234567890123456789012", PublishRunNumber: base.RunNumber,
		PublisherIdentityId: base.PublisherIdentityId, TrustRevision: base.TrustRevision, Subject: base.Subject}
	message, err := PublicURLConnectorPeerPairRebindProofMessage(url, pair, rebind)
	if err != nil {
		t.Fatal(err)
	}
	canonical := tunnelv1.ConnectorPeerPairRebindProof{Phase: "inspect", PublicURLID: url, PairID: pair,
		IdempotencyKey: rebind.IdempotencyKey, ExpectedGeneration: rebind.ExpectedGeneration, RequestedAt: rebind.RequestedAt,
		PublishRunID: rebind.PublishRunId, PublishRunNumber: rebind.PublishRunNumber, PublisherIdentityID: rebind.PublisherIdentityId,
		TrustRevision: rebind.TrustRevision, Subject: tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorHumanDevice,
			IdentityID: *base.Subject.IdentityId, DeviceID: *base.Subject.DeviceId}}
	want, err := canonical.Message()
	if err != nil || !bytes.Equal(message, want) {
		t.Fatal("public URL HTTP adapter changed canonical rebind bytes", err)
	}
	rebind.Source.PreviewId, rebind.Signature = new("pvw_1234567890123456789012"), "not-signing-input"
	next, err := PublicURLConnectorPeerPairRebindProofMessage(url, pair, rebind)
	if err != nil || !bytes.Equal(message, next) {
		t.Fatal("source credentials or HTTP signature entered canonical proof", err)
	}
	relays := make([]ConnectorPeerPairRelay, 2)
	for slot := range relays {
		relays[slot] = ConnectorPeerPairRelay{PublisherConnectionId: "pc_" + strings.Repeat(string(rune('a'+slot)), 22),
			AssignmentRevision: int64(slot + 1), RelayLease: ConnectorPeerRelayLease{RelayServiceId: string(rune('a' + slot)),
				RelayId: "relay", RelayRunId: "process", RelayLeaseRevision: 1},
			RelayAddress: "relay.example.test:443", TlsServerName: "relay.example.test"}
	}
	body := PublicURLConnectorPeerPairRequest{PublishRunId: rebind.PublishRunId, PublishRunNumber: rebind.PublishRunNumber,
		PublisherIdentityId: rebind.PublisherIdentityId, Subject: base.Subject, Action: "create",
		IdempotencyKey: "pair-one", RequestedAt: base.RequestedAt, ExpectedRelays: relays}
	proof, err := PublicURLConnectorPeerPairProof(url, body)
	if err != nil || proof.PublicURLID != url || proof.PublishRunID != body.PublishRunId ||
		proof.ServiceID != "" || proof.ServiceRunID != "" || proof.RunNumber != 0 {
		t.Fatal("HTTP preparation lost its exclusive publication family", err)
	}
	want, err = proof.Message()
	got, adapterErr := PublicURLConnectorPeerPairProofMessage(url, body)
	if err != nil || adapterErr != nil || !bytes.Equal(want, got) || !bytes.HasPrefix(got, []byte("tnl public URL connector peer pair v1\x00")) {
		t.Fatal("HTTP preparation changed canonical proof bytes", err, adapterErr)
	}
	for _, edit := range []func(*PublicURLConnectorPeerPairRequest){
		func(p *PublicURLConnectorPeerPairRequest) { p.PublishRunId = "srun_1234567890123456789012" },
		func(p *PublicURLConnectorPeerPairRequest) { p.PublishRunNumber = 0 },
		func(p *PublicURLConnectorPeerPairRequest) { p.Subject.GrantId = new("") },
		func(p *PublicURLConnectorPeerPairRequest) { p.Subject.KeyId = new("") },
		func(p *PublicURLConnectorPeerPairRequest) { p.Subject.WorkloadSessionId = new("") },
		func(p *PublicURLConnectorPeerPairRequest) { p.Subject.Kind = WorkloadSession },
		func(p *PublicURLConnectorPeerPairRequest) { p.ExpectedRelays = p.ExpectedRelays[:1] },
	} {
		changed := body
		edit(&changed)
		if _, err := PublicURLConnectorPeerPairProof(url, changed); err == nil {
			t.Fatal("invalid public URL HTTP proof signed")
		}
	}
	for _, value := range []any{PublicURLConnectorPeerPair{}, PublicURLConnectorPeerPairDelivery{}, body, rebind} {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{`"service_id"`, `"service_run_id"`, `"run_number"`} {
			if bytes.Contains(raw, []byte(field)) {
				t.Fatal("public URL HTTP representation encoded a service authority field")
			}
		}
	}
}
