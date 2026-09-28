package dnscontroller

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/tnldotdev/tnl/internal/controlstate"
)

func TestRoute53ChallengeWaitsForINSYNCAfterRecordBecomesReadable(t *testing.T) {
	store, record := propagationChallengeFixture()
	client, provider := route53TestProvider(t, "tunnels.example.test")
	client.changeStatus = types.ChangeStatusPending
	verifier := &challengeVerifierStub{verified: true}
	manager, err := NewChallengeManager(store, provider, verifier, Config{ManagedDomain: "tunnels.example.test", ManagedZoneID: "Z123"})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Present(t.Context(), store.challenge.PublicURLID, store.challenge.AuthorizationID); err != nil {
		t.Fatal(err)
	}
	// Route 53's record-set API can list the new TXT before the change has
	// propagated to every authoritative server.
	client.recordSets[dnsName(record)] = []types.ResourceRecordSet{*client.changes[0].ResourceRecordSet}
	store.challenge.State = "presented"
	for range 2 {
		ready, err := manager.Verify(t.Context(), store.challenge.PublicURLID, store.challenge.AuthorizationID)
		if err != nil || ready || verifier.calls != 0 || client.getChangeID != "/change/test" || len(client.changes) != 1 {
			t.Fatalf("pending change: ready=%t checks=%d change=%q writes=%d error=%v", ready, verifier.calls, client.getChangeID, len(client.changes), err)
		}
	}
	client.changeStatus = types.ChangeStatusInsync
	ready, err := manager.Verify(t.Context(), store.challenge.PublicURLID, store.challenge.AuthorizationID)
	if err != nil || !ready || verifier.calls != 1 || len(client.changes) != 1 {
		t.Fatalf("synced change: ready=%t checks=%d writes=%d error=%v", ready, verifier.calls, len(client.changes), err)
	}
}

func TestRoute53ChallengeRecoversWriteBeforeReceiptWasSaved(t *testing.T) {
	store, record := propagationChallengeFixture()
	client, provider := route53TestProvider(t, "tunnels.example.test")
	client.changeStatus = types.ChangeStatusPending
	writes := 0
	client.changeRecords = func(_ context.Context, input *route53.ChangeResourceRecordSetsInput) (*route53.ChangeResourceRecordSetsOutput, error) {
		writes++
		client.recordSets[dnsName(record)] = []types.ResourceRecordSet{*input.ChangeBatch.Changes[0].ResourceRecordSet}
		return &route53.ChangeResourceRecordSetsOutput{ChangeInfo: &types.ChangeInfo{Id: aws.String("/change/recovered"), Status: types.ChangeStatusPending}}, nil
	}
	verifier := &challengeVerifierStub{verified: true}
	config := Config{ManagedDomain: "tunnels.example.test", ManagedZoneID: "Z123"}
	first, err := NewChallengeManager(store, provider, verifier, config)
	if err != nil {
		t.Fatal(err)
	}
	store.saveChangeErr = errors.New("database unavailable after Route 53 accepted the change")
	if err := first.Present(t.Context(), store.challenge.PublicURLID, store.challenge.AuthorizationID); !errors.Is(err, store.saveChangeErr) || writes != 1 {
		t.Fatalf("lost receipt: writes=%d error=%v", writes, err)
	}
	store.saveChangeErr = nil
	restarted, err := NewChallengeManager(store, provider, verifier, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Present(t.Context(), store.challenge.PublicURLID, store.challenge.AuthorizationID); err != nil || writes != 2 {
		t.Fatalf("reconcile after restart: writes=%d error=%v", writes, err)
	}
	store.challenge.State = "presented"
	ready, err := restarted.Verify(t.Context(), store.challenge.PublicURLID, store.challenge.AuthorizationID)
	if err != nil || ready || verifier.calls != 0 {
		t.Fatalf("recovered pending change: ready=%t checks=%d error=%v", ready, verifier.calls, err)
	}
	client.changeStatus = types.ChangeStatusInsync
	ready, err = restarted.Verify(t.Context(), store.challenge.PublicURLID, store.challenge.AuthorizationID)
	if err != nil || !ready || verifier.calls != 1 {
		t.Fatalf("recovered synchronized change: ready=%t checks=%d error=%v", ready, verifier.calls, err)
	}
}

func propagationChallengeFixture() (*challengeStoreStub, string) {
	record := "_acme-challenge.member.tunnels.example.test"
	digest := sha256.Sum256([]byte("first namespace issuance"))
	return &challengeStoreStub{challenge: controlstate.DNSChallengeContext{
		PublicURLID: "public_url_1", TeamID: "team_1", DomainID: "domain_1",
		Identifier: "*.member.tunnels.example.test", AuthorizationID: "authorization_1",
		PresentationReference: "presentation_1", State: "presenting", ChallengeDigest: digest,
		Presentations: []controlstate.DNSChallengePresentation{{ChallengeDigest: digest, Active: true}},
	}}, record
}
