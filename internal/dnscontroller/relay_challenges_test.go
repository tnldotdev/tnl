package dnscontroller

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"slices"
	"testing"

	"github.com/tnldotdev/tnl/internal/controlstate"
)

func TestRelayChallengeManagerReconcilesDurablePresentationSet(t *testing.T) {
	current := sha256.Sum256([]byte("current"))
	concurrent := sha256.Sum256([]byte("concurrent"))
	store := &relayChallengeStoreStub{challenge: controlstate.RelayDNSChallengeContext{
		OrderID: "relay_certificate_order_1", RelayServiceID: "relay-a", TLSServerName: "relay-a.tnl.example.test",
		State: "presenting", ChallengeDigest: current, PresentationReference: "relay_acme_presentation_1",
		Presentations: []controlstate.DNSChallengePresentation{
			{ChallengeDigest: current, Active: true}, {ChallengeDigest: concurrent, Active: true},
		},
	}}
	provider := &challengeProviderStub{zone: Zone{ID: "ZSERVER", Nameservers: []string{"ns-1.example.test"}}}
	verifier := &challengeVerifierStub{verified: true}
	manager, err := NewRelayChallengeManager(store, provider, verifier, "tnl.example.test", "ZSERVER")
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Present(t.Context(), store.challenge.OrderID); err != nil {
		t.Fatal(err)
	}
	wantValues := []string{
		base64.RawURLEncoding.EncodeToString(concurrent[:]), base64.RawURLEncoding.EncodeToString(current[:]),
	}
	slices.Sort(wantValues)
	if provider.record.RecordName != "_acme-challenge.relay-a.tnl.example.test" || provider.record.ZoneID != "ZSERVER" ||
		!slices.Equal(provider.record.DesiredOwnedValues, wantValues) || provider.record.ClaimedZone {
		t.Fatalf("presented relay challenge = %#v", provider.record)
	}
	store.challenge.State = "presented"
	verified, err := manager.Verify(t.Context(), store.challenge.OrderID)
	if err != nil || !verified || verifier.expected != base64.RawURLEncoding.EncodeToString(current[:]) {
		t.Fatalf("verified = %v, expected %q, error %v", verified, verifier.expected, err)
	}
	store.challenge.State = "cleaning"
	store.challenge.Presentations[0].Active = false
	if err := manager.Cleanup(t.Context(), store.challenge.OrderID); err != nil {
		t.Fatal(err)
	}
	wantRemaining := []string{base64.RawURLEncoding.EncodeToString(concurrent[:])}
	if !slices.Equal(provider.record.DesiredOwnedValues, wantRemaining) {
		t.Fatalf("cleaned relay challenge = %#v", provider.record)
	}
}

type relayChallengeStoreStub struct {
	challenge controlstate.RelayDNSChallengeContext
}

func (s *relayChallengeStoreStub) GetRelayDNSChallengeContext(context.Context, string) (controlstate.RelayDNSChallengeContext, error) {
	return s.challenge, nil
}
