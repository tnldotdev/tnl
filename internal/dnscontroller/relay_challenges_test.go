package dnscontroller

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
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
	provider := &challengeProviderStub{zone: Zone{ID: "ZSERVER", Nameservers: []string{"ns-1.example.test", "ns-2.example.test"}}}
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

func TestRelayChallengeManagerWaitsForRoute53Propagation(t *testing.T) {
	digest := sha256.Sum256([]byte("relay"))
	store := &relayChallengeStoreStub{challenge: controlstate.RelayDNSChallengeContext{
		OrderID: "relay_certificate_order_1", RelayServiceID: "relay-a", TLSServerName: "relay-a.tnl.example.test",
		State: "presented", ChallengeDigest: digest, PresentationReference: "presentation_1",
		Presentations: []controlstate.DNSChallengePresentation{{ChallengeDigest: digest, Active: true}},
	}}
	provider := &challengeProviderStub{zone: Zone{ID: "ZSERVER", Nameservers: []string{"ns-1.example.test", "ns-2.example.test"}}, pending: true}
	verifier := &challengeVerifierStub{verified: true}
	manager, err := NewRelayChallengeManager(store, provider, verifier, "tnl.example.test", "ZSERVER")
	if err != nil {
		t.Fatal(err)
	}
	ready, err := manager.Verify(t.Context(), store.challenge.OrderID)
	if err != nil || ready || verifier.calls != 0 {
		t.Fatalf("relay validation before INSYNC: ready=%t checks=%d error=%v", ready, verifier.calls, err)
	}
	provider.pending = false
	ready, err = manager.Verify(t.Context(), store.challenge.OrderID)
	if err != nil || !ready || verifier.calls != 1 {
		t.Fatalf("relay validation after INSYNC: ready=%t checks=%d error=%v", ready, verifier.calls, err)
	}
}

type relayChallengeStoreStub struct {
	challengeStoreStub
	challenge controlstate.RelayDNSChallengeContext
}

func TestRelayChallengeManagerFailedCleanupAndDomainGuards(t *testing.T) {
	for _, hostname := range []string{"relay-a.tnl.example.test", "relay-a.other.test", "relay-a.nottnl.example.test"} {
		t.Run(hostname, func(t *testing.T) {
			digest := sha256.Sum256([]byte("failed challenge"))
			store := &relayChallengeStoreStub{challenge: controlstate.RelayDNSChallengeContext{OrderID: "relay_order_1", RelayServiceID: "relay-a", TLSServerName: hostname, State: "failed_cleaning", ChallengeDigest: digest, PresentationReference: "presentation_1", Presentations: []controlstate.DNSChallengePresentation{{ChallengeDigest: digest}}}}
			provider, verifier := &challengeProviderStub{}, &challengeVerifierStub{}
			manager, err := NewRelayChallengeManager(store, provider, verifier, "tnl.example.test", "ZSERVER")
			if err != nil {
				t.Fatal(err)
			}
			err = manager.Cleanup(t.Context(), "relay_order_1")
			if hostname == "relay-a.tnl.example.test" {
				if err != nil || provider.calls != 1 || len(provider.record.DesiredOwnedValues) != 0 || !slices.Equal(provider.record.PreviouslyOwnedValues, []string{base64.RawURLEncoding.EncodeToString(digest[:])}) {
					t.Fatalf("failed cleanup: error %v, provider %#v", err, provider)
				}
				provider.calls = 0
				if err := manager.Present(t.Context(), "relay_order_1"); err == nil {
					t.Error("failed cleanup allowed presentation")
				}
				if valid, err := manager.Verify(t.Context(), "relay_order_1"); err == nil || valid {
					t.Errorf("failed cleanup allowed verification: %v, %v", valid, err)
				}
			} else {
				var terminal *terminalError
				if !errors.As(err, &terminal) {
					t.Fatalf("out-of-domain cleanup = %v", err)
				}
			}
			if provider.calls != 0 || verifier.calls != 0 {
				t.Fatalf("unsafe DNS work: provider %d, verifier %d", provider.calls, verifier.calls)
			}
		})
	}
}

func (s *relayChallengeStoreStub) GetRelayDNSChallengeContext(context.Context, string) (controlstate.RelayDNSChallengeContext, error) {
	return s.challenge, nil
}
