package dnscontroller

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"slices"
	"testing"

	"github.com/tnldotdev/tnl/internal/controlstate"
)

func TestChallengeManagerReconcilesDurablePresentationSet(t *testing.T) {
	current := sha256.Sum256([]byte("current"))
	concurrent := sha256.Sum256([]byte("concurrent"))
	store := &challengeStoreStub{challenge: controlstate.DNSChallengeContext{
		RouteID: "route_1", TeamID: "team_1", DomainID: "domain_1",
		CanonicalDomain: "tunnels.example.test", AuthorizationID: "acme_authorization_1",
		Identifier: "*.member.tunnels.example.test", PresentationReference: "acme_presentation_1", State: "presenting",
		ChallengeDigest: current,
		Presentations: []controlstate.DNSChallengePresentation{
			{ChallengeDigest: current, Active: true}, {ChallengeDigest: concurrent, Active: true},
		},
	}}
	provider := &challengeProviderStub{zone: Zone{ID: "ZMANAGED", Nameservers: []string{"ns-1.example.test", "ns-2.example.test"}}}
	verifier := &challengeVerifierStub{verified: true}
	manager, err := NewChallengeManager(store, provider, verifier, Config{
		ManagedDomain: "tunnels.example.test", ManagedZoneID: "ZMANAGED",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Present(t.Context(), "route_1", "acme_authorization_1"); err != nil {
		t.Fatal(err)
	}
	wantValues := []string{
		base64.RawURLEncoding.EncodeToString(concurrent[:]), base64.RawURLEncoding.EncodeToString(current[:]),
	}
	slices.Sort(wantValues)
	if provider.record.RecordName != "_acme-challenge.member.tunnels.example.test" ||
		!slices.Equal(provider.record.DesiredOwnedValues, wantValues) || provider.record.ClaimedZone {
		t.Fatalf("presented challenge record = %#v", provider.record)
	}
	store.challenge.State = "presented"
	verified, err := manager.Verify(t.Context(), "route_1", "acme_authorization_1")
	if err != nil || !verified || verifier.expected != base64.RawURLEncoding.EncodeToString(current[:]) {
		t.Fatalf("verified = %v, expected %q, error %v", verified, verifier.expected, err)
	}
	store.challenge.State = "cleaning"
	store.challenge.Presentations[0].Active = false
	if err := manager.Cleanup(t.Context(), "route_1", "acme_authorization_1"); err != nil {
		t.Fatal(err)
	}
	wantRemaining := []string{base64.RawURLEncoding.EncodeToString(concurrent[:])}
	if !slices.Equal(provider.record.DesiredOwnedValues, wantRemaining) ||
		!slices.Equal(provider.record.PreviouslyOwnedValues, wantValues) {
		t.Fatalf("cleaned challenge record = %#v", provider.record)
	}
}

func TestChallengeManagerUsesOwnedClaimedZone(t *testing.T) {
	digest := sha256.Sum256([]byte("claimed"))
	store := &challengeStoreStub{
		challenge: controlstate.DNSChallengeContext{
			RouteID: "route_1", TeamID: "team_1", DomainID: "domain_1", DNSAuthorityReference: "dns_authority_1",
			CanonicalDomain: "claimed.example.test", AuthorizationID: "acme_authorization_1",
			Identifier: "api.claimed.example.test", PresentationReference: "acme_presentation_1", State: "presenting",
			ChallengeDigest: digest,
			Presentations:   []controlstate.DNSChallengePresentation{{ChallengeDigest: digest, Active: true}},
		},
		authority: controlstate.DNSAuthority{
			Reference: "dns_authority_1", TeamID: "team_1", DomainID: "domain_1", CanonicalDomain: "claimed.example.test",
			State: "active", ProviderZoneID: "ZCLAIMED",
		},
	}
	provider := &challengeProviderStub{zone: Zone{ID: "ZCLAIMED", Nameservers: []string{"ns-1.example.test", "ns-2.example.test"}}}
	manager, err := NewChallengeManager(store, provider, &challengeVerifierStub{}, Config{
		ManagedDomain: "tunnels.example.test", ManagedZoneID: "ZMANAGED",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Present(t.Context(), "route_1", "acme_authorization_1"); err != nil {
		t.Fatal(err)
	}
	if !provider.record.ClaimedZone || provider.record.ZoneID != "ZCLAIMED" ||
		provider.record.AuthorityReference != "dns_authority_1" {
		t.Fatalf("claimed challenge record = %#v", provider.record)
	}
}

type challengeStoreStub struct {
	challenge controlstate.DNSChallengeContext
	authority controlstate.DNSAuthority
}

func (s *challengeStoreStub) GetDNSChallengeContext(context.Context, string, string) (controlstate.DNSChallengeContext, error) {
	return s.challenge, nil
}

func (s *challengeStoreStub) GetDNSAuthority(context.Context, string) (controlstate.DNSAuthority, error) {
	return s.authority, nil
}

type challengeProviderStub struct {
	record ChallengeRecord
	zone   Zone
}

func (s *challengeProviderStub) ReconcileChallenge(_ context.Context, record ChallengeRecord) (Zone, error) {
	s.record = record
	return s.zone, nil
}

type challengeVerifierStub struct {
	expected string
	verified bool
}

func (s *challengeVerifierStub) VerifyChallenge(_ context.Context, _, expected string, _ []string) (bool, error) {
	s.expected = expected
	return s.verified, nil
}
