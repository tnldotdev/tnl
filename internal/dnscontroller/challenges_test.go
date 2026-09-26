package dnscontroller

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/tnldotdev/tnl/internal/controlstate"
)

func TestChallengeManagerReconcilesDurablePresentationSet(t *testing.T) {
	current := sha256.Sum256([]byte("current"))
	concurrent := sha256.Sum256([]byte("concurrent"))
	store := &challengeStoreStub{challenge: controlstate.DNSChallengeContext{
		PublicURLID: "public_url_1", TeamID: "team_1", DomainID: "domain_1",
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
	if err := manager.Present(t.Context(), "public_url_1", "acme_authorization_1"); err != nil {
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
	verified, err := manager.Verify(t.Context(), "public_url_1", "acme_authorization_1")
	if err != nil || !verified || verifier.expected != base64.RawURLEncoding.EncodeToString(current[:]) {
		t.Fatalf("verified = %v, expected %q, error %v", verified, verifier.expected, err)
	}
	store.challenge.State = "cleaning"
	store.challenge.Presentations[0].Active = false
	if err := manager.Cleanup(t.Context(), "public_url_1", "acme_authorization_1"); err != nil {
		t.Fatal(err)
	}
	wantRemaining := []string{base64.RawURLEncoding.EncodeToString(concurrent[:])}
	if !slices.Equal(provider.record.DesiredOwnedValues, wantRemaining) ||
		!slices.Equal(provider.record.PreviouslyOwnedValues, wantValues) {
		t.Fatalf("cleaned challenge record = %#v", provider.record)
	}
}

func TestChallengeManagerUsesOwnedClaimedZone(t *testing.T) {
	for _, phase := range []string{"presenting", "presented", "cleaning"} {
		t.Run(phase, func(t *testing.T) {
			store := claimedChallengeStore()
			store.challenge.State = phase
			store.challenge.Presentations[0].Active = phase != "cleaning"
			provider := &challengeProviderStub{zone: Zone{ID: "ZCLAIMED", Nameservers: []string{"ns-1.example.test", "ns-2.example.test"}}}
			verifier := &challengeVerifierStub{verified: true}
			manager, err := NewChallengeManager(store, provider, verifier, Config{
				ManagedDomain: "tunnels.example.test", ManagedZoneID: "ZMANAGED",
			})
			if err != nil {
				t.Fatal(err)
			}
			switch phase {
			case "presenting":
				err = manager.Present(t.Context(), "public_url_1", "acme_authorization_1")
			case "presented":
				var verified bool
				verified, err = manager.Verify(t.Context(), "public_url_1", "acme_authorization_1")
				if !verified || verifier.expected != base64.RawURLEncoding.EncodeToString(store.challenge.ChallengeDigest[:]) ||
					verifier.recordName != "_acme-challenge.api.claimed.example.test" || !slices.Equal(verifier.nameservers, provider.zone.Nameservers) {
					t.Errorf("verification = %v, verifier %#v", verified, verifier)
				}
			case "cleaning":
				err = manager.Cleanup(t.Context(), "public_url_1", "acme_authorization_1")
			}
			if err != nil {
				t.Fatal(err)
			}
			if provider.calls != 1 || !provider.record.ClaimedZone || provider.record.ZoneID != "ZCLAIMED" ||
				provider.record.AuthorityReference != "dns_authority_1" || len(provider.record.PreviouslyOwnedValues) != 1 ||
				(phase == "cleaning" && len(provider.record.DesiredOwnedValues) != 0) {
				t.Fatalf("claimed challenge record = %#v, calls %d", provider.record, provider.calls)
			}
		})
	}
}

func TestChallengeManagerClaimedAuthorityGuards(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*challengeStoreStub)
	}{
		{"missing_reference", func(s *challengeStoreStub) { s.challenge.DNSAuthorityReference = "" }},
		{"reference", func(s *challengeStoreStub) { s.authority.Reference = "dns_authority_other" }},
		{"identifier", func(s *challengeStoreStub) { s.challenge.Identifier = "api.notclaimed.example.test" }},
		{"team", func(s *challengeStoreStub) { s.authority.TeamID = "other_team" }},
		{"domain_id", func(s *challengeStoreStub) { s.authority.DomainID = "other_domain" }},
		{"domain_name", func(s *challengeStoreStub) { s.authority.CanonicalDomain = "other.example.test" }},
		{"missing_zone", func(s *challengeStoreStub) { s.authority.ProviderZoneID = "" }},
		{"pending", func(s *challengeStoreStub) { s.authority.State = "pending" }},
		{"released", func(s *challengeStoreStub) { s.authority.State = "released" }},
		{"failed", func(s *challengeStoreStub) { s.authority.State = "failed" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, phase := range []string{"presenting", "presented", "cleaning"} {
				t.Run(phase, func(t *testing.T) {
					store := claimedChallengeStore()
					test.change(store)
					store.challenge.State = phase
					provider, verifier := &challengeProviderStub{}, &challengeVerifierStub{}
					manager, err := NewChallengeManager(store, provider, verifier, Config{ManagedDomain: "tunnels.example.test", ManagedZoneID: "ZMANAGED"})
					if err != nil {
						t.Fatal(err)
					}
					switch phase {
					case "presenting":
						err = manager.Present(t.Context(), "public_url_1", "acme_authorization_1")
					case "presented":
						_, err = manager.Verify(t.Context(), "public_url_1", "acme_authorization_1")
					case "cleaning":
						err = manager.Cleanup(t.Context(), "public_url_1", "acme_authorization_1")
					}
					var terminal *terminalError
					if !errors.As(err, &terminal) || provider.calls != 0 || verifier.calls != 0 {
						t.Fatalf("unsafe authority: error %v, provider calls %d, verifier calls %d", err, provider.calls, verifier.calls)
					}
				})
			}
		})
	}
}

func TestChallengeManagerReleasingAuthorityAllowsOnlyCleanup(t *testing.T) {
	for _, phase := range []string{"presenting", "presented", "cleaning"} {
		t.Run(phase, func(t *testing.T) {
			store := claimedChallengeStore()
			store.authority.State, store.challenge.State = "releasing", phase
			store.challenge.Presentations[0].Active = phase != "cleaning"
			provider, verifier := &challengeProviderStub{}, &challengeVerifierStub{}
			manager, err := NewChallengeManager(store, provider, verifier, Config{ManagedDomain: "tunnels.example.test", ManagedZoneID: "ZMANAGED"})
			if err != nil {
				t.Fatal(err)
			}
			switch phase {
			case "presenting":
				err = manager.Present(t.Context(), "public_url_1", "acme_authorization_1")
			case "presented":
				_, err = manager.Verify(t.Context(), "public_url_1", "acme_authorization_1")
			case "cleaning":
				err = manager.Cleanup(t.Context(), "public_url_1", "acme_authorization_1")
			}
			if phase == "cleaning" {
				if err != nil || provider.calls != 1 || len(provider.record.DesiredOwnedValues) != 0 || len(provider.record.PreviouslyOwnedValues) != 1 {
					t.Fatalf("release cleanup: error %v, provider %#v", err, provider)
				}
			} else if err == nil || provider.calls != 0 || verifier.calls != 0 {
				t.Fatalf("new work during release: error %v, provider %#v, verifier %#v", err, provider, verifier)
			}
		})
	}
}

func claimedChallengeStore() *challengeStoreStub {
	digest := sha256.Sum256([]byte("claimed"))
	return &challengeStoreStub{
		challenge: controlstate.DNSChallengeContext{
			PublicURLID: "public_url_1", TeamID: "team_1", DomainID: "domain_1", DNSAuthorityReference: "dns_authority_1",
			CanonicalDomain: "claimed.example.test", AuthorizationID: "acme_authorization_1",
			Identifier: "api.claimed.example.test", PresentationReference: "acme_presentation_1", State: "presenting",
			ChallengeDigest: digest,
			Presentations:   []controlstate.DNSChallengePresentation{{ChallengeDigest: digest, Active: true}},
		},
		authority: controlstate.DNSAuthority{
			Reference: "dns_authority_1", TeamID: "team_1", DomainID: "domain_1", CanonicalDomain: "claimed.example.test",
			State: "ready", ProviderZoneID: "ZCLAIMED",
		},
	}
}

func TestChallengeManagerRejectsWrongPhaseBeforeDNSWork(t *testing.T) {
	for _, state := range []string{"presenting", "presented", "validating", "valid", "cleaning", "complete", "canceled", "failed"} {
		for _, operation := range []string{"present", "verify", "cleanup"} {
			if (operation == "present" && state == "presenting") || (operation == "verify" && state == "presented") || (operation == "cleanup" && state == "cleaning") {
				continue
			}
			t.Run(state+"/"+operation, func(t *testing.T) {
				store := claimedChallengeStore()
				store.challenge.CanonicalDomain, store.challenge.Identifier, store.challenge.State = "tunnels.example.test", "api.tunnels.example.test", state
				store.challenge.DNSAuthorityReference = ""
				provider, verifier := &challengeProviderStub{}, &challengeVerifierStub{}
				manager, err := NewChallengeManager(store, provider, verifier, Config{ManagedDomain: "tunnels.example.test", ManagedZoneID: "ZMANAGED"})
				if err != nil {
					t.Fatal(err)
				}
				switch operation {
				case "present":
					err = manager.Present(t.Context(), "public_url_1", "acme_authorization_1")
				case "verify":
					_, err = manager.Verify(t.Context(), "public_url_1", "acme_authorization_1")
				case "cleanup":
					err = manager.Cleanup(t.Context(), "public_url_1", "acme_authorization_1")
				}
				var terminal *terminalError
				if !errors.As(err, &terminal) || provider.calls != 0 || verifier.calls != 0 {
					t.Fatalf("wrong phase: error %v, provider calls %d, verifier calls %d", err, provider.calls, verifier.calls)
				}
			})
		}
	}
}

func TestChallengeManagerResolvesHostedManagedContext(t *testing.T) {
	for _, test := range []struct {
		name, reference, identifier, domain string
		valid                               bool
	}{
		{"implicit", "", "*.member.tunnels.example.test", "", true},
		{"opaque_without_authority", hostedManagedAuthorityReference, "*.member.tunnels.example.test", "", true},
		{"known_managed_domain", hostedManagedAuthorityReference, "*.member.tunnels.example.test", "tunnels.example.test", true},
		{"suffix_boundary", hostedManagedAuthorityReference, "*.member.nottunnels.example.test", "", false},
		{"outside", hostedManagedAuthorityReference, "*.member.other.test", "", false},
		{"domain_mismatch", hostedManagedAuthorityReference, "*.member.tunnels.example.test", "claimed.example.test", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := claimedChallengeStore()
			store.challenge.CanonicalDomain = test.domain
			store.challenge.DNSAuthorityReference, store.challenge.Identifier = test.reference, test.identifier
			store.authorityErr = controlstate.ErrDNSAuthorityNotFound
			provider := &challengeProviderStub{}
			manager, err := NewChallengeManager(store, provider, &challengeVerifierStub{}, Config{ManagedDomain: "tunnels.example.test", ManagedZoneID: "ZMANAGED"})
			if err != nil {
				t.Fatal(err)
			}
			err = manager.Present(t.Context(), "public_url_1", "acme_authorization_1")
			if test.valid {
				if err != nil || store.authorityCalls != 0 || provider.calls != 1 || provider.record.ZoneID != "ZMANAGED" || provider.record.ZoneDomain != "tunnels.example.test" || provider.record.ClaimedZone {
					t.Fatalf("managed context: error %v, provider %#v", err, provider)
				}
			} else if err == nil || provider.calls != 0 {
				t.Fatalf("invalid managed context: error %v, calls %d", err, provider.calls)
			}
		})
	}
}

type challengeStoreStub struct {
	challenge      controlstate.DNSChallengeContext
	authority      controlstate.DNSAuthority
	authorityErr   error
	authorityCalls int
	getContext     func(context.Context, string, string) (controlstate.DNSChallengeContext, error)
	lock           sync.Mutex
	lockRequested  func()
}

func (s *challengeStoreStub) WithDNSChallengeLock(_ context.Context, _ string, run func() error) error {
	if s.lockRequested != nil {
		s.lockRequested()
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	return run()
}

func (s *challengeStoreStub) GetDNSChallengeContext(ctx context.Context, publicURLID, authorizationID string) (controlstate.DNSChallengeContext, error) {
	if s.getContext != nil {
		return s.getContext(ctx, publicURLID, authorizationID)
	}
	return s.challenge, nil
}

func (s *challengeStoreStub) GetDNSAuthority(context.Context, string) (controlstate.DNSAuthority, error) {
	s.authorityCalls++
	return s.authority, s.authorityErr
}

type challengeProviderStub struct {
	mu        sync.Mutex
	record    ChallengeRecord
	zone      Zone
	calls     int
	reconcile func(context.Context, ChallengeRecord) (Zone, error)
}

func (s *challengeProviderStub) ReconcileChallenge(ctx context.Context, record ChallengeRecord) (Zone, error) {
	s.mu.Lock()
	s.record = record
	s.calls++
	zone, reconcile := s.zone, s.reconcile
	s.mu.Unlock()
	if reconcile != nil {
		return reconcile(ctx, record)
	}
	return zone, nil
}

type challengeVerifierStub struct {
	expected    string
	verified    bool
	calls       int
	recordName  string
	nameservers []string
}

func (s *challengeVerifierStub) VerifyChallenge(_ context.Context, recordName, expected string, nameservers []string) (bool, error) {
	s.expected = expected
	s.calls++
	s.recordName, s.nameservers = recordName, slices.Clone(nameservers)
	return s.verified, nil
}
