package dnscontroller

import (
	"context"
	"errors"
	"testing"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
)

type subjectChallengeStoreStub struct {
	challengeStoreStub
	lookups []controlstate.CertificateSubject
	locked  bool
	stale   bool
}

func (s *subjectChallengeStoreStub) GetDNSChallengeContextForSubject(_ context.Context, subject controlstate.CertificateSubject, _ string) (controlstate.DNSChallengeContext, error) {
	s.lookups = append(s.lookups, subject)
	if len(s.lookups) == 2 && !s.locked {
		return controlstate.DNSChallengeContext{}, errors.New("subject reload escaped DNS record lock")
	}
	challenge := s.challenge
	challenge.Subject = subject
	if s.locked && s.stale {
		challenge.Subject.RunNumber++
	}
	return challenge, nil
}

func (s *subjectChallengeStoreStub) WithDNSRecordLock(ctx context.Context, record string, run func() error) error {
	return s.challengeStoreStub.WithDNSRecordLock(ctx, record, func() error {
		s.locked = true
		defer func() { s.locked = false }()
		return run()
	})
}

func TestDNSChallengeSubjectBoundary(t *testing.T) {
	for _, subject := range []controlstate.CertificateSubject{
		{Kind: controlstate.CertificateSubjectPublicURL, ID: "psvc_misleading-public-id", RunID: "public-run", RunNumber: 3},
		{Kind: controlstate.CertificateSubjectManagedService, ID: "opaque-managed-id", RunID: "private-run", RunNumber: 5},
	} {
		for _, stale := range []bool{false, true} {
			t.Run(string(subject.Kind)+map[bool]string{false: "/current", true: "/stale-under-lock"}[stale], func(t *testing.T) {
				store := &subjectChallengeStoreStub{stale: stale, challengeStoreStub: challengeStoreStub{challenge: controlstate.DNSChallengeContext{Identifier: "app.example.test", State: controlstate.ACMEAuthorizationPresenting}}}
				provider := &challengeProviderStub{}
				manager, err := NewChallengeManager(store, provider, &challengeVerifierStub{}, Config{ManagedDomain: "example.test", ManagedZoneID: "zone"})
				if err != nil {
					t.Fatal(err)
				}
				err = manager.PresentSubject(t.Context(), subject, "authorization")
				if stale {
					if !errors.Is(err, controlstate.ErrDNSChallengeNotFound) || provider.calls != 0 {
						t.Fatalf("crossed subject reached provider: calls=%d, %v", provider.calls, err)
					}
				} else if err != nil || provider.calls != 1 {
					t.Fatalf("typed DNS presentation: calls=%d, %v", provider.calls, err)
				}
				if len(store.lookups) != 2 || store.lookups[0] != subject || store.lookups[1] != subject {
					t.Fatal("DNS subject was not retained across the record lock")
				}
			})
		}
	}
}
