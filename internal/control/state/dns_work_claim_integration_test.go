package state

import (
	"errors"
	"testing"
	"time"
)

func TestIntegrationDNSWorkClaimsWithoutIngressAndRejectsReplacedWorker(t *testing.T) {
	f := newPublishRunFixture(t)
	prepared := createPlanIssuanceWork(t, f.database, f.now, f.authentication(), f.certificatePlan(), false, nil)
	original, found, err := f.database.ClaimACMEOrderWork(t.Context(), "original", f.now, time.Second)
	if err != nil || !found || original.ID != prepared.ID || original.ChallengeMethod != "dns-01" {
		t.Fatalf("DNS claim without ingress: found=%t method=%s error=%v", found, original.ChallengeMethod, err)
	}
	if _, found, err := f.database.ClaimACMEOrderWork(t.Context(), "competitor", f.now, time.Second); err != nil || found {
		t.Fatalf("live claim lost exclusion: found=%t error=%v", found, err)
	}
	at := f.now.Add(2 * time.Second)
	replacement, found, err := f.database.ClaimACMEOrderWork(t.Context(), "replacement", at, time.Minute)
	if err != nil || !found || replacement.ID != original.ID || replacement.WorkEpoch != original.WorkEpoch+1 {
		t.Fatalf("DNS claim handoff: found=%t error=%v", found, err)
	}
	if _, err := f.database.SaveACMEOrderWork(t.Context(), original, at); !errors.Is(err, ErrACMEWorkStale) {
		t.Fatalf("replaced DNS worker saved: %v", err)
	}
	replacement.Authorizations[0].State = "presented"
	replacement.Authorizations[0].PresentedAt = &at
	replacement.AvailableAt = at.Add(time.Minute)
	if _, err := f.database.SaveACMEOrderWork(t.Context(), replacement, at); err != nil {
		t.Fatal(err)
	}
	if _, found, err := f.database.ClaimACMEOrderWork(t.Context(), "early", at.Add(time.Second), time.Minute); err != nil || found {
		t.Fatalf("DNS poll deadline bypassed: found=%t error=%v", found, err)
	}
}
