package state

import (
	"crypto/sha256"
	"testing"
	"time"
)

func TestIntegrationDNSAggregationRestorationCurrentOrdersCleanIndependently(t *testing.T) {
	f := newServicePublicationFixture(t)
	d, now := f.database, f.now
	plan := f.prepared.CertificatePlan
	if plan.ChallengeMethod != "dns-01" || len(plan.Identifiers) != 1 {
		t.Fatal("aggregation requires the current exact-host DNS certificate plan", plan)
	}
	orders := make([]ACMEOrderWork, 2)
	for index := range orders {
		orders[index] = createPlanIssuanceWork(t, d, now, f.run, plan, false, func(work *ACMEOrderWork) {
			// only the CA exchange is replaced. distinct CSRs use the current run's
			// real issuance authorization and the same approved exact-host plan.
			work.AvailableAt = now.Add(time.Duration(index+1) * time.Second)
			authorization := &work.Authorizations[0]
			authorization.ChallengeToken = "aggregation-" + work.ID
			authorization.ChallengeDigest = sha256.Sum256([]byte(authorization.ChallengeToken))
		})
		if _, err := d.GetServiceCertificateIssuance(t.Context(), f.service.ID, f.run.RunID, f.run.Token, orders[index].ID, now); err != nil {
			t.Fatal("current run could not read its authorized order", err)
		}
		if len(orders[index].Authorizations) != 1 || orders[index].Subject != orders[0].Subject {
			t.Fatal("orders did not retain the same current certificate subject")
		}
	}
	first, second := orders[0].Authorizations[0], orders[1].Authorizations[0]
	if orders[0].ID == orders[1].ID || first.ID == second.ID ||
		first.Identifier != plan.Identifiers[0] || second.Identifier != first.Identifier ||
		first.ChallengeDigest == second.ChallengeDigest || first.PresentationReference == second.PresentationReference {
		t.Fatal("two independent current orders did not share exactly one DNS record")
	}
	assertPresentations := func(active [2]bool) {
		t.Helper()
		want := map[[32]byte]bool{first.ChallengeDigest: active[0], second.ChallengeDigest: active[1]}
		for _, order := range orders {
			authorization := order.Authorizations[0]
			challenge, err := d.GetDNSChallengeContextForSubject(t.Context(), order.Subject, authorization.ID)
			if err != nil {
				t.Fatal("real subject-bound DNS lookup", err)
			}
			if challenge.Subject != order.Subject || challenge.ServiceID != f.service.ID ||
				challenge.Identifier != first.Identifier || challenge.ChallengeDigest != authorization.ChallengeDigest ||
				challenge.PresentationReference != authorization.PresentationReference || len(challenge.Presentations) != 2 {
				t.Fatalf("lookup lost its exact subject or shared record: %#v", challenge)
			}
			seen := make(map[[32]byte]bool)
			for _, presentation := range challenge.Presentations {
				expected, found := want[presentation.ChallengeDigest]
				if !found || seen[presentation.ChallengeDigest] || presentation.Active != expected {
					t.Fatalf("lookup changed an exact digest or active flag: %#v, want %v", challenge.Presentations, active)
				}
				seen[presentation.ChallengeDigest] = true
			}
		}
	}
	assertPresentations([2]bool{true, true})
	for index := range orders {
		at := now.Add(time.Duration(index+1) * time.Second)
		work, found, err := d.ClaimACMEOrderWork(t.Context(), "aggregation-cleanup", at, time.Minute)
		if err != nil || !found || work.ID != orders[index].ID {
			t.Fatalf("claim exact order for cleanup: found=%t order=%s: %v", found, work.ID, err)
		}
		work.State, work.AvailableAt = ACMEOrderCanceled, at
		work.Authorizations[0].State, work.Authorizations[0].AvailableAt = ACMEAuthorizationCleaning, at
		orders[index], err = d.SaveACMEOrderWork(t.Context(), work, at)
		if err != nil {
			t.Fatal("save independent DNS cleanup", err)
		}
		active := [2]bool{false, index == 0}
		assertPresentations(active)
		work, found, err = d.ClaimACMEOrderWork(t.Context(), "aggregation-cleanup-complete", at, time.Minute)
		if err != nil || !found || work.ID != orders[index].ID {
			t.Fatalf("reclaim exact cleaning order: found=%t order=%s: %v", found, work.ID, err)
		}
		work.Authorizations[0].State, work.Authorizations[0].CleanupCompletedAt = ACMEAuthorizationComplete, &at
		orders[index], err = d.SaveACMEOrderWork(t.Context(), work, at)
		if err != nil {
			t.Fatal("complete independent DNS cleanup", err)
		}
		assertPresentations(active)
	}
	if _, found, err := d.ClaimACMEOrderWork(t.Context(), "aggregation-after-cleanup", now.Add(3*time.Second), time.Minute); err != nil || found {
		t.Fatal("completed DNS cleanup remained claimable", found, err)
	}
}
