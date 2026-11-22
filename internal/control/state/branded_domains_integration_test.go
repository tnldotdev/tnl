package state

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming"
)

func TestIntegrationBrandedDomainClaimLifecycle(t *testing.T) {
	db, now, owner, team := newAuthorityTeam(t)
	ctx := t.Context()
	const suffix = "dns.operator.example"
	if err := db.ReserveOperatorNameservers(ctx, suffix, "NBRAND"); err != nil {
		t.Fatal(err)
	}
	if err := db.ReserveOperatorNameservers(ctx, suffix, "NNEXT"); err == nil {
		t.Fatal("an existing nameserver name was repointed to a different set")
	}
	request := ClaimDomainRequest{
		TeamID: team.ID, IdentityID: owner, Domain: suffix, IdempotencyKey: "branded-claim",
		RequestDigest: sha256.Sum256([]byte("branded-claim")), MakeDefault: true,
		DelegationSetID: "NBRAND", NameserverDomain: suffix,
	}
	if _, err := db.ClaimTeamDomain(ctx, request, now); !errors.Is(err, ErrAuthorityConflict) {
		t.Fatalf("claim of nameserver parent: %v", err)
	}
	request.Domain = "dev.example.com"
	claimed, err := db.ClaimTeamDomain(ctx, request, now)
	if err != nil || claimed.ClaimStage != "checking_nameservers" || len(claimed.RequiredRecords) != 0 {
		t.Fatalf("new claim: %#v / %v", claimed, err)
	}
	next := func(at time.Time) DNSAuthorityWork {
		t.Helper()
		work, found, err := db.ClaimDNSAuthorityWork(ctx, "branded-worker", at, time.Minute)
		if err != nil || !found || work.Reference != claimed.DNSAuthorityReference {
			t.Fatalf("claim work: %#v / %t / %v", work, found, err)
		}
		return work
	}
	save := func(work DNSAuthorityWork, at time.Time) {
		t.Helper()
		if _, err := db.SaveDNSAuthorityWork(ctx, work, at); err != nil {
			t.Fatal(err)
		}
	}
	status := func(stage string, records int) Domain {
		t.Helper()
		domain, err := db.GetTeamDomain(ctx, owner, team.ID, claimed.ID, now)
		if err != nil || domain.ClaimStage != stage || len(domain.RequiredRecords) != records {
			t.Fatalf("claim status: %#v / %v", domain, err)
		}
		return domain
	}
	work := next(now)
	proof := work.ClaimProofValue
	if work.DelegationSetID != "NBRAND" || work.ClaimProofName != "_tnl-claim-dev.example.com" || proof == "" {
		t.Fatal("missing durable proof or delegation settings")
	}
	work.Nameservers, err = naming.BrandedNameservers(suffix)
	if err != nil {
		t.Fatal(err)
	}
	save(work, now)
	first := status("waiting_for_ownership", 1)
	request.NameserverDomain, request.DelegationSetID = "next.operator.example", "NNEXT"
	replay, err := db.ClaimTeamDomain(ctx, request, now)
	if err != nil || len(replay.RequiredRecords) != 1 || replay.RequiredRecords[0] != first.RequiredRecords[0] {
		t.Fatalf("configuration change rewrote a pending claim: %#v / %v", replay, err)
	}
	work = next(now)
	work.ClaimProofVerifiedAt = now
	save(work, now)
	status("preparing_zone", 0)
	work = next(now)
	work.ProviderZoneID = "ZBRAND"
	save(work, now)
	status("waiting_for_delegation", 4)
	work = next(now)
	work.State = DNSAuthorityReady
	save(work, now)
	if domain := status("", 4); domain.State != DomainReady {
		t.Fatalf("ready claim: %#v", domain)
	}
	current, err := db.GetTeam(ctx, owner, team.ID)
	if err != nil || current.DefaultDomainID != claimed.ID {
		t.Fatalf("ready default: %#v / %v", current, err)
	}
	if _, err := db.SetTeamDefaultDomain(ctx, owner, team.ID, team.DefaultDomainID, now); err != nil {
		t.Fatal(err)
	}
	if err := db.ReleaseTeamDomain(ctx, owner, team.ID, claimed.ID, now); err != nil {
		t.Fatal(err)
	}
	work = next(now.Add(time.Minute))
	work.State = DNSAuthorityReleased
	save(work, now.Add(time.Minute))
	request.IdempotencyKey = "fresh-claim"
	claimed, err = db.ClaimTeamDomain(ctx, request, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	work = next(now.Add(time.Minute))
	if work.ClaimProofValue == proof || work.DelegationSetID != "NNEXT" {
		t.Fatal("new claim reused the retired proof or delegation settings")
	}
	work.State, work.AvailableAt = DNSAuthorityFailed, work.ClaimExpiresAt.Add(time.Hour)
	save(work, now.Add(time.Minute))
	work = next(work.ClaimExpiresAt)
	if work.State != DNSAuthorityFailed {
		t.Fatalf("failed claim was not selected for expiry: %s", work.State)
	}
	work.State = DNSAuthorityReleasing
	save(work, work.ClaimExpiresAt)
}
