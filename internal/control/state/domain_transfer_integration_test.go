package state

import (
	"crypto/sha256"
	"errors"
	"slices"
	"testing"
	"time"
)

func TestIntegrationDomainTransferKeepsDelegation(t *testing.T) {
	d, now, actor, destination := newAuthorityTeam(t)
	ctx := t.Context()
	identity, err := d.IdentityContext(ctx, actor)
	if err != nil {
		t.Fatal(err)
	}
	source := identity.PersonalTeamID
	domain := readyTransferDomain(t, d, actor, source, "dev.example.test", now)
	if _, err := d.SetTeamDefaultDomain(ctx, actor, source, domain.ID, now); err != nil {
		t.Fatal(err)
	}
	transferred, err := d.TransferDomain(ctx, actor, domain.CanonicalDomain, destination.ID, false, now)
	if err != nil || transferred.State != "transferred" {
		t.Fatalf("transfer = %#v, %v", transferred, err)
	}
	saved, err := d.GetTeamDomain(ctx, actor, destination.ID, domain.ID, now)
	if err != nil || saved.State != DomainReady || saved.DNSAuthorityReference != domain.DNSAuthorityReference ||
		!slices.Equal(saved.RequiredRecords, domain.RequiredRecords) {
		t.Fatalf("destination did not inherit the verified delegation: %#v, %v", saved, err)
	}
	if _, err := d.GetTeamDomain(ctx, actor, source, domain.ID, now); !errors.Is(err, ErrDomainNotFound) {
		t.Fatalf("old owner retained domain access: %v", err)
	}
	for _, id := range []string{source, destination.ID} {
		team, err := d.GetTeam(ctx, actor, id)
		if err != nil || team.DefaultDomainID != destination.DefaultDomainID {
			t.Fatalf("team default = %#v, %v", team, err)
		}
	}
}

func TestIntegrationDomainTransferNeedsBothOwnersAndUnusedDomain(t *testing.T) {
	d, now, actor, source := newAuthorityTeam(t)
	ctx := t.Context()
	other := "identity_aya"
	insertAuthorityIdentity(t, d, other, "", false, now)
	request := authorityTeamRequest(other)
	request.DisplayName, request.MemberSlug = "nintendo", "aya"
	destination, err := d.CreateTeam(ctx, request, now)
	if err != nil {
		t.Fatal(err)
	}
	domain := readyTransferDomain(t, d, actor, source.ID, "dev.example.test", now)
	if _, err := d.TransferDomain(ctx, other, domain.CanonicalDomain, destination.ID, true, now); !errors.Is(err, ErrDomainNotFound) {
		t.Fatalf("destination accepted without offer: %v", err)
	}
	offer, err := d.TransferDomain(ctx, actor, domain.CanonicalDomain, destination.ID, false, now)
	if err != nil || offer.State != "offered" || offer.ExpiresAt == nil {
		t.Fatalf("offer = %#v, %v", offer, err)
	}
	if _, err := d.TransferDomain(ctx, actor, domain.CanonicalDomain, destination.ID, true, now); !errors.Is(err, ErrDomainNotFound) {
		t.Fatalf("source accepted without destination rights: %v", err)
	}
	if _, err := d.TransferDomain(ctx, other, domain.CanonicalDomain, destination.ID, true, *offer.ExpiresAt); !errors.Is(err, ErrDomainNotFound) {
		t.Fatalf("expired offer accepted: %v", err)
	}
	result, err := d.TransferDomain(ctx, other, domain.CanonicalDomain, destination.ID, true, now)
	if err != nil || result.State != "transferred" {
		t.Fatalf("accept = %#v, %v", result, err)
	}
	service, err := d.CreateServiceAt(ctx, destination.ID, other, "app", "transfer-app",
		ServicePlacement{DomainID: domain.ID}, now, ServiceMetadata{}, &ProjectServiceConfiguration{Target: "localhost:3000"})
	if err != nil {
		t.Fatal(err)
	}
	blocked, err := d.TransferDomain(ctx, other, domain.CanonicalDomain, source.ID, false, now)
	if err != nil || blocked.State != "blocked" || !slices.Contains(blocked.Blockers, "service: "+service.Endpoint.Hostname) {
		t.Fatalf("saved service did not block transfer: %#v, %v", blocked, err)
	}
}

func readyTransferDomain(t *testing.T, d *Database, actor, team, name string, now time.Time) Domain {
	t.Helper()
	ctx := t.Context()
	claimed, err := d.ClaimTeamDomain(ctx, ClaimDomainRequest{
		IdentityID: actor, TeamID: team, Domain: name, IdempotencyKey: name, RequestDigest: sha256.Sum256([]byte(name)),
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	work, found, err := d.ClaimDNSAuthorityWork(ctx, "domain-transfer", now, time.Minute)
	if err != nil || !found {
		t.Fatalf("claim DNS work = %t, %v", found, err)
	}
	work.State, work.ProviderZoneID, work.Nameservers = DNSAuthorityReady, "ZTRANSFER", []string{"ns-1.example.test"}
	if _, err := d.SaveDNSAuthorityWork(ctx, work, now); err != nil {
		t.Fatal(err)
	}
	ready, err := d.GetTeamDomain(ctx, actor, team, claimed.ID, now)
	if err != nil || ready.State != DomainReady {
		t.Fatalf("ready domain = %#v, %v", ready, err)
	}
	return ready
}
