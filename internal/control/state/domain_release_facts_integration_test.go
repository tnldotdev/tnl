package state

import (
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestIntegrationDomainReleaseFacts(t *testing.T) {
	for _, phase := range []string{"saved-services", "saved-deployments", "endpoint-dns", "challenge-cleanup", "uncertain-issuance", "certificate-expiry", "known-expiry-unsettled-issuance", "provider-release"} {
		t.Run(phase, func(t *testing.T) {
			owner, member, domain, fixtures := sessionLockAuthorityFixtures(t)
			f := fixtures[0]
			d, now, ctx := f.database, f.now, t.Context()
			var certificate ACMEOrderWork
			if phase == "saved-deployments" {
				request := ApplyProjectConfigurationRequest{
					TeamID: member.TeamID, ActorID: owner, ProjectKey: "release-facts", ProjectLabel: "release-facts",
					SourceFingerprint: strings.Repeat("c", 64), Now: now,
					Configuration: ProjectConfiguration{Settings: &DeploymentSettings{DomainID: domain.ID},
						Services: map[string]ProjectServiceConfiguration{"web": {Protocol: "http", Target: "localhost:3000"}}},
				}
				if _, err := d.ApplyProjectConfiguration(ctx, selectedProjectRequest(request, "production")); err != nil {
					t.Fatal(err)
				}
			}
			if phase == "endpoint-dns" {
				setEndpointReadinessDNS(t, f, true, ServiceEndpointDNSPending)
			}
			if phase == "challenge-cleanup" || phase == "uncertain-issuance" ||
				phase == "certificate-expiry" || phase == "known-expiry-unsettled-issuance" {
				var err error
				f.run, err = d.StartServiceRun(ctx, f.service.ID, f.prepared.RunID, f.prepared.RunNumber, f.publisher, now)
				if err != nil {
					t.Fatal(err)
				}
				certificate = createPlanIssuanceWork(t, d, now, f.run, f.prepared.CertificatePlan,
					phase != "uncertain-issuance", func(work *ACMEOrderWork) {
						if phase == "uncertain-issuance" || phase == "known-expiry-unsettled-issuance" {
							work.State = ACMEOrderFinalizing
							work.OrderURL, work.FinalizeURL = "https://acme.example.test/order/1", "https://acme.example.test/finalize/1"
						}
					})
			}
			if err := d.ReleaseTeamDomain(ctx, owner, member.TeamID, domain.ID, now); err != nil {
				t.Fatal(err)
			}
			if phase != "saved-services" {
				for _, fixture := range fixtures {
					if err := d.DeleteService(ctx, fixture.service.ID, owner, now); err != nil {
						t.Fatal(err)
					}
				}
			}
			if phase == "challenge-cleanup" {
				if _, err := d.pool.Exec(ctx, `UPDATE control.acme_authorizations
					SET state='canceled',cleanup_completed_at=NULL WHERE order_id=$1`, certificate.ID); err != nil {
					t.Fatal(err)
				}
			}
			domains, err := d.ListTeamDomains(ctx, owner, member.TeamID)
			if err != nil {
				t.Fatal(err)
			}
			var selected Domain
			for _, candidate := range domains {
				if candidate.ID == domain.ID {
					selected = candidate
				}
			}
			facts := releaseFactsProjection(t, selected)
			wanted := map[string]string{"saved-services": "services", "saved-deployments": "deployments", "endpoint-dns": "endpoint_dns",
				"challenge-cleanup": "challenge_cleanup", "uncertain-issuance": "uncertain_issuance",
				"certificate-expiry": "certificate", "known-expiry-unsettled-issuance": "issuance",
				"provider-release": "dns_authority"}[phase]
			if !slices.Contains(facts.Blockers, wanted) || !facts.CompletionUnknown || facts.ObservedAt.IsZero() {
				t.Fatalf("release facts omitted actual %s blocker or invented completion: %+v", phase, facts)
			}
			if certificate.NotAfter != nil && (facts.CertificateExpiresAt == nil || !facts.CertificateExpiresAt.Equal(*certificate.NotAfter)) {
				t.Fatal("release explanation did not retain actual certificate expiry", facts.CertificateExpiresAt, certificate.NotAfter)
			}
			if phase == "uncertain-issuance" && facts.CertificateExpiresAt != nil {
				t.Fatal("uncertain issuance fabricated a certificate expiry")
			}
			if phase == "provider-release" {
				if ready, err := d.DNSAuthorityReleaseReady(ctx, domain.ID, now); err != nil || !ready {
					t.Fatal("release fixture has unresolved preconditions", ready, err)
				}
			}
			if certificate.NotAfter != nil {
				at := *certificate.NotAfter
				observed, err := d.GetTeamDomain(ctx, owner, member.TeamID, domain.ID, at)
				if err != nil {
					t.Fatal(err)
				}
				expired := releaseFactsProjection(t, observed)
				if slices.Contains(expired.Blockers, "certificate") || expired.CertificateExpiresAt == nil ||
					!expired.CertificateExpiresAt.Equal(at) || !expired.CompletionUnknown {
					t.Fatal("actual expiry became an invented completion date or lost retained evidence", expired)
				}
				ready, err := d.DNSAuthorityReleaseReady(ctx, domain.ID, at)
				wantReady := phase == "certificate-expiry"
				if err != nil || ready != wantReady {
					t.Fatal("release explanation did not preserve the existing authority fence", ready, err)
				}
			}
		})
	}
}

func releaseFactsProjection(t *testing.T, domain Domain) *DomainRelease {
	t.Helper()
	if domain.Release == nil {
		t.Fatal("releasing domain has no owner-derived release explanation")
	}
	return domain.Release
}

func TestIntegrationDomainReleaseReadRequiresCurrentTeamAccess(t *testing.T) {
	owner, member, domain, fixtures := sessionLockAuthorityFixtures(t)
	d, now, ctx := fixtures[0].database, fixtures[0].now, t.Context()
	if err := d.ReleaseTeamDomain(ctx, owner, member.TeamID, domain.ID, now); err != nil {
		t.Fatal(err)
	}
	if value, err := d.GetTeamDomain(ctx, member.IdentityID, member.TeamID, domain.ID, now); err != nil || value.Release == nil {
		t.Fatal("current authorized reader lost release facts", err)
	}
	insertAuthorityIdentity(t, d, "domain-release-outsider", "", false, now)
	if _, err := d.GetTeamDomain(ctx, "domain-release-outsider", member.TeamID, domain.ID, now); !errors.Is(err, ErrDomainNotFound) {
		t.Fatal("foreign actor could read release facts", err)
	}
	if err := d.RemoveMembership(ctx, owner, member.TeamID, member.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetTeamDomain(ctx, member.IdentityID, member.TeamID, domain.ID, now); !errors.Is(err, ErrDomainNotFound) {
		t.Fatal("removed actor retained exact release visibility", err)
	}
	if _, err := d.ListTeamDomains(ctx, member.IdentityID, member.TeamID); !errors.Is(err, ErrTeamNotFound) {
		t.Fatal("removed actor retained listed release visibility", err)
	}
}

func TestIntegrationDomainReleasePrerequisites(t *testing.T) {
	d, now, owner, team := newAuthorityTeam(t)
	ctx := t.Context()
	managed := team.DefaultDomainID
	if err := d.ReleaseTeamDomain(ctx, owner, team.ID, managed, now); !errors.Is(err, ErrAuthorityAccess) {
		t.Fatal("team owner could release the managed infrastructure domain", err)
	}
	for _, name := range []string{"com", "github.io", "tunnels.example.test", "control.tunnels.example.test", "example.test"} {
		_, err := d.ClaimTeamDomain(ctx, ClaimDomainRequest{IdentityID: owner, TeamID: team.ID, Domain: name,
			IdempotencyKey: name, RequestDigest: sha256.Sum256([]byte(name))}, now)
		if !errors.Is(err, ErrAuthorityInvalid) && !errors.Is(err, ErrAuthorityConflict) {
			t.Fatalf("claim bypassed suffix/infrastructure ownership protection for %s: %v", name, err)
		}
	}
	domain, err := d.ClaimTeamDomain(ctx, ClaimDomainRequest{IdentityID: owner, TeamID: team.ID, Domain: "release-prerequisites.example.test",
		IdempotencyKey: "prerequisites", RequestDigest: sha256.Sum256([]byte("prerequisites"))}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.SetTeamDefaultDomain(ctx, owner, team.ID, domain.ID, now); !errors.Is(err, ErrAuthorityConflict) {
		t.Fatal("unverified claim became a default", err)
	}
	if _, err := d.CreateServiceAt(ctx, team.ID, owner, "pending", "pending", ServicePlacement{DomainID: domain.ID}, now,
		ServiceMetadata{}, &ProjectServiceConfiguration{Target: "localhost:3000"}); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("unverified domain became usable", err)
	}
	work, found, err := d.ClaimDNSAuthorityWork(ctx, "release-prerequisites", now, time.Minute)
	if err != nil || !found {
		t.Fatal("pending claim did not queue DNS verification", found, err)
	}
	work.State, work.ProviderZoneID, work.Nameservers = DNSAuthorityReady, "ZRELEASE", []string{"ns-1.example.test"}
	if _, err := d.SaveDNSAuthorityWork(ctx, work, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.SetTeamDefaultDomain(ctx, owner, team.ID, domain.ID, now); err != nil {
		t.Fatal(err)
	}
	if err := d.ReleaseTeamDomain(ctx, owner, team.ID, domain.ID, now); !errors.Is(err, ErrAuthorityConflict) {
		t.Fatal("default release silently chose a replacement", err)
	}
	current, err := d.GetTeam(ctx, owner, team.ID)
	if err != nil || current.DefaultDomainID != domain.ID {
		t.Fatal("rejected release changed the default", err)
	}
	if _, err := d.SetTeamDefaultDomain(ctx, owner, team.ID, managed, now); err != nil {
		t.Fatal(err)
	}
	if err := d.ReleaseTeamDomain(ctx, owner, team.ID, domain.ID, now); err != nil {
		t.Fatal("release still failed after explicit default switch", err)
	}
}
