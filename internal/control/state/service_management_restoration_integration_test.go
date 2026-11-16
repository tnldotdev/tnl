package state

import (
	"errors"
	"reflect"
	"testing"

	"github.com/tnldotdev/tnl/internal/naming"
)

func TestIntegrationServiceRestoredSimpleOrganizationNamespaceNegatives(t *testing.T) {
	d, now, owner, team := newAuthorityTeam(t)
	d.managedURLMode = naming.ManagedURLModeSimple
	members, err := d.ListTeamMemberships(t.Context(), owner, team.ID)
	if err != nil || len(members) == 0 {
		t.Fatal(err)
	}
	domains, err := d.ListTeamDomains(t.Context(), owner, team.ID)
	if err != nil || len(domains) == 0 {
		t.Fatal(err)
	}
	member, domain := members[0], domains[0]
	namespace := member.MemberSlug + "." + team.DisplayName + "." + domain.CanonicalDomain
	declaration := ProjectServiceConfiguration{Target: "localhost:3000", DomainID: domain.ID, Hostname: "app." + namespace}
	if _, err := d.CreateServiceAt(t.Context(), team.ID, owner, "namespace-control", "namespace-control",
		ServicePlacement{}, now, ServiceMetadata{}, &declaration); err != nil {
		t.Fatal("valid full member/team namespace was denied", err)
	}
	other := addAuthorityMember(t, d, now, owner, team.ID, "restored-other-member", TeamRoleMember)
	for name, hostname := range map[string]string{
		"namespace-apex":  namespace,
		"generated-label": "app." + member.ManagedLabel + "." + domain.CanonicalDomain,
		"other-member":    "app." + other.MemberSlug + "." + team.DisplayName + "." + domain.CanonicalDomain,
	} {
		t.Run(name, func(t *testing.T) {
			invalid := declaration
			invalid.Hostname = hostname
			if _, err := d.CreateServiceAt(t.Context(), team.ID, owner, name, name,
				ServicePlacement{}, now, ServiceMetadata{}, &invalid); !errors.Is(err, ErrServiceAccess) {
				t.Fatal("simple organization namespace accepted a foreign or apex hostname", err)
			}
		})
	}
}

func TestIntegrationServiceRestoredAdminCleanupDoesNotRewriteAnotherMemberDeclaration(t *testing.T) {
	f := newServiceManagementFixture(t)
	admin := addAuthorityMember(t, f.d, f.now, f.owner, f.team, "restored-cleanup-admin", TeamRoleAdmin)
	var err error
	f.local, err = f.d.ConfigureService(t.Context(), f.local.ID, f.member.IdentityID, f.local.ServiceMetadata,
		&ProjectServiceConfiguration{Target: "localhost:3000"}, ServiceUpdateConditions{}, f.now)
	if err != nil {
		t.Fatal("member owner could not save its declaration", err)
	}
	before, digest, err := f.d.GetServiceConfiguration(t.Context(), f.local.ID, f.member.IdentityID)
	if err != nil || before == nil {
		t.Fatal("member owner has no normalized saved declaration", err)
	}
	f.local, err = f.d.ConfigureService(t.Context(), f.local.ID, admin.IdentityID, f.local.ServiceMetadata,
		before, ServiceUpdateConditions{ConfigurationDigest: digest}, f.now)
	if err != nil {
		t.Fatal("administrator could not replay an unchanged declaration", err)
	}
	previousPool := f.local.PublisherPool
	metadata := f.local.ServiceMetadata
	metadata.PublisherPool = !previousPool
	f.local, err = f.d.ConfigureService(t.Context(), f.local.ID, admin.IdentityID, metadata,
		nil, ServiceUpdateConditions{PublisherPool: &previousPool}, f.now)
	if err != nil || f.local.PublisherPool != metadata.PublisherPool {
		t.Fatal("declaration ownership denied metadata-only administrator management", err)
	}
	candidate := *before
	candidate.Target = "different-member-target.internal:4000"
	normalized, err := normalizeServiceConfiguration(f.local.Name, &candidate)
	if err != nil || reflect.DeepEqual(before, normalized) {
		t.Fatal("administrator edit is not a distinct valid normalized declaration", err)
	}
	_, err = f.d.ConfigureService(t.Context(), f.local.ID, admin.IdentityID, f.local.ServiceMetadata,
		normalized, ServiceUpdateConditions{ConfigurationDigest: digest}, f.now)
	if err != ErrServiceAccess {
		t.Error("administrator rewrote another member-owned declaration", err)
	}
	after, nextDigest, err := f.d.GetServiceConfiguration(t.Context(), f.local.ID, f.member.IdentityID)
	if err != nil || digest != nextDigest || !reflect.DeepEqual(before, after) {
		t.Error("denied cross-member declaration update changed saved configuration", err)
	}
	if err := f.d.DeleteService(t.Context(), f.local.ID, admin.IdentityID, f.now); err != nil {
		t.Fatal("administrator lost cleanup permission for another member service", err)
	}
	if _, err := f.d.GetService(t.Context(), f.local.ID, f.member.IdentityID); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("administrator cleanup did not remove the service", err)
	}
}

func TestIntegrationServiceRestoredReleasingDomainDeniesNewWorkButAllowsCleanup(t *testing.T) {
	owner, member, domain, fixtures := sessionLockAuthorityFixtures(t)
	f := fixtures[0]
	ctx := t.Context()
	declaration, _, err := f.database.GetServiceConfiguration(ctx, f.service.ID, member.IdentityID)
	if err != nil || declaration == nil {
		t.Fatal("custom-domain fixture lacks its saved declaration", err)
	}
	fresh := *declaration
	fresh.Name = "after-release"
	fresh.DomainID, fresh.Hostname = domain.ID, "new."+f.service.Endpoint.Hostname
	normalized, err := normalizeServiceConfiguration("after-release", &fresh)
	if err != nil {
		t.Fatal("new-service declaration is invalid before domain release", err)
	}
	if err := f.database.ReleaseTeamDomain(ctx, owner, member.TeamID, domain.ID, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.CreateServiceAt(ctx, member.TeamID, member.IdentityID, "after-release", "after-release",
		ServicePlacement{}, f.now, f.service.ServiceMetadata, normalized); !errors.Is(err, ErrServiceAccess) {
		t.Error("releasing domain permitted service creation", err)
	}
	fresh = *declaration
	fresh.DomainID, fresh.Hostname, fresh.Target = domain.ID, f.service.Endpoint.Hostname, "localhost:4999"
	if _, err := f.database.ConfigureService(ctx, f.service.ID, member.IdentityID, f.service.ServiceMetadata,
		&fresh, ServiceUpdateConditions{}, f.now); !errors.Is(err, ErrServiceAccess) {
		t.Error("releasing domain permitted declaration replacement", err)
	}
	if _, err := f.database.StartServiceRun(ctx, f.service.ID, f.prepared.RunID, f.prepared.RunNumber,
		f.publisher, f.now); !errors.Is(err, ErrServiceAccess) {
		t.Error("releasing domain permitted a prepared run to start", err)
	}
	for _, fixture := range fixtures {
		if err := f.database.DeleteService(ctx, fixture.service.ID, member.IdentityID, f.now); err != nil {
			t.Fatal("releasing domain prevented stored-owner cleanup", err)
		}
	}
}
