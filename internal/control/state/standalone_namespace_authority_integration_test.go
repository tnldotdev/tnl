package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
)

func standaloneEnrollmentRequest(t *testing.T, d *Database, service ServiceRecord, actor, name string, now time.Time) CreatePublisherEnrollmentRequest {
	t.Helper()
	current, err := controlstatedb.New(d.pool).GetTeamActorContext(t.Context(), controlstatedb.GetTeamActorContextParams{
		TeamID: service.TeamID, IdentityID: actor,
	})
	if err != nil {
		t.Fatal(err)
	}
	return CreatePublisherEnrollmentRequest{
		Scope: PublisherScope{TeamID: service.TeamID, Kind: "service", ServiceID: service.ID},
		Name:  name, Kind: "installed", EditorID: actor, EditorMembershipID: current.ActorMembershipID,
		PolicyRevision: uint64(current.PolicyRevision), Now: now,
	}
}

func TestIntegrationStandaloneMemberExactPublisherRetainsMembershipOwnership(t *testing.T) {
	f := newServiceManagementFixture(t)
	ctx := t.Context()
	if _, err := f.d.GetService(ctx, f.local.ID, f.member.IdentityID); err != nil {
		t.Fatal("fixture member cannot manage its exact standalone service", err)
	}
	if _, _, err := f.d.ListServices(ctx, f.team, f.member.IdentityID, ""); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("exact ownership exposed team inventory", err)
	}
	if _, err := f.d.CreateServiceAt(ctx, f.team, f.member.IdentityID, "unscoped", "unscoped", ServicePlacement{}, f.now, ServiceMetadata{Protocol: "http"}, nil); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("exact ownership opened ordinary team creation", err)
	}
	request := standaloneEnrollmentRequest(t, f.d, f.local, f.member.IdentityID, "member-standalone", f.now)
	for _, test := range []struct {
		name string
		edit func(*CreatePublisherEnrollmentRequest)
	}{
		{"team ownership", func(r *CreatePublisherEnrollmentRequest) { r.Ownership = "team" }},
		{"stale policy", func(r *CreatePublisherEnrollmentRequest) { r.PolicyRevision-- }},
		{"different membership", func(r *CreatePublisherEnrollmentRequest) { r.EditorMembershipID = f.unrelated.ID }},
		{"allocated service", func(r *CreatePublisherEnrollmentRequest) { r.Scope.ServiceID = f.allocation.ID }},
	} {
		t.Run(test.name, func(t *testing.T) {
			invalid := request
			test.edit(&invalid)
			if _, err := f.d.IssuePublisherEnrollment(t.Context(), invalid); !errors.Is(err, ErrPublisherIdentity) {
				t.Fatal("member exact enrollment widened its authority", err)
			}
		})
	}
	if _, err := f.d.CreateServiceGrant(ctx, f.local.ID, f.member.IdentityID, "visitor-is-not-publisher", "identity", f.unrelated.IdentityID, nil, f.now); err != nil {
		t.Fatal(err)
	}
	unrelated := standaloneEnrollmentRequest(t, f.d, f.local, f.unrelated.IdentityID, "unrelated", f.now)
	if _, err := f.d.IssuePublisherEnrollment(ctx, unrelated); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("visitor permission became publisher enrollment authority", err)
	}
	enrollment, err := f.d.IssuePublisherEnrollment(ctx, request)
	if err != nil {
		t.Fatal("stored member owner could not enroll its exact standalone service", err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := f.d.RedeemPublisherEnrollment(ctx, enrollment.Key, public, f.now)
	if err != nil {
		t.Fatal(err)
	}
	scope := PublisherScope{TeamID: f.team, Kind: "service", ServiceID: f.local.ID}
	if publisher.Scope != scope || publisher.Ownership != "member" || publisher.OwnerMembershipID != f.member.ID {
		t.Fatal("member enrollment created a team-owned or wider publisher", publisher.Scope, publisher.Ownership, publisher.OwnerMembershipID)
	}
	stored, err := controlstatedb.New(f.d.pool).GetPublisherGrant(ctx, controlstatedb.GetPublisherGrantParams{
		ID: publisher.GrantID, PublisherIdentityID: publisher.ID,
	})
	if err != nil || scopeFromGrant(f.team, stored) != scope {
		t.Fatal("enrollment did not persist the exact authorized grant", err)
	}
	access := publisherAccess(t, f.d, publisher, private, "", f.now)
	authenticated, err := f.d.AuthenticatePublisherAccess(ctx, access.Token, "", f.now)
	if err != nil || authenticated.Scope != scope || authenticated.Ownership != "member" || authenticated.OwnerMembershipID != f.member.ID {
		t.Fatal("signed exchange changed the member's exact authority", authenticated.Scope, err)
	}
	if _, err := f.d.GetServiceForPublisher(ctx, f.local.ID, authenticated, f.now); err != nil {
		t.Fatal("real member publisher could not read its service", err)
	}
	if _, err := f.d.GetServiceForPublisher(ctx, f.allocation.ID, authenticated, f.now); err == nil {
		t.Fatal("exact publisher adopted another service")
	}
	pendingRequest := request
	pendingRequest.Name = "pending-standalone"
	pending, err := f.d.IssuePublisherEnrollment(ctx, pendingRequest)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.d.RemoveMembership(ctx, f.owner, f.team, f.member.ID, f.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	checkRemoved := func(now time.Time) {
		t.Helper()
		if _, err := f.d.GetService(ctx, f.local.ID, f.member.IdentityID); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("removed or replacement membership inherited exact management", err)
		}
		if _, err := f.d.AuthenticatePublisherAccess(ctx, access.Token, "", now); !errors.Is(err, ErrPublisherIdentity) {
			t.Fatal("member-owned issued access survived membership removal", err)
		}
		assertion, err := publisherproof.Sign(publisher.ID, publisher.KeyID, publisher.GrantID, publisherTestAudience, private, now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.d.ExchangePublisherAssertion(ctx, publisher.ID, publisher.GrantID, publisherTestAudience, assertion, "", now); !errors.Is(err, ErrPublisherIdentity) {
			t.Fatal("removed membership exchanged its retained signing key", err)
		}
		if _, err := f.d.RedeemPublisherEnrollment(ctx, pending.Key, public, now); !errors.Is(err, ErrPublisherEnrollment) {
			t.Fatal("removed membership redeemed a pending exact enrollment", err)
		}
	}
	checkRemoved(f.now.Add(time.Second))
	invitation, err := f.d.CreateTeamInvitation(ctx, authorityInvitationRequest(f.owner, f.team, "replacement-publisher", f.now.Add(2*time.Second)), f.now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := f.d.AcceptInvitation(ctx, f.member.IdentityID, credentials.InvitationToken(invitation.Secret), f.now.Add(2*time.Second))
	if err != nil || replacement.ID == f.member.ID {
		t.Fatal("fixture did not create a distinct replacement membership", replacement, err)
	}
	checkRemoved(f.now.Add(2 * time.Second))
	replacementRequest := standaloneEnrollmentRequest(t, f.d, f.local, f.member.IdentityID, "replacement-owner", f.now.Add(2*time.Second))
	if _, err := f.d.IssuePublisherEnrollment(ctx, replacementRequest); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("replacement membership enrolled the original owner's service", err)
	}
}

func TestIntegrationStandaloneSharedCustomHostnameRemainsTeamOwned(t *testing.T) {
	d, now, owner, team := newAuthorityTeam(t)
	ctx := t.Context()
	creator := addAuthorityMember(t, d, now, owner, team.ID, "shared-publisher", TeamRoleAdmin)
	domain := deploymentCustomDomain(t, d, ApplyProjectConfigurationRequest{TeamID: team.ID, ActorID: owner}, now)
	configuration := &ProjectServiceConfiguration{
		Target: "app", Protocol: "http", DomainID: domain.ID,
		Hostname: "preview.custom.example.test", Public: new(true),
	}
	placement := ServicePlacement{DomainID: domain.ID, Hostname: configuration.Hostname}
	service, err := d.CreateServiceAt(ctx, team.ID, creator.IdentityID, "shared-preview", "shared-preview", placement, now, ServiceMetadata{}, configuration)
	if err != nil {
		t.Fatal("administrator could not create a standalone shared custom hostname", err)
	}
	if service.TeamID != team.ID || service.DomainID != domain.ID || service.Protocol != "http" || service.Ephemeral ||
		service.Source != nil || service.Endpoint == nil || service.Endpoint.Hostname != configuration.Hostname ||
		!service.Endpoint.Public || service.Endpoint.Port != 443 {
		t.Fatal("shared standalone creation changed endpoint or acquired app provenance", service)
	}
	recovered, err := d.CreateServiceAt(ctx, team.ID, creator.IdentityID, "shared-preview", "shared-preview", placement, now, ServiceMetadata{}, configuration)
	if err != nil || recovered.ID != service.ID || recovered.EndpointRevision != service.EndpointRevision {
		t.Fatal("shared standalone creation retry changed its saved service", recovered, err)
	}
	enrollment, err := d.IssuePublisherEnrollment(ctx, standaloneEnrollmentRequest(t, d, service, creator.IdentityID, "shared-standalone", now))
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := d.RedeemPublisherEnrollment(ctx, enrollment.Key, public, now)
	if err != nil {
		t.Fatal(err)
	}
	if publisher.Ownership != "team" || publisher.OwnerMembershipID != "" ||
		publisher.Scope != (PublisherScope{TeamID: team.ID, Kind: "service", ServiceID: service.ID}) {
		t.Fatal("shared publisher borrowed its creator's membership", publisher.Ownership, publisher.OwnerMembershipID, publisher.Scope)
	}
	access := publisherAccess(t, d, publisher, private, "", now)
	if _, err := d.SetMembershipRole(ctx, owner, team.ID, creator.ID, TeamRoleMember, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetService(ctx, service.ID, creator.IdentityID); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("demoted creator retained shared service management", err)
	}
	if _, _, err := d.GetServiceConfiguration(ctx, service.ID, creator.IdentityID); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("demoted creator read the shared service declaration", err)
	}
	if err := d.DeleteService(ctx, service.ID, creator.IdentityID, now.Add(time.Second)); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("demoted creator deleted a team-owned service", err)
	}
	if err := d.RemoveMembership(ctx, owner, team.ID, creator.ID, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if saved, err := d.GetService(ctx, service.ID, owner); err != nil || saved.ID != service.ID {
		t.Fatal("removing the creator removed team management", saved, err)
	}
	if _, err := d.ConfigureService(ctx, service.ID, owner, service.ServiceMetadata, configuration, ServiceUpdateConditions{UnconditionalConfiguration: true}, now.Add(2*time.Second)); err != nil {
		t.Fatal("team owner could not retain a shared standalone declaration", err)
	}
	if current, err := d.AuthenticatePublisherAccess(ctx, access.Token, "", now.Add(2*time.Second)); err != nil ||
		current.Scope != publisher.Scope || current.Ownership != "team" {
		t.Fatal("creator removal revoked an explicitly team-owned publisher", current.Scope, err)
	}
}

func TestIntegrationStandaloneSharedRepairKeepsReservedAndLocalAppHostnameGuards(t *testing.T) {
	d, now, owner, team := newAuthorityTeam(t)
	ctx := t.Context()
	domain := deploymentCustomDomain(t, d, ApplyProjectConfigurationRequest{TeamID: team.ID, ActorID: owner}, now)
	addAuthorityMember(t, d, now, owner, team.ID, "active-member", TeamRoleMember)
	if _, err := d.CreateTeamInvitation(ctx, authorityInvitationRequest(owner, team.ID, "invited-member", now), now); err != nil {
		t.Fatal(err)
	}
	removed := addAuthorityMember(t, d, now, owner, team.ID, "removed-member", TeamRoleMember)
	if err := d.RemoveMembership(ctx, owner, team.ID, removed.ID, now); err != nil {
		t.Fatal(err)
	}
	for _, slug := range []string{"active-member", "invited-member", "removed-member"} {
		for _, prefix := range []string{"", "app.", "api.app."} {
			hostname := prefix + slug + ".custom.example.test"
			declaration := &ProjectServiceConfiguration{
				Target: "app", Protocol: "http", Public: new(true), DomainID: domain.ID, Hostname: hostname,
			}
			if _, err := d.CreateServiceAt(ctx, team.ID, owner, "reserved-"+slug, hostname, ServicePlacement{}, now, ServiceMetadata{}, declaration); !errors.Is(err, ErrServiceAccess) {
				t.Fatal("shared standalone creation claimed a reserved member namespace", hostname, err)
			}
		}
	}
	if _, err := d.RealizeLocalProjectService(ctx, RealizeLocalProjectServiceRequest{
		TeamID: team.ID, ProjectKey: "shared-local", SourceFingerprint: strings.Repeat("a", 64),
		Service: "web", WorktreeKey: "checkout", ActorID: owner, Now: now,
		Configuration: ProjectServiceConfiguration{
			Target: "app", Protocol: "http", Public: new(true), DomainID: domain.ID, Hostname: "local.custom.example.test",
		},
	}); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("standalone shared-host repair opened local-app shared association", err)
	}
	var count int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.services WHERE team_id=$1`, team.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("denied namespace claims left saved services", count, err)
	}
}
