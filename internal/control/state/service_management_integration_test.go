package state

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/oidc"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type serviceManagementFixture struct {
	d                 *Database
	now               time.Time
	team, owner       string
	member, unrelated Membership
	local, allocation ServiceRecord
	publisher         PublisherIdentity
}

func newServiceManagementFixture(t *testing.T) serviceManagementFixture {
	t.Helper()
	d, now, owner, team := newAuthorityTeam(t)
	_, member := allocationVisitorMember(t, d, team.ID, owner, "service-manager", TeamRoleAdmin, now)
	unrelated := addAuthorityMember(t, d, now, owner, team.ID, "other-manager", TeamRoleMember)
	local, err := d.CreateServiceAt(t.Context(), team.ID, member.IdentityID, "local", "local-management", ServicePlacement{}, now, ServiceMetadata{Protocol: "http"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	allocation, publisher := managementAllocation(t, d, team.ID, member.IdentityID, now)
	if _, err := d.SetMembershipRole(t.Context(), owner, team.ID, member.ID, TeamRoleMember, now); err != nil {
		t.Fatal(err)
	}
	return serviceManagementFixture{d, now, team.ID, owner, member, unrelated, local, allocation, publisher}
}

func managementAllocation(t *testing.T, d *Database, team, actor string, now time.Time) (ServiceRecord, PublisherIdentity) {
	t.Helper()
	domain, err := controlstatedb.New(d.pool).FindManagedDomain(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	r := serviceTestAuthority{TeamID: team, ActingIdentityID: actor, DomainID: domain.ID}
	enrollment := publisherEnrollment(t, d, r, PublisherScope{TeamID: team, Kind: "namespace", DomainID: domain.ID}, now)
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := d.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, now)
	if err != nil {
		t.Fatal(err)
	}
	service, err := d.AllocatePublisherService(t.Context(), publisher, AllocateServiceRequest{
		Invocation:    mustOpaqueID(t, opaqueid.InvocationPrefix),
		Configuration: ProjectServiceConfiguration{Target: "localhost:3000"},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	return service, publisher
}

func TestIntegrationServiceManagementMemberOwnership(t *testing.T) {
	f := newServiceManagementFixture(t)
	ctx := t.Context()
	declaration := &ProjectServiceConfiguration{Target: "localhost:4000"}
	if _, err := f.d.ConfigureService(ctx, f.local.ID, f.unrelated.IdentityID, f.local.ServiceMetadata, declaration, ServiceUpdateConditions{UnconditionalConfiguration: true}, f.now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("explicit declaration bypassed stored management authority", err)
	}
	if _, err := f.d.ConfigureService(ctx, f.local.ID, f.member.IdentityID, f.local.ServiceMetadata, declaration, ServiceUpdateConditions{UnconditionalConfiguration: true}, f.now); err != nil {
		t.Fatal("stored member owner could not update its standalone declaration", err)
	}
	for _, service := range []ServiceRecord{f.local, f.allocation} {
		if configuration, digest, err := f.d.GetServiceConfiguration(ctx, service.ID, f.member.IdentityID); err != nil || configuration == nil || !ValidServiceConfigurationDigest(digest) {
			t.Fatal("stored member owner could not read its exact declaration", err)
		}
		if _, err := f.d.GetService(ctx, service.ID, f.member.IdentityID); err != nil {
			t.Fatal("stored member owner could not read its service", err)
		}
		if _, err := f.d.GetService(ctx, service.ID, f.unrelated.IdentityID); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("unrelated member managed a service", err)
		}
		grant, err := f.d.CreateServiceGrant(ctx, service.ID, f.member.IdentityID, "extra/"+service.ID, "identity", f.unrelated.IdentityID, nil, f.now)
		if err != nil {
			t.Fatal("member owner could not create an extra visitor grant", err)
		}
		if _, _, err := f.d.ListServiceGrants(ctx, service.ID, f.member.IdentityID, ""); err != nil {
			t.Fatal(err)
		}
		if _, err := f.d.GetService(ctx, service.ID, f.unrelated.IdentityID); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("visitor grant became management authority", err)
		}
		if configuration, digest, err := f.d.GetServiceConfiguration(ctx, service.ID, f.unrelated.IdentityID); !errors.Is(err, ErrServiceAccess) || configuration != nil || digest != "" {
			t.Fatal("visitor grant exposed the protected declaration", err)
		}
		if err := f.d.RevokeServiceGrant(ctx, service.ID, f.member.IdentityID, grant.ID, f.now); err != nil {
			t.Fatal(err)
		}
		invitation, err := f.d.InviteServiceVisitor(ctx, service.ID, f.member.IdentityID, "invite/"+service.ID, "reviewer@example.test", f.now.Add(time.Hour), f.now)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := f.d.ListServiceInvitations(ctx, service.ID, f.member.IdentityID, ""); err != nil {
			t.Fatal(err)
		}
		if err := f.d.RevokeServiceInvitation(ctx, service.ID, f.member.IdentityID, invitation.ID, f.now); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := f.d.ListServices(ctx, f.team, f.member.IdentityID, ""); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("exact management opened team-wide listing", err)
	}
	if _, err := f.d.CreateServiceAt(ctx, f.team, f.member.IdentityID, "forbidden", "forbidden", ServicePlacement{}, f.now, ServiceMetadata{Protocol: "http"}, nil); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("exact management opened team service creation", err)
	}

	// the original publisher grant supplies provenance even after revocation;
	// it is not the human's management credential.
	if err := f.d.RevokePublisherGrant(ctx, f.team, f.publisher.ID, f.publisher.GrantID, f.owner, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.GetService(ctx, f.allocation.ID, f.member.IdentityID); err != nil {
		t.Fatal("publisher revocation erased human ownership", err)
	}
	if err := f.d.DeletePublisherService(ctx, f.publisher, f.allocation.ID, f.now); err == nil {
		t.Fatal("human management restored revoked publisher deletion authority")
	}
	if err := f.d.DeleteService(ctx, f.allocation.ID, f.unrelated.IdentityID, observedServiceDeletion(t, f.d, f.allocation.ID), f.now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("unrelated human deleted an allocation", err)
	}
	if err := f.d.DeleteService(ctx, f.allocation.ID, f.member.IdentityID, observedServiceDeletion(t, f.d, f.allocation.ID), f.now); err != nil {
		t.Fatal("human owner could not delete its allocation", err)
	}
	if err := f.d.DeleteService(ctx, f.local.ID, f.member.IdentityID, observedServiceDeletion(t, f.d, f.local.ID), f.now); err != nil {
		t.Fatal("human owner could not delete its standalone service", err)
	}
}

func TestIntegrationServiceManagementHTTPGrantKeepsVisitorAuthoritySeparate(t *testing.T) {
	f := newServiceManagementFixture(t)
	ctx := t.Context()
	if err := f.d.PrepareVisitorSigningKeys(ctx, testVisitorIssuer, f.now); err != nil {
		t.Fatal(err)
	}
	input := controlv1.CreateVisitorCredentialRequest{Kind: "token", ExpiresAt: f.now.Add(time.Hour)}
	if _, err := f.d.CreateServiceHTTPGrant(ctx, f.local.ID, f.member.IdentityID, input, f.now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("management alone minted a visitor credential", err)
	}
	if _, err := f.d.CreateServiceGrant(ctx, f.local.ID, f.member.IdentityID, "explicit-self", "identity", f.member.IdentityID, nil, f.now); err != nil {
		t.Fatal(err)
	}
	grant, err := f.d.CreateServiceHTTPGrant(ctx, f.local.ID, f.member.IdentityID, input, f.now)
	if err != nil {
		t.Fatal("member owner with visitor authority could not create HTTP credential", err)
	}
	if _, err := f.d.ListServiceHTTPGrants(ctx, f.local.ID, f.unrelated.IdentityID, f.now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("unrelated member listed HTTP credentials", err)
	}
	if err := f.d.RevokeServiceHTTPGrant(ctx, f.local.ID, f.unrelated.IdentityID, grant.GrantId, f.now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("unrelated member revoked HTTP credential", err)
	}
	if grants, err := f.d.ListServiceHTTPGrants(ctx, f.local.ID, f.member.IdentityID, f.now); err != nil || len(grants) != 1 {
		t.Fatal("member owner could not list HTTP credentials", grants, err)
	}
	if err := f.d.RevokeServiceHTTPGrant(ctx, f.local.ID, f.member.IdentityID, grant.GrantId, f.now); err != nil {
		t.Fatal("member owner could not revoke HTTP credential", err)
	}
}

func TestIntegrationServiceManagementMissingAndConflictingProvenance(t *testing.T) {
	f := newServiceManagementFixture(t)
	for _, test := range []struct {
		name, query string
		service     ServiceRecord
		args        []any
	}{
		{"missing claim", `UPDATE control.service_endpoints SET namespace='missing.example.test' WHERE service_id=$1`, f.local, []any{f.local.ID}},
		{"mismatched source", `UPDATE control.service_endpoints SET local_source_key='another-source' WHERE service_id=$1`, f.local, []any{f.local.ID}},
		{"different member", `UPDATE control.service_namespace_claims SET membership_id=$2 WHERE namespace=$1`, f.local, []any{f.local.Endpoint.Hostname, f.unrelated.ID}},
		{"both sources", `INSERT INTO control.publisher_namespace_allocations(service_id,publisher_identity_id,publisher_grant_id,invocation_id,required_temporary_approval)
		    VALUES($1,$2,$3,$4,'restricted')`, f.local, []any{f.local.ID, f.publisher.ID, f.publisher.GrantID, mustOpaqueID(t, opaqueid.InvocationPrefix)}},
		{"allocation hides source endpoint", `WITH changed AS (
		    UPDATE control.service_endpoints SET local_source_key='' WHERE service_id=$1 RETURNING service_id)
		    INSERT INTO control.publisher_namespace_allocations(service_id,publisher_identity_id,publisher_grant_id,invocation_id,required_temporary_approval)
		    SELECT service_id,$2,$3,$4,'restricted' FROM changed`, f.local, []any{f.local.ID, f.publisher.ID, f.publisher.GrantID, mustOpaqueID(t, opaqueid.InvocationPrefix)}},
		{"allocation with local source", `UPDATE control.service_endpoints SET local_source_key='conflicting-local-source' WHERE service_id=$1`, f.allocation, []any{f.allocation.ID}},
		{"shared namespace grant", `UPDATE control.publisher_grants SET namespace_scope='shared',membership_id=NULL WHERE id=$1`, f.allocation, []any{f.publisher.GrantID}},
	} {
		t.Run(test.name, func(t *testing.T) {
			tx, err := f.d.pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, tx)
			if _, err := tx.Exec(t.Context(), test.query, test.args...); err != nil {
				t.Fatal(err)
			}
			member, err := serviceMembershipForActor(t.Context(), tx, f.team, f.member.IdentityID, f.now)
			if err != nil {
				t.Fatal(err)
			}
			row, err := controlstatedb.New(tx).GetService(t.Context(), test.service.ID)
			if err != nil {
				t.Fatal(err)
			}
			if err := requireServiceManagement(t.Context(), tx, row, member); !errors.Is(err, ErrServiceAccess) {
				t.Fatal("invalid provenance granted member management", err)
			}
		})
	}
}

func TestIntegrationServiceManagementRemovedAndReplacedMembership(t *testing.T) {
	f := newServiceManagementFixture(t)
	if err := f.d.RemoveMembership(t.Context(), f.owner, f.team, f.member.ID, f.now); err != nil {
		t.Fatal(err)
	}
	check := func() {
		t.Helper()
		for _, service := range []ServiceRecord{f.local, f.allocation} {
			if _, err := f.d.GetService(t.Context(), service.ID, f.member.IdentityID); !errors.Is(err, ErrServiceAccess) {
				t.Fatal("old membership ownership authorized the current actor", err)
			}
		}
	}
	check()
	request := authorityInvitationRequest(f.owner, f.team, "replacement-manager", f.now)
	invitation, err := f.d.CreateTeamInvitation(t.Context(), request, f.now)
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := f.d.AcceptInvitation(t.Context(), f.member.IdentityID, credentials.InvitationToken(invitation.Secret), f.now)
	if err != nil || replacement.ID == f.member.ID {
		t.Fatal("fixture did not create a replacement membership", replacement, err)
	}
	check()
}

func TestIntegrationServiceReadsRecheckMembershipAfterPrincipalAuthentication(t *testing.T) {
	d, now, owner, team := newAuthorityTeam(t)
	session, member := allocationVisitorMember(t, d, team.ID, owner, "read-revoked", TeamRoleAdmin, now)
	service, err := d.CreateServiceAt(t.Context(), team.ID, member.IdentityID, "private-settings", "private-settings",
		ServicePlacement{}, now, ServiceMetadata{Protocol: "http"},
		&ProjectServiceConfiguration{Target: "private-settings.internal:3000"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.SetMembershipRole(t.Context(), owner, team.ID, member.ID, TeamRoleMember, now); err != nil {
		t.Fatal(err)
	}
	principal := companyTestPrincipal(t, d, session, now)
	ctx := WithControlPrincipal(t.Context(), principal)
	identity, err := d.IdentityContext(ctx, principal.IdentityID)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, membership := range identity.Memberships {
		found = found || membership.ID == member.ID
	}
	if !found || principal.Administrator {
		t.Fatal("read principal did not capture the ordinary member's current authority")
	}
	if _, err := d.GetService(ctx, service.ID, principal.IdentityID); err != nil {
		t.Fatal("current member owner could not read its service", err)
	}
	if configuration, _, err := d.GetServiceConfiguration(ctx, service.ID, principal.IdentityID); err != nil || configuration == nil {
		t.Fatal("current member owner could not read its protected settings", err)
	}
	// the HTTP read authorizer has already authenticated this principal and
	// observed membership. revoke it before the saved-service read begins.
	if err := d.RemoveMembership(t.Context(), owner, team.ID, member.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AuthenticateAccessToken(t.Context(), credentials.AccessToken(session.AccessToken), now); err != nil {
		t.Fatal("membership removal revoked identity instead of narrowing its team access", err)
	}
	record, err := d.GetService(ctx, service.ID, principal.IdentityID)
	if !errors.Is(err, ErrServiceAccess) || record.ID != "" {
		t.Fatal("previously authenticated principal read a service after membership removal", err)
	}
	configuration, digest, err := d.GetServiceConfiguration(ctx, service.ID, principal.IdentityID)
	if !errors.Is(err, ErrServiceAccess) || configuration != nil || digest != "" {
		t.Fatal("previously authenticated principal exposed protected configuration after removal", err)
	}
	if retained, err := d.GetService(t.Context(), service.ID, owner); err != nil || retained.ID != service.ID {
		t.Fatal("denied member reads changed the owner's service", err)
	}
}

func TestIntegrationServiceManagementNamedAndSharedRemainAdminOnly(t *testing.T) {
	d, now, owner, team := newAuthorityTeam(t)
	member := addAuthorityMember(t, d, now, owner, team.ID, "deployment-creator", TeamRoleAdmin)
	request := selectedProjectRequest(ApplyProjectConfigurationRequest{
		TeamID: team.ID, ActorID: member.IdentityID, ProjectKey: "management", SourceFingerprint: strings.Repeat("a", 64), Now: now,
		Configuration: ProjectConfiguration{Settings: &DeploymentSettings{}, Services: map[string]ProjectServiceConfiguration{"web": {Target: "app"}}},
	}, "production")
	applied, err := d.ApplyProjectConfiguration(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	production, err := d.GetDeployment(t.Context(), DeploymentScope{TeamID: team.ID, ProjectKey: request.ProjectKey, ActorID: member.IdentityID}, "production")
	if err != nil {
		t.Fatal(err)
	}
	f := deploymentPublicationFixture{d: d, now: now, project: request, production: production}
	_, _, access, _ := f.approve(t, nil, "restricted")
	shared, err := f.d.AllocateDeploymentPublication(t.Context(), f.allocation(t, access))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.SetMembershipRole(t.Context(), owner, team.ID, member.ID, TeamRoleMember, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetService(t.Context(), applied.Services[0].ServiceID, member.IdentityID); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("creator identity managed a named deployment after demotion", err)
	}
	if _, err := d.GetService(t.Context(), shared.ID, member.IdentityID); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("ordinary member managed a deployment allocation", err)
	}
	if _, err := d.GetService(t.Context(), applied.Services[0].ServiceID, owner); err != nil {
		t.Fatal("team owner lost named deployment management", err)
	}
	if _, err := d.GetService(t.Context(), shared.ID, owner); err != nil {
		t.Fatal("team owner lost shared allocation management", err)
	}
}

func TestIntegrationServiceManagementPublisherCapabilityIsNotOwnership(t *testing.T) {
	f := newServiceManagementFixture(t)
	if _, err := f.d.SetMembershipRole(t.Context(), f.owner, f.team, f.unrelated.ID, TeamRoleAdmin, f.now); err != nil {
		t.Fatal(err)
	}
	enrollment := publisherEnrollment(t, f.d, serviceTestAuthority{TeamID: f.team, ActingIdentityID: f.unrelated.IdentityID},
		PublisherScope{TeamID: f.team, Kind: "service", ServiceID: f.local.ID}, f.now)
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := f.d.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.SetMembershipRole(t.Context(), f.owner, f.team, f.unrelated.ID, TeamRoleMember, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.GetServiceForPublisher(t.Context(), f.local.ID, publisher, f.now); err != nil {
		t.Fatal("fixture lost exact publisher capability", err)
	}
	for _, actor := range []string{f.unrelated.IdentityID, publisher.ID} {
		if _, err := f.d.GetService(t.Context(), f.local.ID, actor); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("publisher capability became human management authority", err)
		}
	}
}

func TestIntegrationServiceManagementRetainsProjectDefinitionAndGrantGuards(t *testing.T) {
	d, now, owner, team := newAuthorityTeam(t)
	member := addAuthorityMember(t, d, now, owner, team.ID, "local-owner", TeamRoleAdmin)
	local, err := d.RealizeLocalProjectService(t.Context(), RealizeLocalProjectServiceRequest{
		TeamID: team.ID, ProjectKey: "managed", SourceFingerprint: strings.Repeat("a", 64),
		Service: "web", WorktreeKey: "checkout", ActorID: member.IdentityID, Now: now,
		Configuration: ProjectServiceConfiguration{Target: "app", Access: &ProjectServiceAccess{Team: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.SetMembershipRole(t.Context(), owner, team.ID, member.ID, TeamRoleMember, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetService(t.Context(), local.ServiceID, member.IdentityID); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteService(t.Context(), local.ServiceID, member.IdentityID, observedServiceDeletion(t, d, local.ServiceID), now); !errors.Is(err, ErrProjectManaged) {
		t.Fatal("member management bypassed project definition ownership", err)
	}
	var grant string
	if err := d.pool.QueryRow(t.Context(), `SELECT visitor_grant_id FROM control.local_project_services WHERE service_id=$1`, local.ServiceID).Scan(&grant); err != nil {
		t.Fatal(err)
	}
	if err := d.RevokeServiceGrant(t.Context(), local.ServiceID, member.IdentityID, grant, now); !errors.Is(err, ErrProjectManaged) {
		t.Fatal("member management bypassed project grant ownership", err)
	}
}

func managementActorProof(t *testing.T, d *Database, actor, nonce string, now time.Time) OIDCIdentity {
	t.Helper()
	var identity OIDCIdentity
	if err := d.pool.QueryRow(t.Context(), `SELECT issuer,subject FROM control.identities WHERE id=$1`, actor).Scan(&identity.Issuer, &identity.Subject); err != nil {
		t.Fatal(err)
	}
	identity.Nonce, identity.AssertionID = nonce, nonce
	identity.AssertionDigest = sha256.Sum256([]byte(nonce))
	identity.IssuedAt, identity.AssertionExpiry = now, now.Add(time.Minute)
	return identity
}

func TestIntegrationServiceManagementConsumesActorOnceForSeveralServices(t *testing.T) {
	f := newServiceManagementFixture(t)
	proof := managementActorProof(t, f.d, f.member.IdentityID, "several-services", f.now)
	ctx := WithServiceActorProof(t.Context(), proof, proof.Nonce)
	tx, err := f.d.beginServiceAccess(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, tx)
	member, err := serviceMembershipForActor(ctx, tx, f.team, f.member.IdentityID, f.now)
	if err != nil {
		t.Fatal(err)
	}
	for _, service := range []ServiceRecord{f.local, f.allocation} {
		row, err := controlstatedb.New(tx).GetService(ctx, service.ID)
		if err != nil {
			t.Fatal(err)
		}
		if err := requireServiceManagement(ctx, tx, row, member); err != nil {
			t.Fatal("a second exact check consumed the same assertion again", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.GetService(ctx, f.local.ID, f.member.IdentityID); !errors.Is(err, ErrOIDCAssertionReplay) {
		t.Fatal("another operation replayed the consumed assertion", err)
	}
	fresh := managementActorProof(t, f.d, f.member.IdentityID, "member-exact-service", f.now)
	if _, err := f.d.GetService(WithServiceActorProof(t.Context(), fresh, fresh.Nonce), f.local.ID, f.member.IdentityID); err != nil {
		t.Fatal("signed member management attempted admin then replayed a fallback", err)
	}
	adminOnly := managementActorProof(t, f.d, f.member.IdentityID, "member-team-list", f.now)
	if _, _, err := f.d.ListServices(WithServiceActorProof(t.Context(), adminOnly, adminOnly.Nonce), f.team, f.member.IdentityID, ""); !errors.Is(err, ErrServiceManagerRequired) {
		t.Fatal("signed member ownership opened team-wide administration", err)
	}
}

func TestIntegrationServiceManagementRequiresCurrentCompanyProof(t *testing.T) {
	f := newServiceManagementFixture(t)
	if _, err := f.d.pool.Exec(t.Context(), `UPDATE control.identities SET issuer='https://company.example',subject=id WHERE id=$1`, f.member.IdentityID); err != nil {
		t.Fatal(err)
	}
	identity := OIDCIdentity{Issuer: "https://company.example", Subject: f.member.IdentityID, DisplayName: "Service manager", AssertionDigest: sha256.Sum256([]byte("management-personal")), AssertionExpiry: f.now.Add(time.Hour)}
	personal, err := f.d.CreateOIDCControlSession(t.Context(), "tunnels.example.test", identity, time.Hour, 24*time.Hour, f.now)
	if err != nil {
		t.Fatal(err)
	}
	owner := companyTestPrincipal(t, f.d, newOIDCSession(t, f.d, f.now), f.now)
	connection := companyTestConnection(t, f.d, f.team, owner, "approval", f.now)
	companyTestEligibility(t, f.d, connection, f.member.IdentityID, 1, true, f.now)
	personalCtx := WithControlPrincipal(t.Context(), companyTestPrincipal(t, f.d, personal, f.now))
	if _, err := f.d.GetService(personalCtx, f.local.ID, f.member.IdentityID); !errors.Is(err, ErrAuthorityAccess) {
		t.Fatal("personal sign-in bypassed required company session", err)
	}
	companyContext := oidc.TeamContext{TeamID: f.team, IdentityConnectionID: connection.ID, ConnectionRevision: connection.Revision, SourceID: connection.SourceID, Subject: "directory/" + f.member.IdentityID, AuthenticatedAt: f.now.Unix()}
	for _, test := range []struct {
		name string
		edit func(*OIDCIdentity)
		want error
	}{
		{"missing", func(*OIDCIdentity) {}, ErrServiceSourceSignInRequired},
		{"current", func(i *OIDCIdentity) { i.TeamContexts = []oidc.TeamContext{companyContext} }, nil},
		{"old revision", func(i *OIDCIdentity) {
			c := companyContext
			c.ConnectionRevision++
			i.TeamContexts = []oidc.TeamContext{c}
		}, ErrServiceSourceSignInRequired},
		{"wrong source", func(i *OIDCIdentity) {
			c := companyContext
			c.SourceID = "another-source"
			i.TeamContexts = []oidc.TeamContext{c}
		}, ErrServiceSourceSignInRequired},
	} {
		t.Run(test.name, func(t *testing.T) {
			proof := managementActorProof(t, f.d, f.member.IdentityID, "management-company/"+test.name, f.now)
			test.edit(&proof)
			_, err := f.d.GetService(WithServiceActorProof(t.Context(), proof, proof.Nonce), f.local.ID, f.member.IdentityID)
			if test.want == nil && err != nil || test.want != nil && !errors.Is(err, test.want) {
				t.Fatal("signed company management", err)
			}
		})
	}
	identity.TeamContexts = []oidc.TeamContext{companyContext}
	identity, err = companyBindTestIntent(t, f.d, identity, f.now)
	if err != nil {
		t.Fatal(err)
	}
	identity.AssertionDigest = sha256.Sum256([]byte("management-company-session"))
	session, err := f.d.CreateOIDCControlSession(t.Context(), "tunnels.example.test", identity, time.Hour, 24*time.Hour, f.now)
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithControlPrincipal(t.Context(), companyTestPrincipal(t, f.d, session, f.now))
	if _, err := f.d.GetService(ctx, f.allocation.ID, f.member.IdentityID); err != nil {
		t.Fatal("current company session could not manage member allocation", err)
	}
	companyTestEligibility(t, f.d, connection, f.member.IdentityID, 2, false, f.now)
	offboarded := managementActorProof(t, f.d, f.member.IdentityID, "management-offboarded", f.now)
	offboarded.TeamContexts = []oidc.TeamContext{companyContext}
	for _, supplied := range []context.Context{ctx, WithServiceActorProof(t.Context(), offboarded, offboarded.Nonce)} {
		if _, err := f.d.GetService(supplied, f.local.ID, f.member.IdentityID); err == nil {
			t.Fatal("offboarded company member retained management")
		}
	}
}
