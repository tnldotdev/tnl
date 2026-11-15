package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/credentials"
)

func allocationVisitorMember(t *testing.T, d *Database, team, owner, subject string, role TeamRole, now time.Time) (ControlSession, Membership) {
	t.Helper()
	session, err := d.CreateOIDCControlSession(t.Context(), "tunnels.example.test", OIDCIdentity{
		Issuer: "https://identity.fixture.test", Subject: subject, DisplayName: subject,
		AssertionDigest: sha256.Sum256([]byte(subject)), AssertionExpiry: now.Add(time.Hour),
	}, time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	request := authorityInvitationRequest(owner, team, subject, now)
	request.InitialRole = role
	invitation, err := d.CreateTeamInvitation(t.Context(), request, now)
	if err != nil {
		t.Fatal(err)
	}
	member, err := d.AcceptInvitation(t.Context(), session.Identity.Identity.ID, credentials.InvitationToken(invitation.Secret), now)
	if err != nil {
		t.Fatal(err)
	}
	return session, member
}

func assertAllocationHumanVisitor(t *testing.T, d *Database, service string, session ControlSession, now time.Time, want bool) {
	t.Helper()
	ctx := WithControlPrincipal(t.Context(), ControlPrincipal{IdentityID: session.Identity.Identity.ID, SessionID: session.SessionID})
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, _, permissionErr := privateVisitorAccess(ctx, tx, service, session.Identity.Identity.ID, now)
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if (permissionErr == nil) != want {
		t.Errorf("allocation human visitor permission: want=%t, error=%v", want, permissionErr)
	}
	_, tokenErr := d.IssueVisitorToken(ctx, testVisitorIssuer, visitorscope.Scope{Kind: visitorscope.Service, ID: service}, BrowserTokenSource{}, now)
	if (tokenErr == nil) != want {
		t.Errorf("allocation browser token: want=%t, error=%v", want, tokenErr)
	}
}

func TestIntegrationPublisherNamespaceAllocationVisitorOwnership(t *testing.T) {
	d, now, owner, team := newAuthorityTeam(t)
	if err := d.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, now); err != nil {
		t.Fatal(err)
	}
	member, membership := allocationVisitorMember(t, d, team.ID, owner, "allocation-owner", "member", now)
	unrelated, _ := allocationVisitorMember(t, d, team.ID, owner, "allocation-other", "member", now)
	domain, err := controlstatedb.New(d.pool).FindManagedDomain(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	r := CreatePublicURLRequest{TeamID: team.ID, ActingIdentityID: member.Identity.Identity.ID, DomainID: domain.ID}
	enrollment := publisherEnrollment(t, d, r, PublisherScope{TeamID: team.ID, Kind: "namespace", DomainID: domain.ID}, now)
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := d.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, now)
	if err != nil {
		t.Fatal(err)
	}
	service, err := d.AllocatePublisherService(t.Context(), publisher, AllocateServiceRequest{Invocation: mustOpaqueID(t, opaqueid.InvocationPrefix), Configuration: ProjectServiceConfiguration{Target: "localhost:3000"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("member-owner", func(t *testing.T) { assertAllocationHumanVisitor(t, d, service.ID, member, now, true) })
	t.Run("unrelated-member", func(t *testing.T) { assertAllocationHumanVisitor(t, d, service.ID, unrelated, now, false) })
	var shared ShareSessionTokenSource
	t.Run("owner-share", func(t *testing.T) {
		ctx := WithControlPrincipal(t.Context(), ControlPrincipal{IdentityID: member.Identity.Identity.ID, SessionID: member.SessionID})
		secret, raw, err := randomBrowserSecret()
		if err != nil {
			t.Fatal(err)
		}
		share, err := d.CreateShare(ctx, CreateShareRequest{TeamID: team.ID, ActingIdentityID: member.Identity.Identity.ID,
			IdempotencyKey: "owner-share", SecretFingerprint: sha256.Sum256(raw), ExpiresAt: now.Add(time.Hour),
			ServiceIDs: []string{service.ID}, EntryServiceID: service.ID}, now)
		if err != nil {
			t.Fatal("namespace member owner could not share its restricted allocation", err)
		}
		if share.EntryServiceID != service.ID || len(share.ServiceIDs) != 1 || share.ServiceIDs[0] != service.ID {
			t.Fatal("share did not capture the exact allocated service")
		}
		_, _, _, leases := publishRunPrerequisitesInDatabase(t, d, now, nil)
		access := publisherAccess(t, d, publisher, key, "192.0.2.10", now)
		run := readyAppliedServiceRun(t, d, access, key, service, netip.MustParseAddr("192.0.2.10"), leases, now)
		auth := ServiceHTTPRun{Subject: visitorscope.Scope{Kind: visitorscope.Service, ID: service.ID}, RunID: run.RunID, Number: run.RunNumber, Token: credentials.ServiceRunToken(run.Token)}
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(secret)
		if err != nil {
			t.Fatal(err)
		}
		redemption, err := d.RedeemShare(t.Context(), auth, share.ID, decoded, nil, now)
		if err != nil {
			t.Fatal("namespace owner share could not be redeemed", err)
		}
		shared = ShareSessionTokenSource{ShareID: share.ID, Secret: redemption.CookieSecret, RunID: run.RunID}
		if _, err := d.IssueVisitorToken(t.Context(), testVisitorIssuer, auth.Subject, shared, now); err != nil {
			t.Fatal("redeemed allocation share did not authorize HTTP", err)
		}
	})
	t.Run("anonymous-does-not-grant-connector", func(t *testing.T) {
		anonymous, err := d.AllocatePublisherService(t.Context(), publisher, AllocateServiceRequest{Invocation: mustOpaqueID(t, opaqueid.InvocationPrefix), Configuration: ProjectServiceConfiguration{Target: "localhost:3000", HTTP: &config.HTTPService{Access: &config.Access{Mode: "anonymous"}}}}, now)
		if err != nil {
			t.Fatal(err)
		}
		ctx := WithControlPrincipal(t.Context(), ControlPrincipal{IdentityID: unrelated.Identity.Identity.ID, SessionID: unrelated.SessionID})
		scope := visitorscope.Scope{Kind: visitorscope.Service, ID: anonymous.ID}
		policy, err := visitorlease.New(scope, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer policy.Close()
		update, err := visitorlease.Decode(policyObservation(t, d, scope, 0))
		if err != nil {
			t.Fatal(err)
		}
		if err := policy.Apply(policy.Begin(), update); err != nil {
			t.Fatal(err)
		}
		guard, err := policy.BindAnonymous(netip.MustParseAddr("192.0.2.10"), func() {})
		if err != nil {
			t.Fatal("anonymous allocation HTTP policy was not effective", err)
		}
		defer guard.Close()
		if _, err := d.IssueVisitorToken(ctx, testVisitorIssuer, scope, BrowserTokenSource{}, now); err == nil {
			t.Fatal("anonymous HTTP created an unrelated member's explicit visitor token")
		}
		tx, err := d.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer rollbackTestTransaction(t, tx)
		if _, _, err := privateVisitorAccess(ctx, tx, anonymous.ID, unrelated.Identity.Identity.ID, now); err == nil {
			t.Fatal("anonymous HTTP granted an unrelated member connector permission")
		}
	})
	if err := d.RemoveMembership(t.Context(), owner, team.ID, membership.ID, now); err != nil {
		t.Fatal(err)
	}
	t.Run("removed-owner", func(t *testing.T) { assertAllocationHumanVisitor(t, d, service.ID, member, now, false) })
	if _, err := d.IssueVisitorToken(t.Context(), testVisitorIssuer, visitorscope.Scope{Kind: visitorscope.Service, ID: service.ID}, shared, now); err == nil {
		t.Fatal("allocation share survived losing its issuer's management permission")
	}
}

func TestIntegrationDeploymentAllocationVisitorOwnership(t *testing.T) {
	d, now, owner, team := newAuthorityTeam(t)
	ownerSession := newOIDCSession(t, d, now)
	admin, adminMembership := allocationVisitorMember(t, d, team.ID, owner, "allocation-admin", "admin", now)
	member, memberMembership := allocationVisitorMember(t, d, team.ID, owner, "allocation-member", "member", now)
	if err := d.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, now); err != nil {
		t.Fatal(err)
	}
	r := selectedProjectRequest(ApplyProjectConfigurationRequest{TeamID: team.ID, ActorID: owner, ProjectKey: "allocation-visitors", SourceFingerprint: strings.Repeat("a", 64), Configuration: ProjectConfiguration{Settings: &DeploymentSettings{}, Services: map[string]ProjectServiceConfiguration{"web": {Target: "app", Public: new(true)}}}, Now: now}, "production")
	if _, err := d.ApplyProjectConfiguration(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	production, err := d.GetDeployment(t.Context(), DeploymentScope{TeamID: team.ID, ProjectKey: r.ProjectKey, ActorID: owner}, "production")
	if err != nil {
		t.Fatal(err)
	}
	f := deploymentPublicationFixture{d: d, now: now, project: r, production: production}
	_, _, publisher, _ := f.approve(t, nil, "restricted")
	service, err := d.AllocateDeploymentPublication(t.Context(), f.allocation(t, publisher))
	if err != nil {
		t.Fatal(err)
	}
	t.Run("owner", func(t *testing.T) { assertAllocationHumanVisitor(t, d, service.ID, ownerSession, now, true) })
	t.Run("admin", func(t *testing.T) { assertAllocationHumanVisitor(t, d, service.ID, admin, now, true) })
	t.Run("ordinary-member", func(t *testing.T) { assertAllocationHumanVisitor(t, d, service.ID, member, now, false) })
	t.Run("publication-is-not-visitor-approval", func(t *testing.T) {
		if _, err := d.IssueVisitorToken(t.Context(), testVisitorIssuer, visitorscope.Scope{Kind: visitorscope.Service, ID: service.ID}, RegisteredKeyTokenSource{Credential: publisher.Token}, now); err == nil {
			t.Fatal("temporary publication credential granted visitor access")
		}
	})
	if _, err := d.SetMembershipRole(t.Context(), owner, team.ID, adminMembership.ID, "member", now); err != nil {
		t.Fatal(err)
	}
	t.Run("former-admin", func(t *testing.T) { assertAllocationHumanVisitor(t, d, service.ID, admin, now, false) })
	if _, err := d.SetMembershipRole(t.Context(), owner, team.ID, memberMembership.ID, "admin", now); err != nil {
		t.Fatal(err)
	}
	t.Run("current-admin", func(t *testing.T) { assertAllocationHumanVisitor(t, d, service.ID, member, now, true) })
}
